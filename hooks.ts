/**
 * Pi event hooks: where content is scanned, redacted, and guarded.
 *
 *   session_start / shutdown – load config, reset session-scoped state
 *   before_agent_start       – tell the model what placeholders mean
 *   context                  – sanitize history before payload assembly (redact/warn)
 *   before_provider_request  – scan the final payload before it leaves the machine
 *   tool_result              – scan every tool's text output before it enters history
 *   tool_call (edit, write)  – block writes that would copy placeholders over real values
 */

import { isPathWhitelisted } from "./config.ts";
import { chooseConfirmActions } from "./confirm.ts";
import {
	STATUS_KEY,
	accountFindings,
	accountRedactions,
	applyConfig,
	flashRedaction,
	logRedactions,
	rememberPlaceholders,
	updateStatus,
} from "./feedback.ts";
import { isLockfile } from "./lockfiles.ts";
import { blockReason, foreignPlaceholders } from "./placeholder-guard.ts";
import { scanObject, scanText } from "./scanner.ts";
import { buildScanOptions, clearRedactionFlash } from "./state.ts";

import type { Finding } from "./scanner.ts";
import type { ScanRequest, ScannerState } from "./state.ts";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

// Appended to the system prompt while redaction is active, so the model
// treats placeholders as opaque instead of guessing or writing them back.
export const REDACTION_NOTE =
	"Secret scanner: values shown as [REDACTED:TYPE] were replaced locally before reaching you; " +
	"the real values still exist in files and command output. Treat placeholders as opaque. " +
	"Do not try to recover or guess them, and never write a placeholder into a file: " +
	"choose edit oldText that excludes redacted lines, and ask the user when a secret itself must change.";

export function registerHooks(pi: ExtensionAPI, state: ScannerState): void {
	pi.on("session_start", (event, ctx) => {
		state.textCache.clear();
		if (event.reason !== "reload") {
			state.sessionWhitelistHashes.clear();
			state.emittedPlaceholders.clear();
		}
		applyConfig(state, ctx);
		clearRedactionFlash(state);
		updateStatus(state, ctx);
	});

	pi.on("session_shutdown", (_event, ctx) => {
		state.textCache.clear();
		state.sessionWhitelistHashes.clear();
		state.emittedPlaceholders.clear();
		clearRedactionFlash(state);
		if (ctx.hasUI) ctx.ui.setStatus(STATUS_KEY, undefined);
	});

	pi.on("before_agent_start", (event) => {
		if (state.mode !== "redact" && state.mode !== "confirm") return;
		return { systemPrompt: `${event.systemPrompt}\n\n${REDACTION_NOTE}` };
	});

	pi.on("context", (event, ctx) => {
		// Confirm mode must not redact without asking; the provider hook asks.
		if (state.mode === "off" || state.mode === "confirm") return;

		state.stats.scans++;
		const result = scanObject(event.messages, buildScanOptions(state));
		if (result.freshFindings.length > 0) {
			accountFindings(state, result.freshFindings);
			updateStatus(state, ctx);
		}
		// Warn mode observes the full context but leaves it untouched.
		if (state.mode !== "redact" || !result.hasFindings) return;
		accountRedactions(state, ctx, result.freshRedactions, "context");
		rememberPlaceholders(state, result.redactions);
		return { messages: result.redactedObject as typeof event.messages };
	});

	pi.on("before_provider_request", async (event, ctx) => {
		if (state.mode === "off") return;
		state.stats.scans++;

		const result = scanObject(event.payload, buildScanOptions(state));
		if (!result.hasFindings) return;

		accountFindings(state, result.freshFindings);
		updateStatus(state, ctx);

		if (state.mode === "warn" || result.redactions.length === 0) return;

		if (state.mode === "confirm" && ctx.hasUI && result.freshRedactions.length > 0) {
			// Cached chunks already carry earlier decisions and never prompt again.
			const allowOnce = await chooseConfirmActions(state, ctx, result.freshRedactions, "provider request");
			const decided = scanObject(event.payload, buildScanOptions(state, { allowOnce, decided: true }));
			accountRedactions(state, ctx, decided.freshRedactions, "provider request");
			rememberPlaceholders(state, decided.redactions);
			return decided.redactions.length > 0 ? decided.redactedObject : undefined;
		}

		// Redact mode, and confirm mode without a UI (fails safe to redaction).
		accountRedactions(state, ctx, result.freshRedactions, "provider request");
		rememberPlaceholders(state, result.redactions);
		return result.redactedObject;
	});

	pi.on("tool_result", async (event, ctx) => {
		if (state.mode === "off") return;

		const readPath = event.toolName === "read" && typeof event.input.path === "string" ? event.input.path : null;
		// Path-based whitelist: skip scanning results from whitelisted files.
		if (readPath !== null && isPathWhitelisted(state.whitelist, readPath)) return;

		const contentItems = event.content;
		if (!Array.isArray(contentItems)) return;

		state.stats.scans++;

		const request: ScanRequest = { entropy: readPath === null || !isLockfile(readPath), fresh: true };
		const initialResults = contentItems.map((item) =>
			item.type === "text" && typeof item.text === "string"
				? scanText(item.text, buildScanOptions(state, request))
				: null,
		);
		if (!initialResults.some((result) => result && result.findings.length > 0)) return;

		const confirming = state.mode === "confirm" && ctx.hasUI;
		const allowOnce = new Set<string>();
		if (confirming) {
			// Cached results already carry earlier decisions (and blank values).
			const undecided = initialResults.flatMap((result) =>
				result && !result.fromCache ? result.redactions : [],
			);
			for (const hash of await chooseConfirmActions(state, ctx, undecided, `${event.toolName} output`)) {
				allowOnce.add(hash);
			}
		}

		let redactionCount = 0;
		const allFindings: Finding[] = [];
		const newContent = contentItems.map((item, index) => {
			const initialResult = initialResults[index];
			if (!initialResult || initialResult.findings.length === 0 || item.type !== "text") return item;

			if (!initialResult.fromCache) allFindings.push(...initialResult.findings);
			if (state.mode === "warn") return item;

			const result = confirming
				? scanText(item.text, buildScanOptions(state, { ...request, allowOnce, decided: true }))
				: initialResult;
			const freshRedactions = result.fromCache ? [] : result.redactions;
			redactionCount += freshRedactions.length;
			logRedactions(state, `${event.toolName} tool result`, freshRedactions);
			rememberPlaceholders(state, result.redactions);
			return { ...item, text: result.redacted };
		});

		accountFindings(state, allFindings);
		updateStatus(state, ctx);
		if (state.mode === "warn") return;

		state.stats.redactions += redactionCount;
		flashRedaction(state, ctx, redactionCount, `${event.toolName} result`);
		return { content: newContent };
	});

	pi.on("tool_call", (event, ctx) => {
		if (state.mode === "off") return;
		const input = event.input as Record<string, unknown>;
		const placeholders = foreignPlaceholders(
			{ toolName: event.toolName, input },
			state.emittedPlaceholders,
			ctx.cwd,
		);
		if (placeholders.length === 0) return;
		return { block: true, reason: blockReason(event.toolName, String(input.path), placeholders) };
	});
}
