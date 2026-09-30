/**
 * User-facing feedback: footer status, redaction flash, counters, debug
 * logging, and configuration problems. Never shows secret values except in
 * the explicit, opt-in debug log.
 */

import { whitelistSize } from "./config.ts";
import { countByType, placeholderFor } from "./scanner.ts";
import { clearRedactionFlash, reloadWhitelist } from "./state.ts";

import type { Finding } from "./scanner.ts";
import type { ScannerState } from "./state.ts";
import type { ExtensionContext } from "@earendil-works/pi-coding-agent";

/** Only the UI surface the helpers need; every pi context is structurally compatible. */
export type StatusContext = Pick<ExtensionContext, "ui" | "hasUI">;
export type ProjectContext = StatusContext & { cwd: string };

export const REDACTION_FLASH_MS = 5_000;
export const STATUS_KEY = "secret-scanner";

export function updateStatus(state: ScannerState, ctx: StatusContext): void {
	if (!ctx.hasUI) return;
	if (state.mode === "off") {
		ctx.ui.setStatus(STATUS_KEY, undefined);
		return;
	}
	const { stats } = state;
	if (state.redactionFlash) {
		const { count, location } = state.redactionFlash;
		const noun = count === 1 ? "secret" : "secrets";
		ctx.ui.setStatus(
			STATUS_KEY,
			ctx.ui.theme.fg("warning", `🔐 REDACTED ${count} ${noun} • ${location} • total:${stats.redactions}`),
		);
		return;
	}

	const color = state.debug ? "warning" : "dim";
	const redactedInfo = stats.redactions > 0 ? ` • ${stats.redactions} redacted` : "";
	const wlInfo = state.whitelist ? ` wl:${whitelistSize(state.whitelist) - state.whitelist.pathRegexes.length}` : "";
	const flags = `${state.useEntropy ? "+entropy" : ""}${state.debug ? "+DEBUG" : ""}`;
	ctx.ui.setStatus(
		STATUS_KEY,
		ctx.ui.theme.fg(color, `🔍 secret-scanner: ${state.mode}${flags}${wlInfo}${redactedInfo}`),
	);
}

export function flashRedaction(state: ScannerState, ctx: StatusContext, count: number, location: string): void {
	if (!ctx.hasUI || count === 0) return;
	clearRedactionFlash(state);
	state.redactionFlash = { count, location };
	updateStatus(state, ctx);
	state.redactionFlashTimer = setTimeout(() => {
		state.redactionFlash = null;
		state.redactionFlashTimer = undefined;
		updateStatus(state, ctx);
	}, REDACTION_FLASH_MS);
	state.redactionFlashTimer.unref();
}

export function logRedactions(state: ScannerState, location: string, findings: Finding[]): void {
	if (!state.debug || findings.length === 0) return;
	for (const finding of findings) {
		// Debug mode is deliberately unsafe: exact secrets can persist in terminal logs.
		console.warn(
			`[secret-scanner][debug] replaced ${finding.type} (${finding.source}) in ${location}: ${JSON.stringify(finding.value)}`,
		);
	}
}

export function accountFindings(state: ScannerState, findings: Finding[]): void {
	if (findings.length === 0) return;
	const actionable = findings.filter((finding) => finding.action !== "report");
	state.stats.findingsTotal += actionable.length;
	state.stats.reported += findings.length - actionable.length;
	for (const [type, count] of Object.entries(countByType(actionable))) {
		state.stats.byType[type] = (state.stats.byType[type] ?? 0) + count;
	}
}

/** Count, log, and flash redactions that are new (not served from the cache). */
export function accountRedactions(
	state: ScannerState,
	ctx: StatusContext,
	findings: Finding[],
	location: string,
): void {
	if (findings.length === 0) return;
	state.stats.redactions += findings.length;
	logRedactions(state, location, findings);
	flashRedaction(state, ctx, findings.length, location);
}

/** Record placeholders now visible to the model, for the edit/write guard. */
export function rememberPlaceholders(state: ScannerState, findings: Finding[]): void {
	for (const finding of findings) state.emittedPlaceholders.add(placeholderFor(finding.type));
}

/** Reload the allowlist and show configuration problems without failing. */
export function applyConfig(state: ScannerState, ctx: ProjectContext): void {
	const errors = reloadWhitelist(state, ctx.cwd);
	if (errors.length === 0) return;
	const message = `Secret scanner configuration problems (other entries still apply):\n  ${errors.join("\n  ")}`;
	if (ctx.hasUI) ctx.ui.notify(message, "error");
	else console.error(`[secret-scanner] ${message}`);
}
