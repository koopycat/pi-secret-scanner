/**
 * Secret Scanner Extension
 *
 * Scans outgoing LLM requests (and file-read results) for secrets before
 * they leave the machine. Supports three modes:
 *
 *   warn    – let the data through unchanged
 *   redact  – replace secrets with [REDACTED:TYPE] placeholders (default)
 *   confirm – ask the user before each redaction (interactive only)
 *   off     – fully disabled, no scanning at all
 *
 * Commands:
 *   /secret-scanner            – show current mode and stats
 *   /secret-scanner off        – disable completely
 *   /secret-scanner warn       – switch to warn-only mode
 *   /secret-scanner redact     – switch to redact mode
 *   /secret-scanner confirm    – switch to confirm mode
 *   /secret-scanner entropy on|off  – toggle entropy-based detection
 *   /secret-scanner debug on|off    – log exact replaced values (unsafe)
 *   /secret-scanner reset      – reset stats
 *   /secret-scanner reload     – hot-reload whitelist config
 *
 * Whitelist config (priority order): .gitleaks.toml, .secret-scanner.json
 *
 *   .gitleaks.toml   – native gitleaks format, supports [allowlist] and [[allowlists]]
 *   .secret-scanner.json  – { "whitelist": { "values": [...], "value_regexes": [...], "paths": [...], "disable_rules": [...] } }
 *
 * Detection strategy:
 *   1. Named regex patterns for known secret formats (AWS, GitHub, Stripe...)
 *   2. Shannon entropy analysis for unknown high-entropy values
 *
 * Hooks:
 *   before_provider_request  – scans / redacts the full payload just before
 *                              it's sent to the LLM provider
 *   tool_result (read, bash) – scans file read contents and bash output before
 *                              they enter the message history
 *
 * Note: in confirm mode without an interactive UI (e.g. RPC/print mode)
 *   the extension falls back to redact automatically.
 */

import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { parse as parseToml } from "smol-toml";

import { SECRET_PATTERNS } from "./patterns.ts";
import { countByType, formatFindings, scanObject, scanText } from "./scanner.ts";

import type { ScanCacheEntry, ScanOptions } from "./scanner.ts";
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";

// ── State ─────────────────────────────────────────────────────────────────────

type Mode = "off" | "warn" | "redact" | "confirm";

interface Stats {
	scans: number;
	findingsTotal: number;
	redactions: number;
	byType: Record<string, number>;
}

interface WhitelistConfig {
	values?: string[];
	value_regexes?: string[];
	paths?: string[];
	disable_rules?: string[];
}

interface ResolvedWhitelist {
	values: Set<string>;
	valueRegexes: RegExp[];
	pathRegexes: RegExp[];
	disabledRules: Set<string>;
}

interface GitleaksAllowlist {
	paths?: string[];
	regexes?: string[];
	stopwords?: string[];
}

let mode: Mode = "redact";
let useEntropy = true;
let debug = false;
let stats: Stats = { scans: 0, findingsTotal: 0, redactions: 0, byType: {} };
let redactionFlash: { count: number; location: string } | null = null;
let redactionFlashTimer: ReturnType<typeof setTimeout> | undefined;

const REDACTION_FLASH_MS = 5_000;
let whitelist: ResolvedWhitelist | null = null;

// This cache is process-local only. Hashing avoids retaining original
// transcript text as Map keys, and bounded eviction prevents unbounded growth.
const TEXT_CACHE_LIMIT = 4096;
const textCache = new Map<string, ScanCacheEntry>();

function clearScanCaches() {
	textCache.clear();
}

function cacheKey(value: string): string {
	return createHash("sha256").update(value).digest("hex");
}

function resetStats() {
	stats = { scans: 0, findingsTotal: 0, redactions: 0, byType: {} };
}

function mergeTypeCounts(into: Record<string, number>, from: Record<string, number>) {
	for (const [type, count] of Object.entries(from)) {
		into[type] = (into[type] ?? 0) + count;
	}
}

function logRedactions(location: string, findings: ReturnType<typeof scanText>["redactions"]): void {
	if (!debug || findings.length === 0) return;
	for (const finding of findings) {
		// Debug mode is deliberately unsafe: exact secrets can persist in terminal logs.
		console.warn(
			`[secret-scanner][debug] replaced ${finding.type} (${finding.source}) in ${location}: ${JSON.stringify(finding.value)}`,
		);
	}
}

// ── Whitelist loading ─────────────────────────────────────────────────────────

/**
 * Convert a gitleaks/PCRE regex string to a JavaScript RegExp.
 * Handles inline flags like (?i), (?m), (?s) that JS doesn't support natively.
 */
function toJsRegex(pattern: string): RegExp {
	let flags = "";
	let cleaned = pattern;

	// Match leading (?flags) groups -- gitleaks commonly uses (?i) at the start.
	const inlineFlagRe = /^\(\?([imsUux]+)\)/;
	let match: RegExpExecArray | null;
	while ((match = inlineFlagRe.exec(cleaned)) !== null) {
		const f = match[1] ?? "";
		if (f.includes("i")) flags += "i";
		if (f.includes("m")) flags += "m";
		if (f.includes("s")) flags += "s";
		cleaned = cleaned.slice(match[0].length);
	}

	flags = [...new Set(flags)].join("");
	return new RegExp(cleaned, flags);
}

function loadGitleaksToml(cwd: string): ResolvedWhitelist | null {
	const configPath = join(cwd, ".gitleaks.toml");
	if (!existsSync(configPath)) return null;

	try {
		const raw = readFileSync(configPath, "utf-8");
		const parsed = parseToml(raw) as Record<string, unknown>;

		// Support both [allowlist] (singular) and [[allowlists]] (plural array).
		const allowlist = parsed.allowlist as GitleaksAllowlist | undefined;
		const allowlists = parsed.allowlists as GitleaksAllowlist[] | undefined;

		const all: GitleaksAllowlist[] = [];
		if (allowlist) all.push(allowlist);
		if (allowlists) all.push(...allowlists);
		if (all.length === 0) return null;

		const values = new Set<string>();
		const valueRegexes: RegExp[] = [];
		const pathRegexes: RegExp[] = [];

		for (const al of all) {
			for (const w of al.stopwords ?? []) values.add(w);
			for (const r of al.regexes ?? []) valueRegexes.push(toJsRegex(r));
			for (const p of al.paths ?? []) pathRegexes.push(toJsRegex(p));
		}

		const resolved: ResolvedWhitelist = {
			values,
			valueRegexes,
			pathRegexes,
			disabledRules: new Set(),
		};

		const count = values.size + valueRegexes.length + pathRegexes.length;
		return count > 0 ? resolved : null;
	} catch (err) {
		console.error(`[secret-scanner] failed to parse ${configPath}:`, err);
		return null;
	}
}

function loadSecretScannerJson(cwd: string): ResolvedWhitelist | null {
	const configPath = join(cwd, ".secret-scanner.json");
	if (!existsSync(configPath)) return null;

	try {
		const raw = readFileSync(configPath, "utf-8");
		const parsed = JSON.parse(raw) as { whitelist?: WhitelistConfig };
		const wl = parsed.whitelist;
		if (!wl) return null;

		const resolved: ResolvedWhitelist = {
			values: new Set(wl.values ?? []),
			valueRegexes: (wl.value_regexes ?? []).map((s) => new RegExp(s)),
			pathRegexes: (wl.paths ?? []).map((s) => new RegExp(s)),
			disabledRules: new Set(wl.disable_rules ?? []),
		};

		const count =
			resolved.values.size +
			resolved.valueRegexes.length +
			resolved.pathRegexes.length +
			resolved.disabledRules.size;

		return count > 0 ? resolved : null;
	} catch (err) {
		console.error(`[secret-scanner] failed to parse ${configPath}:`, err);
		return null;
	}
}

function loadWhitelist(cwd: string): ResolvedWhitelist | null {
	return loadGitleaksToml(cwd) ?? loadSecretScannerJson(cwd);
}

function isPathWhitelisted(filePath: string): boolean {
	if (!whitelist?.pathRegexes.length) return false;
	for (const re of whitelist.pathRegexes) {
		re.lastIndex = 0;
		if (re.test(filePath)) return true;
	}
	return false;
}

function buildScanOptions(): ScanOptions {
	return {
		useEntropy,
		patterns: SECRET_PATTERNS,
		whitelist: whitelist?.values,
		whitelistRegexes: whitelist?.valueRegexes,
		disabledRules: whitelist?.disabledRules,
		textCache,
		textCacheKey: (text) => cacheKey(text),
		textCacheMaxEntries: TEXT_CACHE_LIMIT,
		cacheRead: mode !== "confirm",
		cacheWrite: mode !== "confirm",
	};
}

// ── Extension ─────────────────────────────────────────────────────────────────

export default function (pi: ExtensionAPI) {
	// Only the UI surface the helpers need; every pi context is structurally compatible.
	type StatusContext = Pick<ExtensionContext, "ui" | "hasUI">;

	function accountFindings(findings: ReturnType<typeof scanText>["findings"]): void {
		if (findings.length === 0) return;
		stats.findingsTotal += findings.length;
		mergeTypeCounts(stats.byType, countByType(findings));
	}

	function accountRedactions(
		ctx: StatusContext,
		findings: ReturnType<typeof scanText>["redactions"],
		location: string,
	): void {
		if (findings.length === 0) return;
		stats.redactions += findings.length;
		logRedactions(location, findings);
		flashRedaction(ctx, findings.length, location);
	}

	function updateStatus(ctx: StatusContext) {
		if (!ctx.hasUI) return;
		if (mode === "off") {
			ctx.ui.setStatus("secret-scanner", undefined);
			return;
		}
		if (redactionFlash) {
			const noun = redactionFlash.count === 1 ? "secret" : "secrets";
			ctx.ui.setStatus(
				"secret-scanner",
				ctx.ui.theme.fg(
					"warning",
					`🔐 REDACTED ${redactionFlash.count} ${noun} • ${redactionFlash.location} • total:${stats.redactions}`,
				),
			);
			return;
		}

		const color = debug ? "warning" : "dim";
		const redactedInfo = stats.redactions > 0 ? ` • ${stats.redactions} redacted` : "";
		const wlInfo = whitelist
			? ` wl:${whitelist.values.size + whitelist.valueRegexes.length + whitelist.disabledRules.size}`
			: "";
		ctx.ui.setStatus(
			"secret-scanner",
			ctx.ui.theme.fg(
				color,
				`🔍 secret-scanner: ${mode}${useEntropy ? "+entropy" : ""}${debug ? "+DEBUG" : ""}${wlInfo}${redactedInfo}`,
			),
		);
	}

	function flashRedaction(ctx: StatusContext, count: number, location: string): void {
		if (!ctx.hasUI || count === 0) return;
		if (redactionFlashTimer) clearTimeout(redactionFlashTimer);
		redactionFlash = { count, location };
		updateStatus(ctx);
		redactionFlashTimer = setTimeout(() => {
			redactionFlash = null;
			redactionFlashTimer = undefined;
			updateStatus(ctx);
		}, REDACTION_FLASH_MS);
		redactionFlashTimer.unref();
	}

	pi.on("session_start", (_event, ctx) => {
		clearScanCaches();
		whitelist = loadWhitelist(ctx.cwd);
		redactionFlash = null;
		if (redactionFlashTimer) clearTimeout(redactionFlashTimer);
		redactionFlashTimer = undefined;
		updateStatus(ctx);
	});

	pi.on("session_shutdown", (_event, ctx) => {
		clearScanCaches();
		if (redactionFlashTimer) clearTimeout(redactionFlashTimer);
		redactionFlashTimer = undefined;
		redactionFlash = null;
		if (ctx.hasUI) ctx.ui.setStatus("secret-scanner", undefined);
	});

	// ── Hook: context ────────────────────────────────────────────────────────

	pi.on("context", (event, ctx) => {
		if (mode === "off" || mode === "confirm") return;

		stats.scans++;
		const result = scanObject(event.messages, buildScanOptions());
		if (result.freshFindings.length > 0) {
			accountFindings(result.freshFindings);
			updateStatus(ctx);
		}
		if (mode === "redact") {
			accountRedactions(ctx, result.freshRedactions, "context");
			if (result.hasFindings) return { messages: result.redactedObject as typeof event.messages };
		} else if (result.hasFindings) {
			// Warn mode observes the full context but leaves it untouched.
			return;
		}
	});

	// ── Hook: before_provider_request ───────────────────────────────────────

	pi.on("before_provider_request", async (event, ctx) => {
		if (mode === "off") return;
		stats.scans++;

		const result = scanObject(event.payload, buildScanOptions());

		if (!result.hasFindings) return;

		accountFindings(result.freshFindings);

		updateStatus(ctx);

		if (mode === "warn" || result.redactions.length === 0) {
			return;
		}

		if (mode === "redact" && result.freshRedactions.length === 0) {
			return result.redactedObject;
		}

		if (mode === "confirm" && ctx.hasUI && result.freshRedactions.length === 0) {
			// Cached findings are already accounted for and should not repeatedly
			// prompt the user. The sanitized payload can still be returned below.
			return result.redactedObject;
		}

		if (mode === "confirm" && ctx.hasUI) {
			const redactionSummary = formatFindings(result.freshRedactions);
			const redactionCount = result.freshRedactions.length;
			const redactionLabel = redactionCount === 1 ? "secret" : "secrets";
			const ok = await ctx.ui.confirm(
				`🔐 Secret Scanner: ${redactionCount} potential ${redactionLabel} detected`,
				`Redact before sending to LLM?\n\n${redactionSummary}\n\nChoose "Yes" to redact, "No" to send as-is.`,
			);
			if (!ok) {
				return;
			}
		}

		accountRedactions(ctx, result.freshRedactions, "provider request");
		return result.redactedObject;
	});

	// ── Hook: tool_result (read + bash tools) ───────────────────────────────

	pi.on("tool_result", async (event, ctx) => {
		if (mode === "off") return;
		if (event.toolName !== "read" && event.toolName !== "bash") return;

		// Path-based whitelist: skip scanning results from whitelisted files.
		if (event.toolName === "read" && typeof event.input.path === "string") {
			if (isPathWhitelisted(event.input.path)) return;
		}

		const contentItems = event.content;
		if (!Array.isArray(contentItems)) return;

		stats.scans++;

		const scanOptions = buildScanOptions();
		let hasFindings = false;
		let redactionCount = 0;
		const allFindings: ReturnType<typeof scanText>["findings"] = [];
		const newContent: typeof contentItems = [];

		for (const item of contentItems) {
			if (item.type !== "text" || typeof item.text !== "string") {
				newContent.push(item);
				continue;
			}

			const result = scanText(item.text, scanOptions);

			if (result.findings.length > 0) {
				hasFindings = true;
				if (!result.fromCache) allFindings.push(...result.findings);

				if (mode === "warn") {
					newContent.push(item);
				} else if (mode === "confirm" && ctx.hasUI && !result.fromCache && result.redactions.length > 0) {
					const summary = formatFindings(result.redactions);
					const count = result.redactions.length;
					const label = count === 1 ? "secret" : "secrets";
					const ok = await ctx.ui.confirm(
						`🔐 Secret Scanner: ${count} potential ${label} in file`,
						`Redact from file contents before adding to context?\n\n${summary}`,
					);
					if (ok) {
						redactionCount = redactionCount + result.redactions.length;
						logRedactions(`${event.toolName} tool result`, result.redactions);
						newContent.push({ ...item, text: result.redacted });
					} else {
						newContent.push(item);
					}
				} else {
					const freshRedactions = result.fromCache ? [] : result.redactions;
					redactionCount = redactionCount + freshRedactions.length;
					logRedactions(`${event.toolName} tool result`, freshRedactions);
					newContent.push({ ...item, text: result.redacted });
				}
			} else {
				newContent.push(item);
			}
		}

		if (!hasFindings) return;

		accountFindings(allFindings);

		updateStatus(ctx);

		if (mode === "warn") {
			return;
		}

		stats.redactions += redactionCount;
		flashRedaction(ctx, redactionCount, `${event.toolName} result`);
		return { content: newContent };
	});

	// ── Command: /secret-scanner ─────────────────────────────────────────────

	pi.registerCommand("secret-scanner", {
		description:
			"Show secret scanner status or set mode: warn | redact | confirm | entropy on/off | debug on/off | reset | reload",
		handler: async (args, ctx) => {
			const arg = args.trim().toLowerCase();

			if (arg === "off" || arg === "warn" || arg === "redact" || arg === "confirm") {
				clearScanCaches();
				mode = arg;
				updateStatus(ctx);
				ctx.ui.notify(`Secret scanner mode set to: ${mode}`, mode === "off" ? "warning" : "info");
				return;
			}

			if (arg === "entropy on") {
				clearScanCaches();
				useEntropy = true;
				updateStatus(ctx);
				ctx.ui.notify("Entropy-based detection: ON", "info");
				return;
			}

			if (arg === "entropy off") {
				clearScanCaches();
				useEntropy = false;
				updateStatus(ctx);
				ctx.ui.notify("Entropy-based detection: OFF", "info");
				return;
			}

			if (arg === "debug on") {
				debug = true;
				updateStatus(ctx);
				ctx.ui.notify(
					"Secret scanner debug enabled: exact secret values will be written to terminal logs",
					"warning",
				);
				return;
			}

			if (arg === "debug off") {
				debug = false;
				updateStatus(ctx);
				ctx.ui.notify("Secret scanner debug disabled", "info");
				return;
			}

			if (arg === "debug") {
				ctx.ui.notify(`Secret scanner debug is ${debug ? "on (unsafe)" : "off"}`, debug ? "warning" : "info");
				return;
			}

			if (arg === "reset") {
				resetStats();
				updateStatus(ctx);
				ctx.ui.notify("Secret scanner stats reset.", "info");
				return;
			}

			if (arg === "reload") {
				clearScanCaches();
				whitelist = loadWhitelist(ctx.cwd);
				updateStatus(ctx);
				const wlMsg = whitelist
					? `loaded ${whitelist.values.size + whitelist.valueRegexes.length + whitelist.disabledRules.size} entries`
					: "no whitelist found";
				ctx.ui.notify(`Secret scanner whitelist reloaded: ${wlMsg}`, "info");
				return;
			}

			// Default: show status
			const typeBreakdown =
				Object.keys(stats.byType).length > 0
					? `\n\nTypes found:\n${Object.entries(stats.byType)
							.sort(([, a], [, b]) => b - a)
							.map(([t, n]) => `  ${t}: ${n}`)
							.join("\n")}`
					: "";

			const wlInfo = whitelist
				? `\n  Values wl:   ${whitelist.values.size}\n` +
					`  Regex wl:    ${whitelist.valueRegexes.length}\n` +
					`  Paths wl:    ${whitelist.pathRegexes.length}\n` +
					`  Rules off:   ${whitelist.disabledRules.size}`
				: "\n  Whitelist:   none";

			ctx.ui.notify(
				`🔐 Secret Scanner Status\n` +
					`  Mode:        ${mode}${mode === "off" ? "  ⏸️  (disabled)" : ""}\n` +
					`  Entropy:     ${useEntropy ? "on" : "off"}\n` +
					`  Debug:       ${debug ? "on (logs exact secrets!)" : "off"}\n` +
					`  Patterns:    ${SECRET_PATTERNS.length} regex rules\n` +
					`  Scans:       ${stats.scans}\n` +
					`  Findings:    ${stats.findingsTotal}\n` +
					`  Redactions:  ${stats.redactions}${wlInfo}${typeBreakdown}`,
				"info",
			);
		},
	});
}
