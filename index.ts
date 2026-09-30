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

import { execFileSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
	appendFileSync,
	chmodSync,
	closeSync,
	existsSync,
	openSync,
	readFileSync,
	renameSync,
	unlinkSync,
	writeFileSync,
} from "node:fs";
import { join, relative } from "node:path";

import { parse as parseToml } from "smol-toml";

import { SECRET_PATTERNS } from "./patterns.ts";
import { countByType, formatConfirmFindings, scanObject, scanText } from "./scanner.ts";

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
	value_hashes?: string[];
	value_regexes?: string[];
	paths?: string[];
	disable_rules?: string[];
}

interface ResolvedWhitelist {
	values: Set<string>;
	valueHashes: Set<string>;
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
let sessionWhitelistHashes = new Set<string>();

const LOCAL_CONFIG_NAME = ".secret-scanner.local.json";
const CONFIRM_REDACT = "Redact";
const CONFIRM_ALLOW_ONCE = "Allow once";
const CONFIRM_ALLOW_SESSION = "Allow for this session";
const CONFIRM_ALLOW_PROJECT = "Always allow in this project";

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

function secretFingerprint(value: string): string {
	return `sha256:${cacheKey(value)}`;
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
			valueHashes: new Set(),
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

function loadSecretScannerJson(cwd: string, fileName = ".secret-scanner.json"): ResolvedWhitelist | null {
	const configPath = join(cwd, fileName);
	if (!existsSync(configPath)) return null;

	try {
		const raw = readFileSync(configPath, "utf-8");
		const parsed = JSON.parse(raw) as { whitelist?: WhitelistConfig };
		const wl = parsed.whitelist;
		if (!wl) return null;

		const resolved: ResolvedWhitelist = {
			values: new Set(wl.values ?? []),
			valueHashes: new Set(wl.value_hashes ?? []),
			valueRegexes: (wl.value_regexes ?? []).map((s) => new RegExp(s)),
			pathRegexes: (wl.paths ?? []).map((s) => new RegExp(s)),
			disabledRules: new Set(wl.disable_rules ?? []),
		};

		const count =
			resolved.values.size +
			resolved.valueHashes.size +
			resolved.valueRegexes.length +
			resolved.pathRegexes.length +
			resolved.disabledRules.size;

		return count > 0 ? resolved : null;
	} catch (err) {
		console.error(`[secret-scanner] failed to parse ${configPath}:`, err);
		return null;
	}
}

function mergeWhitelists(primary: ResolvedWhitelist | null, local: ResolvedWhitelist | null): ResolvedWhitelist | null {
	if (!primary) return local;
	if (!local) return primary;
	return {
		values: new Set([...primary.values, ...local.values]),
		valueHashes: new Set([...primary.valueHashes, ...local.valueHashes]),
		valueRegexes: [...primary.valueRegexes, ...local.valueRegexes],
		pathRegexes: [...primary.pathRegexes, ...local.pathRegexes],
		disabledRules: new Set([...primary.disabledRules, ...local.disabledRules]),
	};
}

function loadWhitelist(cwd: string): ResolvedWhitelist | null {
	const primary = loadGitleaksToml(cwd) ?? loadSecretScannerJson(cwd);
	return mergeWhitelists(primary, loadSecretScannerJson(cwd, LOCAL_CONFIG_NAME));
}

function prepareLocalConfigGitExclusion(cwd: string): void {
	let root: string;
	try {
		root = execFileSync("git", ["rev-parse", "--show-toplevel"], {
			cwd,
			encoding: "utf-8",
			stdio: ["ignore", "pipe", "ignore"],
		}).trim();
	} catch {
		return; // Non-Git project.
	}

	const relativeConfigPath = relative(root, join(cwd, LOCAL_CONFIG_NAME)).replaceAll("\\", "/");
	try {
		execFileSync("git", ["ls-files", "--error-unmatch", "--", relativeConfigPath], {
			cwd: root,
			stdio: "ignore",
		});
		throw new Error(`${relativeConfigPath} is already tracked by Git; untrack it before saving local decisions`);
	} catch (error) {
		if (error instanceof Error && error.message.includes("is already tracked by Git")) throw error;
	}

	const excludePath = execFileSync("git", ["rev-parse", "--git-path", "info/exclude"], {
		cwd: root,
		encoding: "utf-8",
		stdio: ["ignore", "pipe", "ignore"],
	}).trim();
	if (!excludePath) throw new Error("Git did not return an info/exclude path");
	const absoluteExcludePath = join(root, excludePath);
	const pattern = `/${relativeConfigPath}`;
	const existing = existsSync(absoluteExcludePath) ? readFileSync(absoluteExcludePath, "utf-8") : "";
	if (!existing.split(/\r?\n/).includes(pattern)) {
		appendFileSync(
			absoluteExcludePath,
			`${existing.length > 0 && !existing.endsWith("\n") ? "\n" : ""}${pattern}\n`,
		);
	}
}

function persistProjectFingerprint(cwd: string, fingerprint: string): void {
	const configPath = join(cwd, LOCAL_CONFIG_NAME);
	const lockPath = `${configPath}.lock`;
	let lockFd: number | undefined;
	for (let attempt = 0; attempt < 40; attempt++) {
		try {
			lockFd = openSync(lockPath, "wx", 0o600);
			break;
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code !== "EEXIST" || attempt === 39) throw error;
			Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 25);
		}
	}
	if (lockFd === undefined) throw new Error("could not acquire local configuration lock");

	const temporaryPath = `${configPath}.tmp-${randomUUID()}`;
	try {
		prepareLocalConfigGitExclusion(cwd);
		let parsed: { whitelist?: WhitelistConfig } = {};
		if (existsSync(configPath)) {
			parsed = JSON.parse(readFileSync(configPath, "utf-8")) as { whitelist?: WhitelistConfig };
		}
		const hashes = new Set(parsed.whitelist?.value_hashes ?? []);
		hashes.add(fingerprint);
		parsed.whitelist = { ...parsed.whitelist, value_hashes: [...hashes].sort() };

		writeFileSync(temporaryPath, `${JSON.stringify(parsed, null, "\t")}\n`, { mode: 0o600, flag: "wx" });
		renameSync(temporaryPath, configPath);
		chmodSync(configPath, 0o600);
	} finally {
		try {
			unlinkSync(temporaryPath);
		} catch {
			// The temporary file may not exist or may already have been renamed.
		}
		closeSync(lockFd);
		unlinkSync(lockPath);
	}
}

function isPathWhitelisted(filePath: string): boolean {
	if (!whitelist?.pathRegexes.length) return false;
	for (const re of whitelist.pathRegexes) {
		re.lastIndex = 0;
		if (re.test(filePath)) return true;
	}
	return false;
}

function buildScanOptions(additionalHashes?: ReadonlySet<string>): ScanOptions {
	return {
		useEntropy,
		patterns: SECRET_PATTERNS,
		whitelist: whitelist?.values,
		whitelistRegexes: whitelist?.valueRegexes,
		whitelistHashes: new Set([
			...(whitelist?.valueHashes ?? []),
			...sessionWhitelistHashes,
			...(additionalHashes ?? []),
		]),
		hashWhitelistValue: secretFingerprint,
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

	async function chooseConfirmActions(
		findings: ReturnType<typeof scanText>["redactions"],
		ctx: StatusContext & { cwd: string },
		location: string,
	): Promise<Set<string>> {
		const allowOnce = new Set<string>();
		const seen = new Set<string>();
		for (const finding of findings) {
			const fingerprint = secretFingerprint(finding.value);
			if (seen.has(fingerprint)) continue;
			seen.add(fingerprint);

			const summary = formatConfirmFindings([finding]);
			const choice = await ctx.ui.select(`🔐 Potential secret in ${location}\n\n${summary}`, [
				CONFIRM_REDACT,
				CONFIRM_ALLOW_ONCE,
				CONFIRM_ALLOW_SESSION,
				CONFIRM_ALLOW_PROJECT,
			]);
			if (choice === CONFIRM_ALLOW_ONCE) {
				allowOnce.add(fingerprint);
			} else if (choice === CONFIRM_ALLOW_SESSION) {
				sessionWhitelistHashes.add(fingerprint);
			} else if (choice === CONFIRM_ALLOW_PROJECT) {
				try {
					persistProjectFingerprint(ctx.cwd, fingerprint);
					whitelist = loadWhitelist(ctx.cwd);
					ctx.ui.notify(`Saved fingerprint to ${LOCAL_CONFIG_NAME}; plaintext was not stored`, "info");
				} catch (error) {
					ctx.ui.notify(
						`Could not save ${LOCAL_CONFIG_NAME}; keeping the value redacted: ${error instanceof Error ? error.message : String(error)}`,
						"error",
					);
				}
			}
			// Escape/cancel returns undefined and therefore fails safe to redaction.
		}
		return allowOnce;
	}

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
			? ` wl:${whitelist.values.size + whitelist.valueHashes.size + whitelist.valueRegexes.length + whitelist.disabledRules.size}`
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

	pi.on("session_start", (event, ctx) => {
		clearScanCaches();
		if (event.reason !== "reload") sessionWhitelistHashes = new Set();
		whitelist = loadWhitelist(ctx.cwd);
		redactionFlash = null;
		if (redactionFlashTimer) clearTimeout(redactionFlashTimer);
		redactionFlashTimer = undefined;
		updateStatus(ctx);
	});

	pi.on("session_shutdown", (_event, ctx) => {
		clearScanCaches();
		sessionWhitelistHashes.clear();
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
			const allowOnce = await chooseConfirmActions(result.freshRedactions, ctx, "provider request");
			const decided = scanObject(event.payload, buildScanOptions(allowOnce));
			accountRedactions(ctx, decided.freshRedactions, "provider request");
			return decided.redactions.length > 0 ? decided.redactedObject : undefined;
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

		let redactionCount = 0;
		const allFindings: ReturnType<typeof scanText>["findings"] = [];
		const initialResults = contentItems.map((item) =>
			item.type === "text" && typeof item.text === "string" ? scanText(item.text, buildScanOptions()) : null,
		);
		const operationAllowOnce = new Set<string>();

		if (mode === "confirm" && ctx.hasUI) {
			const operationRedactions = initialResults.flatMap((result) => result?.redactions ?? []);
			for (const hash of await chooseConfirmActions(operationRedactions, ctx, `${event.toolName} output`)) {
				operationAllowOnce.add(hash);
			}
		}

		const newContent = contentItems.map((item, index) => {
			const initialResult = initialResults[index];
			if (!initialResult || initialResult.findings.length === 0) return item;

			if (!initialResult.fromCache) allFindings.push(...initialResult.findings);
			if (mode === "warn") return item;

			const result =
				mode === "confirm" && ctx.hasUI && item.type === "text"
					? scanText(item.text, buildScanOptions(operationAllowOnce))
					: initialResult;
			const freshRedactions = result.fromCache ? [] : result.redactions;
			redactionCount += freshRedactions.length;
			logRedactions(`${event.toolName} tool result`, freshRedactions);
			return { ...item, text: result.redacted };
		});

		if (!initialResults.some((result) => result && result.findings.length > 0)) return;

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
					? `loaded ${whitelist.values.size + whitelist.valueHashes.size + whitelist.valueRegexes.length + whitelist.disabledRules.size} entries`
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
					`  Hash wl:     ${whitelist.valueHashes.size + sessionWhitelistHashes.size}\n` +
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
