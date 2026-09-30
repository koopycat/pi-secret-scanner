/**
 * Secret Scanner Extension
 *
 * Scans outgoing LLM requests (and tool results) for secrets before
 * they leave the machine. Supports four modes:
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
 * Whitelist config (all merged): .gitleaks.toml, .secret-scanner.json, .secret-scanner.local.json
 *
 *   .gitleaks.toml   – native gitleaks format, supports [allowlist] and [[allowlists]]
 *   .secret-scanner.json  – { "whitelist": { "values": [...], "value_regexes": [...], "paths": [...], "disable_rules": [...] } }
 *
 * Detection strategy:
 *   1. Named regex patterns for known secret formats (AWS, GitHub, Stripe...)
 *   2. Shannon entropy analysis for unknown high-entropy values
 *
 * Hooks:
 *   before_agent_start       – tells the model what redaction placeholders mean
 *   before_provider_request  – scans / redacts the full payload just before
 *                              it's sent to the LLM provider
 *   tool_result (all tools)  – scans tool output before it enters the
 *                              message history
 *   tool_call (edit, write)  – blocks writes that would copy redaction
 *                              placeholders over the real values on disk
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
	rmSync,
	statSync,
	writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { join, relative, resolve } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";

import { parse as parseToml } from "smol-toml";

import { isLockfile } from "./lockfiles.ts";
import { SECRET_PATTERNS } from "./patterns.ts";
import { countByType, formatConfirmFindings, placeholderFor, scanObject, scanText } from "./scanner.ts";

import type { Finding, ScanCacheEntry, ScanOptions } from "./scanner.ts";
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";

// ── State ─────────────────────────────────────────────────────────────────────

type Mode = "off" | "warn" | "redact" | "confirm";

interface Stats {
	scans: number;
	/** Findings that are replaced in redact mode (named rules and redactable entropy). */
	findingsTotal: number;
	/** Report-only entropy findings: visible in stats, never replaced. */
	reported: number;
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
	/** Gitleaks stopwords: lowercase substrings of a detected value. */
	valueSubstrings: string[];
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
let stats: Stats = emptyStats();
let redactionFlash: { count: number; location: string } | null = null;
let redactionFlashTimer: ReturnType<typeof setTimeout> | undefined;

const REDACTION_FLASH_MS = 5_000;
let whitelist: ResolvedWhitelist | null = null;
let sessionWhitelistHashes = new Set<string>();
/** Placeholders this process has written into model-visible content. */
const emittedPlaceholders = new Set<string>();

const LOCAL_CONFIG_NAME = ".secret-scanner.local.json";
const LOCK_ATTEMPTS = 40;
const LOCK_RETRY_MS = 25;
// A lock older than this was left behind by a crashed process; holding it
// never takes longer than one small synchronous read-modify-write.
const LOCK_STALE_MS = 10_000;
const CONFIRM_REDACT = "Redact";
const CONFIRM_ALLOW_ONCE = "Allow once";
const CONFIRM_ALLOW_SESSION = "Allow for this session";
const CONFIRM_ALLOW_PROJECT = "Always allow in this project";

const USAGE = "Usage: /secret-scanner [off|warn|redact|confirm | entropy on|off | debug on|off | reset | reload]";

// Appended to the system prompt while redaction is active, so the model
// treats placeholders as opaque instead of guessing or writing them back.
const REDACTION_NOTE =
	"Secret scanner: values shown as [REDACTED:TYPE] were replaced locally before reaching you; " +
	"the real values still exist in files and command output. Treat placeholders as opaque. " +
	"Do not try to recover or guess them, and never write a placeholder into a file: " +
	"choose edit oldText that excludes redacted lines, and ask the user when a secret itself must change.";

const PLACEHOLDER = /\[REDACTED:[^\]\s]+\]/g;

// This cache is process-local only. Hashing avoids retaining original
// transcript text as Map keys, and bounded eviction prevents unbounded growth.
const TEXT_CACHE_LIMIT = 4096;
const textCache = new Map<string, ScanCacheEntry>();

function emptyStats(): Stats {
	return { scans: 0, findingsTotal: 0, reported: 0, redactions: 0, byType: {} };
}

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
	stats = emptyStats();
}

function mergeTypeCounts(into: Record<string, number>, from: Record<string, number>) {
	for (const [type, count] of Object.entries(from)) {
		into[type] = (into[type] ?? 0) + count;
	}
}

function logRedactions(location: string, findings: Finding[]): void {
	if (!debug || findings.length === 0) return;
	for (const finding of findings) {
		// Debug mode is deliberately unsafe: exact secrets can persist in terminal logs.
		console.warn(
			`[secret-scanner][debug] replaced ${finding.type} (${finding.source}) in ${location}: ${JSON.stringify(finding.value)}`,
		);
	}
}

function rememberPlaceholders(findings: Finding[]): void {
	for (const finding of findings) emittedPlaceholders.add(placeholderFor(finding.type));
}

function resolveToolPath(cwd: string, filePath: string): string {
	const expanded = filePath.replace(/^@/, "").replace(/^~(?=$|[/\\])/, homedir());
	return resolve(cwd, expanded);
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

/**
 * Compile each pattern independently so one unsupported expression drops only
 * itself, not the whole allowlist file.
 */
function compileRegexes(
	patterns: readonly unknown[],
	compile: (pattern: string) => RegExp,
	label: string,
	errors: string[],
): RegExp[] {
	const compiled: RegExp[] = [];
	for (const pattern of patterns) {
		if (typeof pattern !== "string") {
			errors.push(`${label}: ignored non-string entry ${JSON.stringify(pattern)}`);
			continue;
		}
		try {
			compiled.push(compile(pattern));
		} catch (error) {
			errors.push(`${label}: ignored invalid regex ${JSON.stringify(pattern)} (${errorMessage(error)})`);
		}
	}
	return compiled;
}

function errorMessage(error: unknown): string {
	return error instanceof Error ? error.message : String(error);
}

function emptyWhitelist(): ResolvedWhitelist {
	return {
		values: new Set(),
		valueHashes: new Set(),
		valueSubstrings: [],
		valueRegexes: [],
		pathRegexes: [],
		disabledRules: new Set(),
	};
}

function whitelistSize(wl: ResolvedWhitelist): number {
	return (
		wl.values.size +
		wl.valueHashes.size +
		wl.valueSubstrings.length +
		wl.valueRegexes.length +
		wl.pathRegexes.length +
		wl.disabledRules.size
	);
}

function loadGitleaksToml(cwd: string, errors: string[]): ResolvedWhitelist | null {
	const fileName = ".gitleaks.toml";
	const configPath = join(cwd, fileName);
	if (!existsSync(configPath)) return null;

	let parsed: Record<string, unknown>;
	try {
		parsed = parseToml(readFileSync(configPath, "utf-8"));
	} catch (error) {
		errors.push(`${fileName}: ${errorMessage(error)}`);
		return null;
	}

	// Support both [allowlist] (singular) and [[allowlists]] (plural array).
	const allowlist = parsed.allowlist as GitleaksAllowlist | undefined;
	const allowlists = parsed.allowlists as GitleaksAllowlist[] | undefined;

	const all: GitleaksAllowlist[] = [];
	if (allowlist) all.push(allowlist);
	if (allowlists) all.push(...allowlists);

	const resolved = emptyWhitelist();
	for (const al of all) {
		// Gitleaks matches stopwords as case-insensitive substrings of the secret.
		for (const w of al.stopwords ?? [])
			if (typeof w === "string" && w) resolved.valueSubstrings.push(w.toLowerCase());
		resolved.valueRegexes.push(...compileRegexes(al.regexes ?? [], toJsRegex, `${fileName} regexes`, errors));
		resolved.pathRegexes.push(...compileRegexes(al.paths ?? [], toJsRegex, `${fileName} paths`, errors));
	}
	return whitelistSize(resolved) > 0 ? resolved : null;
}

function loadSecretScannerJson(cwd: string, fileName: string, errors: string[]): ResolvedWhitelist | null {
	const configPath = join(cwd, fileName);
	if (!existsSync(configPath)) return null;

	let wl: WhitelistConfig | undefined;
	try {
		wl = (JSON.parse(readFileSync(configPath, "utf-8")) as { whitelist?: WhitelistConfig }).whitelist;
	} catch (error) {
		errors.push(`${fileName}: ${errorMessage(error)}`);
		return null;
	}
	if (!wl) return null;

	const toRegex = (source: string) => new RegExp(source);
	const resolved: ResolvedWhitelist = {
		values: new Set(wl.values ?? []),
		valueHashes: new Set(wl.value_hashes ?? []),
		valueSubstrings: [],
		valueRegexes: compileRegexes(wl.value_regexes ?? [], toRegex, `${fileName} value_regexes`, errors),
		pathRegexes: compileRegexes(wl.paths ?? [], toRegex, `${fileName} paths`, errors),
		disabledRules: new Set(wl.disable_rules ?? []),
	};
	return whitelistSize(resolved) > 0 ? resolved : null;
}

function mergeWhitelists(...sources: Array<ResolvedWhitelist | null>): ResolvedWhitelist | null {
	const present = sources.filter((source): source is ResolvedWhitelist => source !== null);
	if (present.length === 0) return null;
	if (present.length === 1) return present[0] ?? null;
	return {
		values: new Set(present.flatMap((wl) => [...wl.values])),
		valueHashes: new Set(present.flatMap((wl) => [...wl.valueHashes])),
		valueSubstrings: present.flatMap((wl) => wl.valueSubstrings),
		valueRegexes: present.flatMap((wl) => wl.valueRegexes),
		pathRegexes: present.flatMap((wl) => wl.pathRegexes),
		disabledRules: new Set(present.flatMap((wl) => [...wl.disabledRules])),
	};
}

/** Load and merge every allowlist source; invalid entries are reported, not fatal. */
function loadWhitelist(cwd: string): { whitelist: ResolvedWhitelist | null; errors: string[] } {
	const errors: string[] = [];
	const merged = mergeWhitelists(
		loadGitleaksToml(cwd, errors),
		loadSecretScannerJson(cwd, ".secret-scanner.json", errors),
		loadSecretScannerJson(cwd, LOCAL_CONFIG_NAME, errors),
	);
	return { whitelist: merged, errors };
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
	let tracked = true;
	try {
		execFileSync("git", ["ls-files", "--error-unmatch", "--", relativeConfigPath], {
			cwd: root,
			stdio: "ignore",
		});
	} catch {
		tracked = false;
	}
	if (tracked) {
		throw new Error(`${relativeConfigPath} is already tracked by Git; untrack it before saving local decisions`);
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

function isStaleLock(lockPath: string): boolean {
	try {
		return Date.now() - statSync(lockPath).mtimeMs > LOCK_STALE_MS;
	} catch {
		return false; // Released between our open attempt and this check.
	}
}

async function acquireLock(lockPath: string): Promise<number> {
	for (let attempt = 0; attempt < LOCK_ATTEMPTS; attempt++) {
		try {
			return openSync(lockPath, "wx", 0o600);
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
			if (isStaleLock(lockPath)) {
				rmSync(lockPath, { force: true });
				continue;
			}
			await sleep(LOCK_RETRY_MS);
		}
	}
	throw new Error(`${LOCAL_CONFIG_NAME} is locked by another process; remove ${lockPath} if none is running`);
}

async function persistProjectFingerprint(cwd: string, fingerprint: string): Promise<void> {
	const configPath = join(cwd, LOCAL_CONFIG_NAME);
	const lockPath = `${configPath}.lock`;
	const lockFd = await acquireLock(lockPath);

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
		rmSync(temporaryPath, { force: true });
		closeSync(lockFd);
		// Never let lock cleanup mask the original error.
		rmSync(lockPath, { force: true });
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

interface ScanRequest {
	/** Fingerprints allowed for this single operation (confirm mode). */
	allowOnce?: ReadonlySet<string>;
	/** Confirm mode: the result reflects the user's decisions and may be cached. */
	decided?: boolean;
	/** Run the entropy fallback for this scan; defaults to the global toggle. */
	entropy?: boolean;
	/** New content (a tool result): confirm mode asks about it even if identical text was decided before. */
	fresh?: boolean;
}

function buildScanOptions(request: ScanRequest = {}): ScanOptions {
	const scanEntropy = useEntropy && request.entropy !== false;
	return {
		useEntropy: scanEntropy,
		patterns: SECRET_PATTERNS,
		whitelist: whitelist?.values,
		whitelistSubstrings: whitelist?.valueSubstrings,
		whitelistRegexes: whitelist?.valueRegexes,
		whitelistHashes: new Set([
			...(whitelist?.valueHashes ?? []),
			...sessionWhitelistHashes,
			...(request.allowOnce ?? []),
		]),
		hashWhitelistValue: secretFingerprint,
		disabledRules: whitelist?.disabledRules,
		textCache,
		// Entropy-free scans produce different results for the same text.
		textCacheKey: (text) => (scanEntropy ? cacheKey(text) : `no-entropy:${cacheKey(text)}`),
		textCacheMaxEntries: TEXT_CACHE_LIMIT,
		// Confirm mode reuses earlier results for re-sent history, which already
		// reflect the user's decisions, so the same content never prompts twice.
		// New tool output is a new occurrence and is always asked about. An
		// undecided result is cached only when it has nothing to decide.
		cacheRead: mode !== "confirm" || !request.fresh,
		cacheWrite: mode !== "confirm" || request.decided ? true : "clean",
	};
}

// ── Extension ─────────────────────────────────────────────────────────────────

export default function (pi: ExtensionAPI) {
	// Only the UI surface the helpers need; every pi context is structurally compatible.
	type StatusContext = Pick<ExtensionContext, "ui" | "hasUI">;

	function applyConfig(ctx: StatusContext & { cwd: string }): void {
		const loaded = loadWhitelist(ctx.cwd);
		whitelist = loaded.whitelist;
		if (loaded.errors.length === 0) return;
		const message = `Secret scanner configuration problems (other entries still apply):\n  ${loaded.errors.join("\n  ")}`;
		if (ctx.hasUI) ctx.ui.notify(message, "error");
		else console.error(`[secret-scanner] ${message}`);
	}

	async function chooseConfirmActions(
		findings: Finding[],
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
					await persistProjectFingerprint(ctx.cwd, fingerprint);
					applyConfig(ctx);
					ctx.ui.notify(`Saved fingerprint to ${LOCAL_CONFIG_NAME}; plaintext was not stored`, "info");
				} catch (error) {
					ctx.ui.notify(
						`Could not save ${LOCAL_CONFIG_NAME}; keeping the value redacted: ${errorMessage(error)}`,
						"error",
					);
				}
			}
			// Escape/cancel returns undefined and therefore fails safe to redaction.
		}
		return allowOnce;
	}

	function accountFindings(findings: Finding[]): void {
		if (findings.length === 0) return;
		const actionable = findings.filter((finding) => finding.action !== "report");
		stats.findingsTotal += actionable.length;
		stats.reported += findings.length - actionable.length;
		mergeTypeCounts(stats.byType, countByType(actionable));
	}

	function accountRedactions(ctx: StatusContext, findings: Finding[], location: string): void {
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
		const wlInfo = whitelist ? ` wl:${whitelistSize(whitelist) - whitelist.pathRegexes.length}` : "";
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
		if (event.reason !== "reload") {
			sessionWhitelistHashes = new Set();
			emittedPlaceholders.clear();
		}
		applyConfig(ctx);
		redactionFlash = null;
		if (redactionFlashTimer) clearTimeout(redactionFlashTimer);
		redactionFlashTimer = undefined;
		updateStatus(ctx);
	});

	pi.on("session_shutdown", (_event, ctx) => {
		clearScanCaches();
		sessionWhitelistHashes.clear();
		emittedPlaceholders.clear();
		if (redactionFlashTimer) clearTimeout(redactionFlashTimer);
		redactionFlashTimer = undefined;
		redactionFlash = null;
		if (ctx.hasUI) ctx.ui.setStatus("secret-scanner", undefined);
	});

	// ── Hook: before_agent_start ─────────────────────────────────────────────

	pi.on("before_agent_start", (event) => {
		if (mode !== "redact" && mode !== "confirm") return;
		return { systemPrompt: `${event.systemPrompt}\n\n${REDACTION_NOTE}` };
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
			rememberPlaceholders(result.redactions);
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

		if (mode === "confirm" && ctx.hasUI && result.freshRedactions.length > 0) {
			// Cached chunks already carry earlier decisions and never prompt again.
			const allowOnce = await chooseConfirmActions(result.freshRedactions, ctx, "provider request");
			const decided = scanObject(event.payload, buildScanOptions({ allowOnce, decided: true }));
			accountRedactions(ctx, decided.freshRedactions, "provider request");
			rememberPlaceholders(decided.redactions);
			return decided.redactions.length > 0 ? decided.redactedObject : undefined;
		}

		accountRedactions(ctx, result.freshRedactions, "provider request");
		rememberPlaceholders(result.redactions);
		return result.redactedObject;
	});

	// ── Hook: tool_result (every tool) ──────────────────────────────────────

	pi.on("tool_result", async (event, ctx) => {
		if (mode === "off") return;

		const readPath = event.toolName === "read" && typeof event.input.path === "string" ? event.input.path : null;
		// Path-based whitelist: skip scanning results from whitelisted files.
		if (readPath !== null && isPathWhitelisted(readPath)) return;

		const contentItems = event.content;
		if (!Array.isArray(contentItems)) return;

		stats.scans++;

		const request: ScanRequest = { entropy: readPath === null || !isLockfile(readPath), fresh: true };
		let redactionCount = 0;
		const allFindings: Finding[] = [];
		const initialResults = contentItems.map((item) =>
			item.type === "text" && typeof item.text === "string"
				? scanText(item.text, buildScanOptions(request))
				: null,
		);
		const operationAllowOnce = new Set<string>();
		const confirming = mode === "confirm" && ctx.hasUI;

		if (confirming) {
			// Cached results already carry earlier decisions (and blank values).
			const operationRedactions = initialResults.flatMap((result) =>
				result && !result.fromCache ? result.redactions : [],
			);
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
				confirming && item.type === "text"
					? scanText(
							item.text,
							buildScanOptions({ ...request, allowOnce: operationAllowOnce, decided: true }),
						)
					: initialResult;
			const freshRedactions = result.fromCache ? [] : result.redactions;
			redactionCount += freshRedactions.length;
			logRedactions(`${event.toolName} tool result`, freshRedactions);
			rememberPlaceholders(result.redactions);
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

	// ── Hook: tool_call (edit, write) ────────────────────────────────────────

	pi.on("tool_call", (event, ctx) => {
		if (mode === "off" || emittedPlaceholders.size === 0) return;
		if (event.toolName !== "edit" && event.toolName !== "write") return;

		const input = event.input as { path?: unknown; content?: unknown; edits?: unknown };
		if (typeof input.path !== "string") return;
		const texts: unknown[] =
			event.toolName === "write"
				? [input.content]
				: Array.isArray(input.edits)
					? input.edits.flatMap((edit: { oldText?: unknown; newText?: unknown }) => [
							edit.oldText,
							edit.newText,
						])
					: [];

		const used = new Set<string>();
		for (const text of texts) {
			if (typeof text !== "string") continue;
			for (const match of text.matchAll(PLACEHOLDER)) {
				if (emittedPlaceholders.has(match[0])) used.add(match[0]);
			}
		}
		if (used.size === 0) return;

		// A file that already contains the literal placeholder (docs, tests) is
		// edited legitimately; only block placeholders standing in for real values.
		let existing = "";
		try {
			existing = readFileSync(resolveToolPath(ctx.cwd, input.path), "utf-8");
		} catch {
			// New or unreadable file: nothing on disk legitimizes the placeholder.
		}
		const foreign = [...used].filter((placeholder) => !existing.includes(placeholder));
		if (foreign.length === 0) return;

		return {
			block: true,
			reason:
				`Blocked by secret scanner: this ${event.toolName} would write ${foreign.join(", ")} into ${input.path}. ` +
				"Placeholders stand in for secret values that were removed before you saw them; the file still holds the real values. " +
				"Do not copy placeholders into files. Choose edit oldText/newText that excludes the redacted lines, " +
				"or ask the user to change the secret themselves.",
		};
	});

	// ── Command: /secret-scanner ─────────────────────────────────────────────

	pi.registerCommand("secret-scanner", {
		description:
			"Show secret scanner status or set mode: warn | redact | confirm | entropy on/off | debug on/off | reset | reload",
		handler: async (args, ctx) => {
			const arg = args.trim().toLowerCase().replace(/\s+/g, " ");

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
				applyConfig(ctx);
				updateStatus(ctx);
				const wlMsg = whitelist ? `loaded ${whitelistSize(whitelist)} entries` : "no whitelist found";
				ctx.ui.notify(`Secret scanner whitelist reloaded: ${wlMsg}`, "info");
				return;
			}

			if (arg !== "" && arg !== "status") {
				ctx.ui.notify(`Unknown secret scanner command: ${arg}\n${USAGE}`, "warning");
				return;
			}

			const typeBreakdown =
				Object.keys(stats.byType).length > 0
					? `\n\nTypes found:\n${Object.entries(stats.byType)
							.sort(([, a], [, b]) => b - a)
							.map(([t, n]) => `  ${t}: ${n}`)
							.join("\n")}`
					: "";

			const wlInfo = whitelist
				? `\n  Values wl:   ${whitelist.values.size + whitelist.valueSubstrings.length}\n` +
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
					`  Findings:    ${stats.findingsTotal}${stats.reported > 0 ? ` (+${stats.reported} report-only)` : ""}\n` +
					`  Redactions:  ${stats.redactions}${wlInfo}${typeBreakdown}`,
				"info",
			);
		},
	});
}
