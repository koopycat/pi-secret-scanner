/**
 * Mutable scanner state and the scan options derived from it.
 *
 * All state lives in one explicit object. The published extension shares a
 * single instance per process (see index.ts), so the mode, counters, and
 * session decisions survive `/new`, resume, and fork just as module-level
 * variables did. Tests create a fresh instance per harness.
 */

import { createHash } from "node:crypto";

import { loadWhitelist } from "./config.ts";
import { SECRET_PATTERNS } from "./patterns.ts";

import type { ResolvedWhitelist } from "./config.ts";
import type { ScanCacheEntry, ScanOptions } from "./scanner.ts";

export type Mode = "off" | "warn" | "redact" | "confirm";

export interface Stats {
	scans: number;
	/** Findings that are replaced in redact mode (named rules and redactable entropy). */
	findingsTotal: number;
	/** Report-only entropy findings: visible in stats, never replaced. */
	reported: number;
	redactions: number;
	byType: Record<string, number>;
}

export interface ScannerState {
	mode: Mode;
	useEntropy: boolean;
	/** Log exact replaced values to stderr (unsafe, opt-in). */
	debug: boolean;
	stats: Stats;
	whitelist: ResolvedWhitelist | null;
	/** Fingerprints allowed until the session ends ("Allow for this session"). */
	sessionWhitelistHashes: Set<string>;
	/** Placeholders written into model-visible content during this session. */
	emittedPlaceholders: Set<string>;
	/**
	 * Sanitized text keyed by a SHA-256 of the input. Hashing avoids retaining
	 * original transcript text as keys; eviction keeps the cache bounded.
	 */
	textCache: Map<string, ScanCacheEntry>;
	redactionFlash: { count: number; location: string } | null;
	redactionFlashTimer: ReturnType<typeof setTimeout> | undefined;
}

export const TEXT_CACHE_LIMIT = 4096;

export function emptyStats(): Stats {
	return { scans: 0, findingsTotal: 0, reported: 0, redactions: 0, byType: {} };
}

export function createState(): ScannerState {
	return {
		mode: "redact",
		useEntropy: true,
		debug: false,
		stats: emptyStats(),
		whitelist: null,
		sessionWhitelistHashes: new Set(),
		emittedPlaceholders: new Set(),
		textCache: new Map(),
		redactionFlash: null,
		redactionFlashTimer: undefined,
	};
}

/** Reload the merged allowlist for `cwd` into the state; returns configuration problems. */
export function reloadWhitelist(state: ScannerState, cwd: string): string[] {
	const loaded = loadWhitelist(cwd);
	state.whitelist = loaded.whitelist;
	return loaded.errors;
}

export function clearRedactionFlash(state: ScannerState): void {
	if (state.redactionFlashTimer) clearTimeout(state.redactionFlashTimer);
	state.redactionFlashTimer = undefined;
	state.redactionFlash = null;
}

function sha256Hex(value: string): string {
	return createHash("sha256").update(value).digest("hex");
}

/** The representation stored in `value_hashes` and session/project allowlists. */
export function secretFingerprint(value: string): string {
	return `sha256:${sha256Hex(value)}`;
}

export interface ScanRequest {
	/** Fingerprints allowed for this single operation (confirm mode). */
	allowOnce?: ReadonlySet<string>;
	/** Confirm mode: the result reflects the user's decisions and may be cached. */
	decided?: boolean;
	/** Run the entropy fallback for this scan; defaults to the global toggle. */
	entropy?: boolean;
	/** New content (a tool result): confirm mode asks about it even if identical text was decided before. */
	fresh?: boolean;
}

export function buildScanOptions(state: ScannerState, request: ScanRequest = {}): ScanOptions {
	const scanEntropy = state.useEntropy && request.entropy !== false;
	const { whitelist } = state;
	return {
		useEntropy: scanEntropy,
		patterns: SECRET_PATTERNS,
		whitelist: whitelist?.values,
		whitelistSubstrings: whitelist?.valueSubstrings,
		whitelistRegexes: whitelist?.valueRegexes,
		whitelistHashes: new Set([
			...(whitelist?.valueHashes ?? []),
			...state.sessionWhitelistHashes,
			...(request.allowOnce ?? []),
		]),
		hashWhitelistValue: secretFingerprint,
		disabledRules: whitelist?.disabledRules,
		textCache: state.textCache,
		// Entropy-free scans produce different results for the same text.
		textCacheKey: (text) => (scanEntropy ? sha256Hex(text) : `no-entropy:${sha256Hex(text)}`),
		textCacheMaxEntries: TEXT_CACHE_LIMIT,
		// Confirm mode reuses earlier results for re-sent history, which already
		// reflect the user's decisions, so the same content never prompts twice.
		// New tool output is a new occurrence and is always asked about. An
		// undecided result is cached only when it has nothing to decide.
		cacheRead: state.mode !== "confirm" || !request.fresh,
		cacheWrite: state.mode !== "confirm" || request.decided ? true : "clean",
	};
}
