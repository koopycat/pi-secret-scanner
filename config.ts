/**
 * Allowlist configuration: `.gitleaks.toml`, `.secret-scanner.json`, and the
 * confirm-mode `.secret-scanner.local.json`, merged into one whitelist.
 *
 * Loading never throws. Unreadable files and invalid entries are returned as
 * human-readable errors so the extension can show them; every valid entry
 * still applies.
 */

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { parse as parseToml } from "smol-toml";

export const PROJECT_CONFIG_NAME = ".secret-scanner.json";
export const LOCAL_CONFIG_NAME = ".secret-scanner.local.json";
export const GITLEAKS_CONFIG_NAME = ".gitleaks.toml";

export interface WhitelistConfig {
	values?: string[];
	value_hashes?: string[];
	value_regexes?: string[];
	paths?: string[];
	disable_rules?: string[];
}

export interface ResolvedWhitelist {
	values: Set<string>;
	valueHashes: Set<string>;
	/** Gitleaks stopwords: lowercase substrings of a detected value. */
	valueSubstrings: string[];
	valueRegexes: RegExp[];
	pathRegexes: RegExp[];
	disabledRules: Set<string>;
}

export interface LoadedWhitelist {
	whitelist: ResolvedWhitelist | null;
	errors: string[];
}

interface GitleaksAllowlist {
	paths?: unknown[];
	regexes?: unknown[];
	stopwords?: unknown[];
}

/**
 * Convert a gitleaks/PCRE regex string to a JavaScript RegExp.
 * Handles leading inline flags like (?i), (?m), (?s) that JS doesn't support natively.
 */
export function toJsRegex(pattern: string): RegExp {
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

function errorMessage(error: unknown): string {
	return error instanceof Error ? error.message : String(error);
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

export function whitelistSize(wl: ResolvedWhitelist): number {
	return (
		wl.values.size +
		wl.valueHashes.size +
		wl.valueSubstrings.length +
		wl.valueRegexes.length +
		wl.pathRegexes.length +
		wl.disabledRules.size
	);
}

function asArray(value: unknown): unknown[] {
	return Array.isArray(value) ? value : [];
}

function loadGitleaksToml(cwd: string, errors: string[]): ResolvedWhitelist | null {
	const configPath = join(cwd, GITLEAKS_CONFIG_NAME);
	if (!existsSync(configPath)) return null;

	let parsed: Record<string, unknown>;
	try {
		parsed = parseToml(readFileSync(configPath, "utf-8"));
	} catch (error) {
		errors.push(`${GITLEAKS_CONFIG_NAME}: ${errorMessage(error)}`);
		return null;
	}

	// Support both [allowlist] (singular) and [[allowlists]] (plural array).
	const all: GitleaksAllowlist[] = [];
	if (parsed.allowlist && typeof parsed.allowlist === "object") all.push(parsed.allowlist);
	all.push(...(asArray(parsed.allowlists) as GitleaksAllowlist[]));

	const resolved = emptyWhitelist();
	for (const al of all) {
		// Gitleaks matches stopwords as case-insensitive substrings of the secret.
		for (const word of asArray(al.stopwords)) {
			if (typeof word === "string" && word) resolved.valueSubstrings.push(word.toLowerCase());
		}
		resolved.valueRegexes.push(
			...compileRegexes(asArray(al.regexes), toJsRegex, `${GITLEAKS_CONFIG_NAME} regexes`, errors),
		);
		resolved.pathRegexes.push(
			...compileRegexes(asArray(al.paths), toJsRegex, `${GITLEAKS_CONFIG_NAME} paths`, errors),
		);
	}
	return whitelistSize(resolved) > 0 ? resolved : null;
}

function loadSecretScannerJson(cwd: string, fileName: string, errors: string[]): ResolvedWhitelist | null {
	const configPath = join(cwd, fileName);
	if (!existsSync(configPath)) return null;

	let wl: WhitelistConfig | undefined;
	try {
		wl = (JSON.parse(readFileSync(configPath, "utf-8")) as { whitelist?: WhitelistConfig } | null)?.whitelist;
	} catch (error) {
		errors.push(`${fileName}: ${errorMessage(error)}`);
		return null;
	}
	if (!wl) return null;

	const toRegex = (source: string) => new RegExp(source);
	const strings = (value: unknown) => asArray(value).filter((entry): entry is string => typeof entry === "string");
	const resolved: ResolvedWhitelist = {
		values: new Set(strings(wl.values)),
		valueHashes: new Set(strings(wl.value_hashes)),
		valueSubstrings: [],
		valueRegexes: compileRegexes(asArray(wl.value_regexes), toRegex, `${fileName} value_regexes`, errors),
		pathRegexes: compileRegexes(asArray(wl.paths), toRegex, `${fileName} paths`, errors),
		disabledRules: new Set(strings(wl.disable_rules)),
	};
	return whitelistSize(resolved) > 0 ? resolved : null;
}

export function mergeWhitelists(...sources: Array<ResolvedWhitelist | null>): ResolvedWhitelist | null {
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

/** Load and merge every allowlist source in `cwd`; invalid entries are reported, not fatal. */
export function loadWhitelist(cwd: string): LoadedWhitelist {
	const errors: string[] = [];
	const whitelist = mergeWhitelists(
		loadGitleaksToml(cwd, errors),
		loadSecretScannerJson(cwd, PROJECT_CONFIG_NAME, errors),
		loadSecretScannerJson(cwd, LOCAL_CONFIG_NAME, errors),
	);
	return { whitelist, errors };
}

export function isPathWhitelisted(whitelist: ResolvedWhitelist | null, filePath: string): boolean {
	for (const re of whitelist?.pathRegexes ?? []) {
		re.lastIndex = 0;
		if (re.test(filePath)) return true;
	}
	return false;
}
