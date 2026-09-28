/**
 * Core scanning and redaction logic.
 *
 * Uses a curated set of hand-tuned regex patterns (patterns.ts) for code
 * and payload scanning -- zero false positives on source code because every
 * rule requires provider-specific context (prefixes, keywords, or delimiters).
 *
 * Optionally falls back to Shannon entropy analysis for high-entropy strings.
 */

import { shannonEntropy, findHighEntropyStrings } from "./entropy.ts";
import { SECRET_PATTERNS } from "./patterns.ts";

import type { SecretPattern as _SecretPattern } from "./patterns.ts";

// ── Re-exports ────────────────────────────────────────────────────────────────

export { shannonEntropy };

// ── Types ─────────────────────────────────────────────────────────────────────

export type FindingSource = "regex" | "entropy";

export interface Finding {
	type: string;
	source: FindingSource;
	value: string;
	confidence: "high" | "medium" | "low";
	entropy?: number;
	charSet?: string;
}

export interface ScanResult {
	findings: Finding[];
	/** Findings whose spans were actually replaced after overlap resolution. */
	redactions: Finding[];
	/** Text with secret values replaced by [REDACTED:TYPE] placeholders. */
	redacted: string;
}

export interface ScanOptions {
	useEntropy?: boolean;
	patterns?: typeof SECRET_PATTERNS;
	/** Exact secret values to skip (gitleaks "stopwords" equivalent). */
	whitelist?: Set<string>;
	/** Regex patterns -- if a secret value matches, it's skipped. */
	whitelistRegexes?: RegExp[];
	/** Rule names to disable entirely (e.g. "Generic Password Assignment"). */
	disabledRules?: Set<string>;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function placeholder(type: string): string {
	return `[REDACTED:${type.toUpperCase().replace(/\s+/g, "_")}]`;
}

function isWhitelisted(value: string, whitelist?: Set<string>, regexes?: RegExp[]): boolean {
	if (whitelist?.has(value)) return true;
	if (regexes) {
		for (const re of regexes) {
			re.lastIndex = 0;
			if (re.test(value)) return true;
		}
	}
	return false;
}

// ── Text scanning ─────────────────────────────────────────────────────────────

type ExecWithIndices = RegExpExecArray & { indices?: Array<[number, number] | undefined> };

export function scanText(text: string, options?: ScanOptions): ScanResult {
	const patterns = options?.patterns ?? SECRET_PATTERNS;
	const disabled = options?.disabledRules;
	const findings: Finding[] = [];

	type Redaction = { start: number; end: number; placeholder: string; finding: Finding };
	const candidates: Redaction[] = [];

	// Phase 1: Regex patterns.
	for (const pattern of patterns) {
		if (disabled?.has(pattern.name)) continue;

		// Clone with the `d` flag when the pattern targets a capture group so the
		// group's offset is exact even if the value recurs inside the assignment
		// prefix (e.g. `token=token12345678`).
		const regex =
			pattern.secretGroup === undefined
				? pattern.regex
				: new RegExp(pattern.regex.source, `${pattern.regex.flags}d`);

		regex.lastIndex = 0;
		let match: RegExpExecArray | null;
		while ((match = regex.exec(text)) !== null) {
			const group = pattern.secretGroup;
			const value = group === undefined ? match[0] : match[group];
			if (!value) {
				if (match[0].length === 0) regex.lastIndex++;
				continue;
			}
			if (pattern.rejectValue?.(value)) continue;

			let start: number;
			if (group === undefined) {
				start = match.index;
			} else {
				const indices = (match as ExecWithIndices).indices?.[group];
				if (!indices) continue;
				start = indices[0];
			}
			const end = start + value.length;

			if (value.startsWith("[REDACTED:") || match[0].includes("[REDACTED:")) continue;
			if (isWhitelisted(value, options?.whitelist, options?.whitelistRegexes)) continue;

			const finding: Finding = {
				type: pattern.name,
				source: "regex",
				value,
				confidence: pattern.confidence,
			};
			findings.push(finding);
			candidates.push({ start, end, placeholder: placeholder(pattern.name), finding });
		}
	}

	// Phase 2: Entropy detection (optional).
	if (options?.useEntropy !== false) {
		for (const ef of findHighEntropyStrings(text)) {
			if (isWhitelisted(ef.value, options?.whitelist, options?.whitelistRegexes)) continue;
			if (candidates.some((part) => ef.start < part.end && part.start < ef.end)) continue;

			const finding: Finding = {
				type: `High-Entropy ${ef.charSet.toUpperCase()}`,
				source: "entropy",
				value: ef.value,
				confidence: "low",
				entropy: ef.entropy,
				charSet: ef.charSet,
			};
			findings.push(finding);
			candidates.push({ start: ef.start, end: ef.end, placeholder: placeholder(finding.type), finding });
		}
	}

	// Resolve overlaps before modifying the text. A specific, high-confidence
	// detection wins over a broader generic or entropy-based detection.
	const confidenceRank = { high: 0, medium: 1, low: 2 } as const;
	candidates.sort(
		(a, b) =>
			confidenceRank[a.finding.confidence] - confidenceRank[b.finding.confidence] ||
			a.end - a.start - (b.end - b.start) ||
			a.start - b.start,
	);
	const selected: Redaction[] = [];
	for (const candidate of candidates) {
		if (selected.some((part) => candidate.start < part.end && part.start < candidate.end)) continue;
		selected.push(candidate);
	}
	selected.sort((a, b) => a.start - b.start);

	let cursor = 0;
	let redacted = "";
	for (const part of selected) {
		redacted += text.slice(cursor, part.start) + part.placeholder;
		cursor = part.end;
	}
	redacted += text.slice(cursor);

	return { findings, redactions: selected.map((part) => part.finding), redacted };
}

// ── Object scanning (for provider payloads) ───────────────────────────────────

/**
 * Object keys whose string values are file-system paths, never secrets.
 * Edit-tool payloads carry project paths here; scanning them corrupted the
 * path in-flight (the LLM received `[REDACTED:HIGH-ENTROPY_MIXED].ts` and the
 * edit failed with ENOENT). Credential-bearing keys (token, secret, …) are
 * deliberately NOT in this list -- their values always stay scannable.
 */
const PATH_KEYS = new Set([
	"path",
	"file_path",
	"filepath",
	"abs_path",
	"absolute_path",
	"cwd",
	"dir",
	"directory",
	"folder",
	"workdir",
	"working_dir",
]);

function normalizeKey(key: string): string {
	return key
		.replace(/([a-z0-9])([A-Z])/g, "$1_$2")
		.replace(/([A-Z]+)([A-Z][a-z])/g, "$1_$2")
		.toLowerCase();
}

export interface ObjectScanResult {
	findings: Finding[];
	/** Findings whose values were actually replaced. */
	redactions: Finding[];
	/** Deep clone of the object with secret string values replaced. */
	redactedObject: unknown;
	/** True if any findings were made. */
	hasFindings: boolean;
}

/**
 * Recursively walks a JSON-serializable object, scanning every string value.
 * Returns a deep clone where secrets are replaced with placeholders.
 */
export function scanObject(obj: unknown, options?: ScanOptions): ObjectScanResult {
	const allFindings: Finding[] = [];
	const allRedactions: Finding[] = [];

	function walk(node: unknown): unknown {
		if (typeof node === "string") {
			const result = scanText(node, options);
			allFindings.push(...result.findings);
			allRedactions.push(...result.redactions);
			return result.redacted;
		}

		if (Array.isArray(node)) {
			return node.map(walk);
		}

		if (node !== null && typeof node === "object") {
			const out: Record<string, unknown> = {};
			for (const [key, value] of Object.entries(node as Record<string, unknown>)) {
				// String values under known path keys are file-system paths, not
				// secrets; pass them through untouched. Everything else is scanned.
				out[key] = typeof value === "string" && PATH_KEYS.has(normalizeKey(key)) ? value : walk(value);
			}
			return out;
		}

		return node;
	}

	const redactedObject = walk(obj);

	return {
		findings: allFindings,
		redactions: allRedactions,
		redactedObject,
		hasFindings: allFindings.length > 0,
	};
}

// ── Summary helpers ───────────────────────────────────────────────────────────

export function formatFindings(findings: Finding[]): string {
	if (findings.length === 0) return "No secrets detected.";

	const seen = new Set<string>();
	const lines: string[] = [];

	for (const f of findings) {
		if (seen.has(f.type)) continue;
		seen.add(f.type);

		const confidence = f.confidence === "high" ? "🔴" : f.confidence === "medium" ? "🟡" : "🟢";
		let line = `  ${confidence} ${f.type}`;
		if (f.entropy) {
			line += ` (entropy: ${f.entropy.toFixed(1)}, charset: ${f.charSet})`;
		}
		lines.push(line);
	}

	return lines.join("\n");
}

export function countByType(findings: Finding[]): Record<string, number> {
	const counts: Record<string, number> = {};
	for (const f of findings) {
		counts[f.type] = (counts[f.type] ?? 0) + 1;
	}
	return counts;
}
