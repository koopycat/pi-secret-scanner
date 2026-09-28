/**
 * Shannon entropy analysis for detecting high-entropy strings that may be secrets.
 *
 * Strategy:
 *   1. Extract "token-shaped" strings from text (values after = / : / in quotes).
 *   2. Calculate Shannon entropy per character.
 *   3. Flag candidates whose entropy exceeds thresholds based on their character set.
 *
 * False positive mitigation:
 *   - Skip candidates that match known-safe patterns (UUIDs, timestamps, placeholders…).
 *   - Apply different thresholds for hex vs base64 vs mixed character sets.
 *   - Require minimum candidate length to reduce noise.
 */

export interface EntropyFinding {
	value: string;
	start: number;
	end: number;
	entropy: number;
	charSet: "hex" | "base64" | "mixed";
}

// ── Character set detection (regex-based, avoids writing long charset literals) ─

function detectCharSet(s: string): "hex" | "base64" | "mixed" | null {
	if (/^[0-9a-fA-F]+$/.test(s)) return "hex";
	// base64 (standard and URL-safe variants)
	if (/^[A-Za-z0-9+/=]+$/.test(s) || /^[A-Za-z0-9_\-=]+$/.test(s)) return "base64";
	if (/[A-Za-z0-9]/.test(s)) return "mixed";
	return null;
}

// ── Thresholds ────────────────────────────────────────────────────────────────
// Lower values = more false positives; higher values = more misses.
// These are tuned to match roughly what gitleaks uses.

const ENTROPY_THRESHOLDS: Record<"hex" | "base64" | "mixed", number> = {
	hex: 3.5, // hex alphabet max ~4 bits; 3.5 = ~87% of max
	base64: 4.5, // base64 alphabet max ~6 bits; 4.5 = ~75% of max
	mixed: 3.7,
};

const MIN_CANDIDATE_LENGTH: Record<"hex" | "base64" | "mixed", number> = {
	hex: 20, // e.g., MD5 is 32 chars
	base64: 20,
	mixed: 16,
};

// ── Known-safe exclusions ──────────────────────────────────────────────────────

const SAFE_PATTERNS = [
	// UUIDs
	/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
	// Long runs of a single repeated char (not random)
	/^(.)\1{7,}$/,
	// Common placeholder strings
	/^(test|example|demo|sample|placeholder|changeme|your_|xxx|000)/i,
	// Unix timestamps (10–13 digits)
	/^[0-9]{10,13}$/,
	// Short hex color codes
	/^[0-9a-f]{6,8}$/i,
	// Data URIs
	/^data:/i,
	// Filesystem paths (Unix absolute, home-relative, Windows)
	/^\/(?:[A-Za-z0-9._\-]+\/)*[A-Za-z0-9._\-]*$/,
	/^~\//,
	/^\.\.?\//,
	// Relative multi-segment filesystem paths (project/src/module, dist/bundle.js).
	// Requires ≥2 separators and forbids `+`/`=` so slashed base64 secrets with
	// padding or plus signs keep being detected.
	/^[A-Za-z0-9._\-]+(?:\/[A-Za-z0-9._\-]+){2,}$/,
];

function isSafe(candidate: string): boolean {
	return SAFE_PATTERNS.some((p) => p.test(candidate));
}

// ── Contextual false-positive suppression ──────────────────────────────────────
// Canonical public identifiers (Git OIDs, Docker/OCI digests and IDs, pinned
// GitHub Action refs, docker-desktop build URLs) are only safe when they appear
// in the metadata context that produces them. The same hex/string under an
// ambiguous or credential-bearing key stays detectable.

const CREDENTIAL_KEYS = new Set([
	"password",
	"passwd",
	"pwd",
	"secret",
	"token",
	"api_key",
	"auth_key",
	"auth_token",
	"access_token",
	"private_key",
]);
const CREDENTIAL_KEY_PARTS = new Set(["password", "passwd", "pwd", "secret", "token"]);
const CREDENTIAL_KEY_SUFFIXES = ["api_key", "auth_key", "auth_token", "access_token", "private_key"];

const GIT_OID_CONTEXT_KEYS = new Set([
	"commit",
	"commit_sha",
	"commit_id",
	"git_commit",
	"git_sha",
	"git_oid",
	"sha",
	"oid",
	"rev",
	"revision",
]);

const LOWER_HEX_40 = /^[0-9a-f]{40}$/;
const LOWER_HEX_40_OR_64 = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const LOWER_HEX_64 = /^[0-9a-f]{64}$/;

// Nearest assignment key immediately before the candidate, e.g. `commit_sha: "`.
const KEY_BEFORE = /([A-Za-z0-9_\-.]{1,40})\s*[=:]\s*["']?$/;
const ASSIGNMENT_KEYS_BEFORE = /(?:^|[\s,;{[("'?&])([A-Za-z0-9_\-.]{1,40})["']?\s*[=:]\s*["']?/g;

function keyBefore(before: string): string | null {
	const m = KEY_BEFORE.exec(before);
	return m?.[1] ?? null;
}

function isCredentialKey(key: string): boolean {
	const normalized = key
		.replace(/([a-z0-9])([A-Z])/g, "$1_$2")
		.replace(/([A-Z]+)([A-Z][a-z])/g, "$1_$2")
		.toLowerCase()
		.replace(/[^a-z0-9]+/g, "_");
	if (CREDENTIAL_KEYS.has(normalized)) return true;
	if (CREDENTIAL_KEY_SUFFIXES.some((suffix) => normalized === suffix || normalized.endsWith(`_${suffix}`)))
		return true;
	return normalized.split("_").some((part) => CREDENTIAL_KEY_PARTS.has(part));
}

function hasCredentialAssignment(before: string): boolean {
	ASSIGNMENT_KEYS_BEFORE.lastIndex = 0;
	let match: RegExpExecArray | null;
	while ((match = ASSIGNMENT_KEYS_BEFORE.exec(before)) !== null) {
		if (match[1] && isCredentialKey(match[1])) return true;
	}
	return false;
}

function isGitOidForKey(candidate: string, key: string): boolean {
	const normalized = key.toLowerCase();
	if (GIT_OID_CONTEXT_KEYS.has(normalized)) return LOWER_HEX_40_OR_64.test(candidate);
	if (normalized === "sha1") return LOWER_HEX_40.test(candidate);
	if (normalized === "sha256") return LOWER_HEX_64.test(candidate);
	return false;
}

function isContextuallySafe(candidate: string, text: string, start: number, end: number): boolean {
	const lineStart = text.lastIndexOf("\n", start - 1) + 1;
	const lineEnd = text.indexOf("\n", end);
	const line = text.slice(lineStart, lineEnd === -1 ? text.length : lineEnd);
	const relStart = start - lineStart;
	const relEnd = end - lineStart;
	const before = line.slice(0, relStart);
	const key = keyBefore(before);

	// Check every assignment before the candidate so nested syntax such as
	// `token=sha256:<value>` cannot disguise a credential as a public digest.
	if (hasCredentialAssignment(before)) return false;

	// Canonical lowercase Git object IDs under explicit public metadata keys.
	if (key && isGitOidForKey(candidate, key)) return true;
	if (LOWER_HEX_40_OR_64.test(candidate) && /\bcommit\s+$/.test(before)) return true;

	// Docker/OCI digest syntax: `sha256:<64 lowercase hex>`.
	if (LOWER_HEX_64.test(candidate) && /(?:^|[@:\s])sha256:\s*$/.test(before)) return true;

	// Bare Docker image/container IDs (underscore or hyphen variants).
	if (LOWER_HEX_64.test(candidate) && key && /^(?:docker[-_]?)?(?:image|container)[-_]id$/.test(key.toLowerCase())) {
		return true;
	}

	// Pinned GitHub Action refs: `uses: owner/repo@<oid>`, optionally quoted
	// and followed by a YAML comment.
	const uses = /\buses:\s*(["']?)[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+@([0-9a-f]{40}|[0-9a-f]{64})\1\s*(?:#.*)?$/.exec(
		line,
	);
	if (uses) {
		const repo = /([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+)@/.exec(uses[0])?.[1] ?? "";
		const oid = uses[2] ?? "";
		const repoStart = uses.index + uses[0].indexOf(repo);
		const oidStart = uses.index + uses[0].lastIndexOf(oid);
		if (relStart === repoStart && relEnd === repoStart + repo.length) return true;
		if (relStart === oidStart && relEnd === oidStart + oid.length) return true;
	}

	// Strict docker-desktop dashboard build URLs. Exempt only complete path
	// segments, not arbitrary candidates embedded inside the URL.
	const buildUrl =
		/(?:^|\s)(docker-desktop:\/\/dashboard\/build\/([A-Za-z0-9._-]+)\/([A-Za-z0-9._-]+)\/([A-Za-z0-9_-]+))\s*$/.exec(
			line,
		);
	if (buildUrl) {
		const url = buildUrl[1] ?? "";
		const urlStart = buildUrl.index + buildUrl[0].indexOf(url);
		for (const segment of buildUrl.slice(2)) {
			if (!segment) continue;
			const segmentStart = buildUrl.index + buildUrl[0].indexOf(segment);
			if (relStart === segmentStart && relEnd === segmentStart + segment.length) return true;
		}
		// The extractor may return the URL tail as one candidate. This exact tail
		// is safe only when it spans the complete path of a canonical build URL.
		const tailStart = urlStart + "docker-desktop:".length;
		if (relStart === tailStart && relEnd === urlStart + url.length) return true;
	}

	return false;
}

// ── Shannon entropy ────────────────────────────────────────────────────────────

export function shannonEntropy(s: string): number {
	const freq: Record<string, number> = {};
	for (const c of s) {
		freq[c] = (freq[c] ?? 0) + 1;
	}
	const len = s.length;
	return Object.values(freq).reduce((sum, count) => {
		const p = count / len;
		return sum - p * Math.log2(p);
	}, 0);
}

// ── Candidate extraction ──────────────────────────────────────────────────────
// Look for value-like positions: after = or :, or quoted strings.

const ASSIGNED_CANDIDATE =
	/(?:^|[\s,;{[("'?&])(?:[A-Za-z0-9_\-.]{2,40})["']?\s*[=:]\s*["']?([A-Za-z0-9+/=_\-]{16,})["']?/gm;
const QUOTED_CANDIDATE = /["']([A-Za-z0-9+/=_\-]{20,200})["']/gm;
const STRUCTURED_CANDIDATE = /(?<=[@:/])([A-Za-z0-9=_\-]{20,})(?![A-Za-z0-9=_\-])/gm;

function extractCandidates(text: string): Array<{ value: string; start: number; end: number }> {
	const candidates: Array<{ value: string; start: number; end: number }> = [];
	for (const extractor of [ASSIGNED_CANDIDATE, QUOTED_CANDIDATE, STRUCTURED_CANDIDATE]) {
		extractor.lastIndex = 0;
		let match: RegExpExecArray | null;
		while ((match = extractor.exec(text)) !== null) {
			const value = match[1];
			if (!value) continue;
			const offset = match[0].indexOf(value);
			if (offset < 0) continue;
			const start = match.index + offset;
			const end = start + value.length;
			if (!candidates.some((candidate) => candidate.start === start && candidate.end === end)) {
				candidates.push({ value, start, end });
			}
		}
	}
	return candidates.sort((a, b) => a.start - b.start || b.end - b.start - (a.end - a.start));
}

export function findHighEntropyStrings(text: string): EntropyFinding[] {
	const findings: EntropyFinding[] = [];

	for (const { value: candidate, start, end } of extractCandidates(text)) {
		if (isSafe(candidate)) continue;

		const charSet = detectCharSet(candidate);
		if (!charSet) continue;

		const minLen = MIN_CANDIDATE_LENGTH[charSet];
		if (candidate.length < minLen) continue;

		if (isContextuallySafe(candidate, text, start, end)) continue;

		const entropy = shannonEntropy(candidate);
		const threshold = ENTROPY_THRESHOLDS[charSet];

		if (entropy >= threshold) {
			findings.push({
				value: candidate,
				start,
				end,
				entropy: parseFloat(entropy.toFixed(2)),
				charSet,
			});
		}
	}

	return findings;
}
