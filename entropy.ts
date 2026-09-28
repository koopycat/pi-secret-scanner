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

import { SECRET_PATTERNS } from "./patterns.ts";

export type EntropyAction = "redact" | "report";
export type EntropyContext = "credential-assignment" | "basic-auth" | "encoded-credential" | "ambiguous";
export type Base64Encoding = "base64" | "base64url";
export type DecodedKind = "credential" | "text" | "binary" | "non-printable" | "invalid";

export interface EntropyFinding {
	value: string;
	start: number;
	end: number;
	entropy: number;
	charSet: "hex" | "base64" | "mixed";
	/** Whether this candidate is safe to replace automatically or only report. */
	action: EntropyAction;
	/** Why the candidate received its action. */
	context: EntropyContext;
	/** Strictly validated encoding variant, when this is canonical Base64. */
	encoding?: Base64Encoding;
	/** Classification of strictly decoded Base64 bytes. */
	decodedKind?: DecodedKind;
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
	// Relative filesystem and repository paths (owner/repo, project/src/module).
	// A slash-delimited value without base64-only `+`/`=` characters is public
	// locator data, not an opaque secret. This also covers GitHub remotes,
	// plugin/rule IDs, GitHub Action slugs, and stack-trace module paths.
	/^[A-Za-z0-9._\-]+(?:\/[A-Za-z0-9._\-]+)+$/,
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
	"auth",
	"auth_key",
	"auth_token",
	"access_key",
	"access_token",
	"encryption_key",
	"master_key",
	"private_key",
	"signing_key",
]);
const CREDENTIAL_KEY_PARTS = new Set(["password", "passwd", "pwd", "secret", "token"]);
const CREDENTIAL_KEY_SUFFIXES = [
	"api_key",
	"auth_key",
	"auth_token",
	"access_key",
	"access_token",
	"encryption_key",
	"master_key",
	"private_key",
	"signing_key",
];

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

// Nearest assignment key immediately before the candidate, including quoted
// JSON/YAML keys such as `"token": "`.
const KEY_BEFORE = /["']?([A-Za-z0-9_\-.]{1,40})["']?\s*[=:]\s*["']?$/;
const BASIC_AUTH_BEFORE = /\b(?:proxy-)?authorization\s*:\s*basic[ \t]+["']?$/i;
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

	// Package-manager Subresource Integrity hashes are public verification data.
	// Keep this below the credential guard so `token=sha512-...` remains detected.
	// The second condition also suppresses structured sub-candidates extracted
	// after `/` inside the base64 digest.
	if (/^sha(?:256|384|512)-[A-Za-z0-9+/]+={0,2}$/.test(candidate) && key === "integrity") return true;
	if (/\bintegrity\s*[=:]\s*["']?sha(?:256|384|512)-[A-Za-z0-9+/=]*$/i.test(before)) return true;

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

// ── Base64 classification ────────────────────────────────────────────────────

const MAX_BASE64_DECODE_LENGTH = 256 * 1024;
const MAX_DECODED_INSPECTION_LENGTH = 16 * 1024;
const STANDARD_BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;
const URLSAFE_BASE64 = /^[A-Za-z0-9_-]+={0,2}$/;

interface DecodedBase64 {
	bytes: Buffer;
	encoding: Base64Encoding;
}

function withoutPadding(value: string): string {
	return value.replace(/=+$/, "");
}

/**
 * Buffer.from is deliberately permissive, so verify its result by encoding it
 * again. This rejects malformed padding, mixed alphabets, and ignored junk.
 */
function decodeCanonicalBase64(value: string): DecodedBase64 | null {
	if (value.length > MAX_BASE64_DECODE_LENGTH) return null;

	if (STANDARD_BASE64.test(value)) {
		const bytes = Buffer.from(value, "base64");
		const canonical = bytes.toString("base64");
		if (value === canonical || value === withoutPadding(canonical)) return { bytes, encoding: "base64" };
	}

	if (URLSAFE_BASE64.test(value)) {
		const bytes = Buffer.from(value, "base64url");
		const canonical = bytes.toString("base64url");
		if (withoutPadding(value) === canonical && (!value.includes("=") || value.length % 4 === 0)) {
			return { bytes, encoding: "base64url" };
		}
	}

	return null;
}

const BINARY_SIGNATURES: ReadonlyArray<readonly number[]> = [
	[0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], // PNG
	[0xff, 0xd8, 0xff], // JPEG
	[0x47, 0x49, 0x46, 0x38, 0x37, 0x61], // GIF87a
	[0x47, 0x49, 0x46, 0x38, 0x39, 0x61], // GIF89a
	[0x25, 0x50, 0x44, 0x46, 0x2d], // PDF
	[0x50, 0x4b, 0x03, 0x04], // ZIP
	[0x50, 0x4b, 0x05, 0x06],
	[0x50, 0x4b, 0x07, 0x08],
	[0x1f, 0x8b], // gzip
	[0x7f, 0x45, 0x4c, 0x46], // ELF
	[0x00, 0x61, 0x73, 0x6d], // WebAssembly
];

function hasRecognizedBinarySignature(bytes: Buffer): boolean {
	return BINARY_SIGNATURES.some(
		(signature) => bytes.length >= signature.length && signature.every((byte, index) => bytes[index] === byte),
	);
}

function decodeMostlyPrintableText(bytes: Buffer): string | null {
	let decoded: string;
	try {
		decoded = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
	} catch {
		return null;
	}
	if (decoded.length === 0) return "";

	let printable = 0;
	let total = 0;
	for (const char of decoded) {
		total++;
		const codePoint = char.codePointAt(0) ?? 0;
		if (char === "\n" || char === "\r" || char === "\t" || (codePoint >= 0x20 && codePoint !== 0x7f)) {
			printable++;
		}
	}
	return printable / total >= 0.85 ? decoded : null;
}

function containsRecognizedCredential(text: string): boolean {
	// Keep provider-pattern inspection bounded even when an attacker supplies a
	// large, highly compressible printable payload. Inspect both ends because
	// encoded configuration commonly has credentials near either boundary.
	const windows =
		text.length <= MAX_DECODED_INSPECTION_LENGTH
			? [text]
			: [text.slice(0, MAX_DECODED_INSPECTION_LENGTH / 2), text.slice(-MAX_DECODED_INSPECTION_LENGTH / 2)];
	for (const inspected of windows) {
		for (const pattern of SECRET_PATTERNS) {
			pattern.regex.lastIndex = 0;
			let match: RegExpExecArray | null;
			while ((match = pattern.regex.exec(inspected)) !== null) {
				const value = pattern.secretGroup === undefined ? match[0] : match[pattern.secretGroup];
				if (value && !pattern.rejectValue?.(value)) return true;
				if (match[0].length === 0) pattern.regex.lastIndex++;
			}
		}
	}
	return false;
}

function classifyBase64(
	candidate: string,
	text: string,
	start: number,
): Pick<EntropyFinding, "action" | "context" | "encoding" | "decodedKind"> {
	// Keep a bounded amount of preceding syntax so multiline assignments such
	// as `client_secret:\n  <value>` retain their credential context without
	// letting an unrelated key arbitrarily far away affect classification.
	const before = text.slice(Math.max(0, start - 256), start);
	const key = keyBefore(before);
	const credentialContext = key !== null && isCredentialKey(key);
	const basicAuthContext = BASIC_AUTH_BEFORE.test(before);
	const decoded = decodeCanonicalBase64(candidate);

	let decodedKind: DecodedKind = "invalid";
	let containsCredential = false;
	if (decoded) {
		if (hasRecognizedBinarySignature(decoded.bytes)) {
			decodedKind = "binary";
		} else {
			const decodedText = decodeMostlyPrintableText(decoded.bytes);
			if (decodedText === null) {
				decodedKind = "non-printable";
			} else if (containsRecognizedCredential(decodedText)) {
				decodedKind = "credential";
				containsCredential = true;
			} else {
				decodedKind = "text";
			}
		}
	}

	const context: EntropyContext = basicAuthContext
		? "basic-auth"
		: credentialContext
			? "credential-assignment"
			: containsCredential
				? "encoded-credential"
				: "ambiguous";

	// Explicit credential and authentication contexts always win. Base64 is
	// merely an identification signal only when its surrounding context is
	// ambiguous; a benign-looking decode must not override `token=`, `api_key=`,
	// or Authorization: Basic.
	const action: EntropyAction =
		credentialContext || basicAuthContext || decodedKind === "credential" ? "redact" : "report";
	return { action, context, encoding: decoded?.encoding, decodedKind };
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
const BASIC_AUTH_CANDIDATE = /\b(?:proxy-)?authorization[ \t]*:[ \t]*basic[ \t]+["']?([A-Za-z0-9+/=_-]{16,})/gim;
const QUOTED_CANDIDATE = /["']([A-Za-z0-9+/=_\-]{20,200})["']/gm;
const STRUCTURED_CANDIDATE = /(?<=[@:/])([A-Za-z0-9=_\-]{20,})(?![A-Za-z0-9=_\-])/gm;

function extractCandidates(text: string): Array<{ value: string; start: number; end: number }> {
	const candidates: Array<{ value: string; start: number; end: number }> = [];
	for (const extractor of [ASSIGNED_CANDIDATE, BASIC_AUTH_CANDIDATE, QUOTED_CANDIDATE, STRUCTURED_CANDIDATE]) {
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
		const charSet = detectCharSet(candidate);
		if (!charSet) continue;

		const classification =
			charSet === "base64"
				? classifyBase64(candidate, text, start)
				: ({ action: "redact", context: "ambiguous" } as const);

		// Safe shapes suppress ambiguous candidates. They are overridden only by
		// an immediate credential/authentication context, not merely because the
		// decoded bytes happen to resemble a credential.
		if (
			isSafe(candidate) &&
			classification.context !== "credential-assignment" &&
			classification.context !== "basic-auth" &&
			classification.context !== "encoded-credential"
		)
			continue;

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
				...classification,
			});
		}
	}

	return findings;
}
