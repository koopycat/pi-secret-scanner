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

const PATH_PATTERNS = [
	/^\/(?:[A-Za-z0-9._\-]+\/)*[A-Za-z0-9._\-]*$/,
	/^~\//,
	/^\.\.?\//,
	/^[A-Za-z0-9._\-]+(?:\/[A-Za-z0-9._\-]+)+$/,
];

// PATH-style lists and `from=to` path mappings, optionally behind a CLI flag,
// e.g. the Nix-generated `-fmacro-prefix-map=/nix/store/<hash>-a=/nix/store/<hash>-b`.
function isPathList(candidate: string): boolean {
	const parts = candidate.split(/[=:]/).filter((part) => part.length > 0);
	const flag = parts[0] ?? "";
	if (parts.length > 1 && /^--?[A-Za-z][A-Za-z0-9-]*$/.test(flag) && !isCredentialKey(flag.replace(/^-+/, ""))) {
		parts.shift();
	}
	return parts.length > 1 && parts.every((part) => PATH_PATTERNS.some((p) => p.test(part)));
}

function isSafe(candidate: string): boolean {
	return SAFE_PATTERNS.some((p) => p.test(candidate)) || isPathList(candidate);
}

// ── Contextual false-positive suppression ──────────────────────────────────────
// Canonical public identifiers (Git OIDs, Docker/OCI digests and IDs, pinned
// GitHub Action refs, docker-desktop build URLs) are suppressed conservatively.
// A lowercase 40-hex SHA-1 is recognized by shape because Git OIDs commonly
// appear bare in command output; other identifiers require producing context.
// Credential-bearing keys always take precedence over these suppressions.

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
	"signature",
];

const GENERIC_HEX_CONTEXT_KEYS = new Set(["id", "hash", "digest", "checksum", "fingerprint", "identifier"]);

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
const NIX_STORE_NAME = /^[0-9a-df-np-sv-z]{32}(?:-[A-Za-z0-9+._?=-]+)?$/;
const SRI_DIGEST = /^sha(1|256|384|512)-([A-Za-z0-9+/]+={0,2})$/;
const SRI_DIGEST_BYTES: Record<string, number> = { "1": 20, "256": 32, "384": 48, "512": 64 };

function isSriDigest(candidate: string): boolean {
	const match = SRI_DIGEST.exec(candidate);
	if (!match?.[1] || !match[2]) return false;
	const bytes = SRI_DIGEST_BYTES[match[1]] ?? 0;
	if (match[2].length !== Math.ceil(bytes / 3) * 4) return false;
	return decodeCanonicalBase64(match[2])?.bytes.length === bytes;
}

const BASIC_AUTH_BEFORE = /\b(?:proxy-)?authorization\s*:\s*basic[ \t]+["']?$/i;
const ASSIGNMENT_KEYS_BEFORE = /(?:^|[\s,;{[("'?&])([A-Za-z0-9_\-.]{1,40})["']?\s*[=:]\s*["']?/g;

// Per-character predicates for the manual backward key scan in `keyBefore`.
// A regex equivalent to the old `KEY_BEFORE` pattern is orders of magnitude
// slower here: without a `^` anchor it retries every start position of the
// 256-char context window per candidate, which dominated scans of files with
// many value-like strings (measured ~14s on a 164KB JSON document).

function isWsChar(code: number): boolean {
	if (code === 32 || code === 9 || code === 10 || code === 13 || code === 11 || code === 12) return true;
	// Match the JS `\s` class for non-ASCII whitespace (NBSP, ideographic, …).
	return code > 127 && /\s/.test(String.fromCharCode(code));
}

function isQuoteChar(code: number): boolean {
	return code === 34 || code === 39; // " or '
}

function isKeyChar(code: number): boolean {
	return (
		(code >= 97 && code <= 122) || // a-z
		(code >= 65 && code <= 90) || // A-Z
		(code >= 48 && code <= 57) || // 0-9
		code === 95 ||
		code === 45 ||
		code === 46 // _ - .
	);
}

/**
 * Nearest assignment key immediately before the candidate, including quoted
 * JSON/YAML keys such as `"token": "`. Equivalent to matching
 * /["']?([A-Za-z0-9_\-.]{1,40})["']?\s*[=:]\s*["']?$/ against `before`, but
 * parsed backwards from the end in O(key length) instead of searching the
 * whole window.
 */
function keyBefore(before: string): string | null {
	let i = before.length;
	// Trailing quote that opens the value: `token="…`.
	if (i > 0 && isQuoteChar(before.charCodeAt(i - 1))) i--;
	// Whitespace between the separator and the value quote.
	while (i > 0 && isWsChar(before.charCodeAt(i - 1))) i--;
	// The separator itself.
	const sep = i > 0 ? before.charCodeAt(i - 1) : 0;
	if (sep !== 61 /* = */ && sep !== 58 /* : */) return null;
	i--;
	// Whitespace between the key and the separator: `token = …`.
	while (i > 0 && isWsChar(before.charCodeAt(i - 1))) i--;
	// Closing quote of a JSON/YAML key: `"token": …`.
	if (i > 0 && isQuoteChar(before.charCodeAt(i - 1))) i--;
	// The key itself: 1-40 characters of [A-Za-z0-9_\-.].
	const end = i;
	while (i > 0 && end - i < 40 && isKeyChar(before.charCodeAt(i - 1))) i--;
	return i === end ? null : before.slice(i, end);
}

function normalizeContextKey(key: string): string {
	return key
		.replace(/([a-z0-9])([A-Z])/g, "$1_$2")
		.replace(/([A-Z]+)([A-Z][a-z])/g, "$1_$2")
		.toLowerCase()
		.replace(/[^a-z0-9]+/g, "_");
}

function isCredentialKey(key: string): boolean {
	const normalized = normalizeContextKey(key);
	if (CREDENTIAL_KEYS.has(normalized)) return true;
	if (CREDENTIAL_KEY_SUFFIXES.some((suffix) => normalized === suffix || normalized.endsWith(`_${suffix}`)))
		return true;
	return normalized.split("_").some((part) => CREDENTIAL_KEY_PARTS.has(part));
}

// Characters that end a value, so assignments before them belong to other
// values (`"dist/token-util.js":{…},"integrity":"<v>"` or `a=1&token=x&b=<v>`).
const VALUE_BOUNDARY = /[\n,;{}[\]()&]/g;

/** The assignment chain that leads directly to the candidate (`token=sha256:`). */
function assignmentChain(before: string): string {
	let cut = -1;
	VALUE_BOUNDARY.lastIndex = 0;
	while (VALUE_BOUNDARY.exec(before) !== null) cut = VALUE_BOUNDARY.lastIndex - 1;
	return before.slice(cut + 1);
}

function hasCredentialAssignment(before: string): boolean {
	const chain = assignmentChain(before);
	ASSIGNMENT_KEYS_BEFORE.lastIndex = 0;
	let match: RegExpExecArray | null;
	while ((match = ASSIGNMENT_KEYS_BEFORE.exec(chain)) !== null) {
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

const URL_SCHEME_PREFIX = /^[A-Za-z][A-Za-z0-9+.-]*:\/\//;

// Whether the token containing the candidate starts with a URL scheme
// (https://, ftp://, docker-desktop://, …), which distinguishes URL paths
// from filesystem paths. Token start is the last delimiter before the
// candidate; the bounded window may truncate very long tokens, in which case
// detection fails closed and the candidate keeps its default classification.
function startsWithUrlScheme(before: string): boolean {
	const delimiters = /[\s"'([<=,;]/g;
	let cut = -1;
	let match: RegExpExecArray | null;
	while ((match = delimiters.exec(before)) !== null) cut = match.index;
	return URL_SCHEME_PREFIX.test(cut === -1 ? before : before.slice(cut + 1));
}

function classifyOpaqueEntropy(text: string, start: number, bare = false): Pick<EntropyFinding, "action" | "context"> {
	const before = text.slice(Math.max(0, start - 256), start);
	// `keyBefore` may cross a newline (`secret:\n  <value>`), but other
	// assignments only count in the candidate's own assignment chain: a
	// `PASSWORD=` line must not turn every later value into a credential.
	const lineBefore = assignmentChain(before);
	const key = keyBefore(before);
	const nestedCredential = /(?:^|[\s,;{[(]"?)([A-Za-z0-9_.-]{1,40})["']?\s*[=:]\s*sha(?:1|256):\s*$/i.exec(
		lineBefore,
	);
	const credentialContext =
		(key !== null && isCredentialKey(key)) ||
		hasCredentialAssignment(lineBefore) ||
		(nestedCredential?.[1] !== undefined && isCredentialKey(nestedCredential[1]));
	const genericHexContext = key !== null && GENERIC_HEX_CONTEXT_KEYS.has(normalizeContextKey(key));
	// Identifiers embedded in URL path segments are reported, not replaced:
	// replacing a URL segment corrupts the link, and public URL identifiers
	// (commit URLs, artifact digests) vastly outnumber URL-embedded secrets.
	const urlPathContext = /[/\\]$/.test(before) && startsWithUrlScheme(before);
	// Standalone hex without any key/quote/separator context is report-only:
	// free prose is full of public hashes, and generated keys pasted as prose
	// still deserve visibility without corrupting the surrounding text.
	return credentialContext
		? { action: "redact", context: "credential-assignment" }
		: genericHexContext
			? { action: "report", context: "ambiguous" }
			: urlPathContext || bare
				? { action: "report", context: "ambiguous" }
				: { action: "redact", context: "ambiguous" };
}

function isContextuallySafe(candidate: string, text: string, start: number, end: number): boolean {
	// The safe-shape checks only ever inspect a bounded neighborhood of the
	// candidate: an assignment key, a digest prefix, or a `uses:` pin that ends
	// at the candidate. Unbounded line scans are quadratic on single-line files
	// such as minified bundles (measured ~24s for a 400KB bundle before this
	// bounding). Two compromises, both far outside realistic secret contexts:
	// credential assignments more than CONTEXT_BEFORE chars earlier no longer
	// force detection, and `uses:`/build-URL suppression is skipped when the
	// line extends beyond the window (a `$`-anchored match on a truncated line
	// could wrongly exempt a value).
	const winStart = Math.max(0, start - CONTEXT_BEFORE);
	const beforeWindow = text.slice(winStart, start);
	const nlBack = beforeWindow.lastIndexOf("\n");
	const lineStart = nlBack !== -1 ? winStart + nlBack + 1 : start <= CONTEXT_BEFORE ? 0 : -1;
	const before = nlBack !== -1 ? beforeWindow.slice(nlBack + 1) : beforeWindow;

	const afterWindow = text.slice(end, end + CONTEXT_AFTER + 1);
	const nlFwd = afterWindow.indexOf("\n");
	let lineEnd: number;
	let lineComplete: boolean;
	if (nlFwd !== -1) {
		lineEnd = end + nlFwd;
		lineComplete = true;
	} else if (end + CONTEXT_AFTER + 1 >= text.length) {
		lineEnd = text.length;
		lineComplete = true;
	} else {
		lineEnd = end + CONTEXT_AFTER;
		lineComplete = false;
	}

	const lo = lineStart === -1 ? winStart : lineStart;
	const line = text.slice(lo, lineEnd);
	const relStart = start - lo;
	const relEnd = end - lo;
	const key = keyBefore(before);

	// Check every assignment before the candidate so nested syntax such as
	// `token=sha256:<value>` cannot disguise a credential as a public digest.
	if (hasCredentialAssignment(before)) return false;

	// Git's canonical SHA-1 object IDs commonly appear bare in command output,
	// where there is no reliable contextual marker. Recognize the exact lowercase
	// 40-hex shape globally. Keep this below the credential guard so values under
	// `token=`, `secret=`, and similar keys remain detected.
	if (LOWER_HEX_40.test(candidate)) return true;

	// Package-manager Subresource Integrity hashes are public verification data.
	// Keep this below the credential guard so `token=sha512-...` remains detected.
	// The second condition also suppresses structured sub-candidates extracted
	// after `/` inside the base64 digest.
	// Nix uses the same SRI form for `hash`/`narHash`; an exact digest length
	// makes the shape specific enough to accept under any non-credential key.
	if (isSriDigest(candidate)) return true;
	if (/^sha(?:256|384|512)-[A-Za-z0-9+/]+={0,2}$/.test(candidate) && key === "integrity") return true;
	if (/\bintegrity\s*[=:]\s*["']?sha(?:256|384|512)-[A-Za-z0-9+/=]*$/i.test(before)) return true;
	if (/(?:^|[\s"'=:])sha(?:256|384|512)-[A-Za-z0-9+/]*$/.test(before) && /^[A-Za-z0-9+/]+={0,2}$/.test(candidate)) {
		return true;
	}

	// A single host label right after a URL scheme (`https://docs-site.example`):
	// the extractor reads `https:` as a key. Hostnames are not secrets, and
	// credentials in the authority are covered by the named URL rule.
	if (/^\/\/[A-Za-z0-9-]+$/.test(candidate) && /[A-Za-z][A-Za-z0-9+.-]*:$/.test(before) && text[end] === ".") {
		return true;
	}

	// Nix store entries: `<32-char nix-base32 hash>-<name>` directly after a
	// store directory. The Nix alphabet omits e, o, t, and u.
	if (/\/$/.test(before) && NIX_STORE_NAME.test(candidate)) return true;

	// Canonical lowercase Git object IDs under explicit public metadata keys.
	if (key && isGitOidForKey(candidate, key)) return true;
	if (LOWER_HEX_40_OR_64.test(candidate) && /\bcommit\s+$/.test(before)) return true;

	// Docker/OCI digest syntax: `sha256:<64 lowercase hex>`.
	if (LOWER_HEX_64.test(candidate) && /(?:^|[@:\s"'=])sha256:\s*$/.test(before)) return true;

	// Hex-named filesystem segments are content addresses (git object files,
	// Docker overlay layers, content-addressed caches, temp dirs), not secrets.
	// Only pure lowercase hex qualifies, and only outside URL tokens — URL-path
	// identifiers fall through to a report-only classification instead, so a
	// link is never corrupted and a URL-embedded secret stays visible. This
	// sits below the credential guard: `token=/…/<hex>` still redacts.
	if (
		/^[0-9a-f]{20,}$/.test(candidate) &&
		/[/\\]$/.test(before) &&
		!startsWithUrlScheme(before) &&
		(end >= text.length || /^[\s/\\."'),;:\]}]/.test(text[end] ?? ""))
	) {
		return true;
	}

	// Bare Docker image/container IDs (underscore or hyphen variants).
	if (LOWER_HEX_64.test(candidate) && key && /^(?:docker[-_]?)?(?:image|container)[-_]id$/.test(key.toLowerCase())) {
		return true;
	}

	// Pinned GitHub Action refs: `uses: owner/repo@<oid>`, optionally quoted
	// and followed by a YAML comment. Only matched against a complete line; on
	// a truncated line the `$` anchor could exempt values the full line would
	// not.
	if (lineComplete) {
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
	}

	return false;
}

// ── Base64 classification ────────────────────────────────────────────────────

const MAX_BASE64_DECODE_LENGTH = 256 * 1024;
const MAX_DECODED_INSPECTION_LENGTH = 16 * 1024;
// Bounded context windows for the safe-shape checks in `isContextuallySafe`.
const CONTEXT_BEFORE = 1024;
const CONTEXT_AFTER = 1024;
const STANDARD_BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;
const URLSAFE_BASE64 = /^[A-Za-z0-9_-]+={0,2}$/;

const UTF8_STRICT = new TextDecoder("utf-8", { fatal: true });

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
	// Reused across calls: TextDecoder construction is expensive and decode()
	// is stateless when not streaming.
	let decoded: string;
	try {
		decoded = UTF8_STRICT.decode(bytes);
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
	// Note: this deliberately always uses the built-in SECRET_PATTERNS set. It
	// runs inside entropy classification, which has no access to ScanOptions,
	// so disabled rules and whitelists do not suppress encoded-credential
	// redaction. That asymmetry is intentional: an encoded secret should still
	// be caught even when the plaintext rule is disabled.
	//
	// Keep provider-pattern inspection bounded even when an attacker supplies a
	// large, highly compressible printable payload. Inspect both ends because
	// encoded configuration commonly has credentials near either boundary.
	// Known limitation: for decoded text longer than 2x the window size a
	// credential straddling the boundary between the two windows is missed.
	const windows =
		text.length <= MAX_DECODED_INSPECTION_LENGTH
			? [text]
			: [text.slice(0, MAX_DECODED_INSPECTION_LENGTH / 2), text.slice(-MAX_DECODED_INSPECTION_LENGTH / 2)];
	for (const inspected of windows) {
		for (const pattern of SECRET_PATTERNS) {
			// Use a private regex instance: this classification can run while the
			// outer scanner is using the same named pattern objects, and a shared
			// lastIndex would make the result dependent on traversal order.
			const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
			let match: RegExpExecArray | null;
			while ((match = regex.exec(inspected)) !== null) {
				const value = pattern.secretGroup === undefined ? match[0] : match[pattern.secretGroup];
				if (value && !pattern.rejectValue?.(value)) return true;
				if (match[0].length === 0) regex.lastIndex++;
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
// Standalone hex runs of MD5 length or more with no key, quote, or separator
// around them — generated keys pasted as free prose. Extracted so they are at
// least reported; `bare` keeps them report-only, since free prose is full of
// public hashes that must not be replaced.
const BARE_HEX_CANDIDATE = /(?<![0-9a-fA-F])([0-9a-f]{32,})(?![0-9a-fA-F])/g;

function extractCandidates(text: string): Array<{ value: string; start: number; end: number; bare: boolean }> {
	const candidates: Array<{ value: string; start: number; end: number; bare: boolean }> = [];
	const seen = new Set<string>();
	for (const { regex, bare } of [
		{ regex: ASSIGNED_CANDIDATE, bare: false },
		{ regex: BASIC_AUTH_CANDIDATE, bare: false },
		{ regex: QUOTED_CANDIDATE, bare: false },
		{ regex: STRUCTURED_CANDIDATE, bare: false },
		{ regex: BARE_HEX_CANDIDATE, bare: true },
	]) {
		regex.lastIndex = 0;
		let match: RegExpExecArray | null;
		while ((match = regex.exec(text)) !== null) {
			const value = match[1];
			if (!value) continue;
			const offset = match[0].indexOf(value);
			if (offset < 0) continue;
			const start = match.index + offset;
			const end = start + value.length;
			// Span-keyed dedup instead of a linear `some()` scan: candidate counts
			// reach the thousands on large documents and the scan was quadratic.
			const key = `${start}:${end}`;
			if (!seen.has(key)) {
				seen.add(key);
				candidates.push({ value, start, end, bare });
			}
		}
	}
	return candidates.sort((a, b) => a.start - b.start || b.end - b.start - (a.end - a.start));
}

export function findHighEntropyStrings(text: string): EntropyFinding[] {
	const findings: EntropyFinding[] = [];

	for (const { value: candidate, start, end, bare } of extractCandidates(text)) {
		const charSet = detectCharSet(candidate);
		if (!charSet) continue;

		// Cheap rejections first: length and entropy gates run before the
		// expensive Base64 classification (decode + pattern scan) so that
		// candidates that could never become findings do not pay for it.
		const minLen = MIN_CANDIDATE_LENGTH[charSet];
		if (candidate.length < minLen) continue;

		const entropy = shannonEntropy(candidate);
		const threshold = ENTROPY_THRESHOLDS[charSet];
		if (entropy < threshold) continue;

		const classification =
			charSet === "base64" ? classifyBase64(candidate, text, start) : classifyOpaqueEntropy(text, start, bare);

		// Safe shapes suppress ambiguous candidates. They are overridden only by
		// an immediate credential/authentication context, not merely because the
		// decoded bytes happen to resemble a credential.
		if (isSafe(candidate) && classification.context === "ambiguous") continue;

		if (isContextuallySafe(candidate, text, start, end)) continue;

		findings.push({
			value: candidate,
			start,
			end,
			entropy: parseFloat(entropy.toFixed(2)),
			charSet,
			...classification,
		});
	}

	return findings;
}
