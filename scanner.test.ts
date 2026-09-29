/**
 * Tests for the secret-scanner extension (custom pattern-based detection).
 *
 * Secret-like strings are assembled via concatenation so the test file
 * itself does not trigger redaction when written to disk.
 *
 * Run:  npx vitest run --config ../vitest.config.ts secret-scanner/scanner.test.ts
 */

import { describe, it, expect } from "vitest";

import { shannonEntropy, findHighEntropyStrings } from "./entropy.ts";
import { SECRET_PATTERNS } from "./patterns.ts";
import { scanText, scanObject, formatFindings, countByType } from "./scanner.ts";

// ── String builders (concatenation prevents source-level regex matches) ──────

function awsKey(): string {
	return "AKIA" + "IOSFODNN7EXAMPLE";
}

function openAiKey(): string {
	return "sk-" + "AbCdEfGhIjKlMnOpQrStUvWxYz1234567890AbCdEfGhIjKl";
}

function anthropicKey(): string {
	return (
		"sk-ant-api03-" + "AbCdEfGhIjKlMnOpQrStUvWxYz1234567890AbCdEfGhIjKlMnOpQrStUvWxYz1234567890AbCdEfGhIjKlMnOpQrSt"
	);
}

function githubPat(): string {
	return "ghp_" + "abcdefghijklmnopqrstuvwxyz1234567890";
}

function stripeLiveKey(): string {
	return "sk_live_" + "51ABCDEFGHIJKLMNOPQRSTUVWXYZab";
}

function jwtToken(): string {
	return "eyJhbGciOiJIUzI1NiJ9" + ".eyJzdWIiOiIxMjM0NTY3ODkwIn0" + ".dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
}

function twilioSid(): string {
	return "AC" + "abcdef1234567890abcdef1234567890";
}

function urlWithCreds(): string {
	return "https://" + "admin:secretpassword123" + "@db.example.com:5432/mydb";
}

// High-entropy base64 string (all unique chars → log2(30) ≈ 4.91 > 4.5 threshold)
function highEntropyBase64(): string {
	return "aB3dE5fG7hI9jK1lM2nO4pQ6rS8tU0vW";
}

function encodeBase64(value: string): string {
	return Buffer.from(value).toString("base64");
}

function sourceMapBase64(): string {
	return encodeBase64(
		JSON.stringify({ version: 3, sources: ["src/index.ts"], names: [], mappings: "AAAA,SAASA,IAAI,CAAC" }),
	);
}

function pngBase64(): string {
	return Buffer.from([
		0x89,
		0x50,
		0x4e,
		0x47,
		0x0d,
		0x0a,
		0x1a,
		0x0a,
		...Array.from({ length: 48 }, (_, index) => (index * 37) % 256),
	]).toString("base64");
}

// Synthetic Git SHA-1 (40 lowercase hex) — not a real OID, assembled to keep
// the source free of anything that looks like a live identifier.
function gitSha40(): string {
	return "3c2ca677" + "676f6876cad18aedbdcc5933a39f5cc1";
}

// Synthetic SHA-256 (64 lowercase hex) used for digests and action pins.
function gitSha64(): string {
	return "6457d53fb065d6f250e1504b9bc42d5b6c65941d57532c072d929dd0628977d0";
}

// ═══════════════════════════════════════════════════════════════════════
// shannonEntropy
// ═══════════════════════════════════════════════════════════════════════

describe("shannonEntropy", () => {
	it("returns 0 for identical characters", () => {
		expect(shannonEntropy("aaaa")).toBe(0);
	});

	it("returns 0 for empty string", () => {
		expect(shannonEntropy("")).toBe(0);
	});

	it("log2(n) for n unique chars", () => {
		expect(shannonEntropy("abcd")).toBeCloseTo(2.0, 5);
		expect(shannonEntropy("abcdefgh")).toBeCloseTo(3.0, 5);
	});

	it("higher entropy for more random strings", () => {
		const ordered = shannonEntropy("aaaaabbbbbcccccdddddeeee");
		const random = shannonEntropy("a1b2c3d4e5f6g7h8i9j0k");
		expect(random).toBeGreaterThan(ordered);
	});
});

// ═══════════════════════════════════════════════════════════════════════
// findHighEntropyStrings
// ═══════════════════════════════════════════════════════════════════════

describe("findHighEntropyStrings", () => {
	it("detects high-entropy base64 after equals sign with exact offsets", () => {
		const value = highEntropyBase64();
		const text = `export KEY=${value}`;
		const r = findHighEntropyStrings(text);
		expect(r.length).toBeGreaterThanOrEqual(1);
		expect(text.slice(r[0]!.start, r[0]!.end)).toBe(value);
	});

	it("excludes UUIDs", () => {
		expect(findHighEntropyStrings("id=550e8400-e29b-41d4-a716-446655440000")).toHaveLength(0);
	});

	it("excludes short hex colors", () => {
		expect(findHighEntropyStrings('color: "ff5733"')).toHaveLength(0);
	});

	it("excludes UNIX timestamps", () => {
		expect(findHighEntropyStrings("ts=1718208000")).toHaveLength(0);
	});

	it("excludes placeholders", () => {
		expect(findHighEntropyStrings("KEY=test")).toHaveLength(0);
		expect(findHighEntropyStrings("TOKEN=placeholder")).toHaveLength(0);
	});

	it("excludes filesystem paths, repository slugs, and rule IDs", () => {
		expect(findHighEntropyStrings("path=/home/user/project/src/index.ts")).toHaveLength(0);
		const projectPath = "ghost-" + "complete/src/provider-factory.ts";
		expect(findHighEntropyStrings(`path: ${projectPath}`)).toHaveLength(0);
		expect(findHighEntropyStrings(`path=${projectPath}`)).toHaveLength(0);
		const repository = ["koopycat", "pi-secret-scanner"].join("/");
		const rule = ["import-x", "no-unresolved"].join("/");
		const action = ["renovatebot", "github-action"].join("/");
		expect(findHighEntropyStrings(`remote: "${repository}"`)).toHaveLength(0);
		expect(findHighEntropyStrings(`rule: "${rule}"`)).toHaveLength(0);
		expect(findHighEntropyStrings(`uses: ${action}@main`)).toHaveLength(0);
	});

	it("excludes package-manager integrity hashes but not credential-wrapped hashes", () => {
		const sri = `sha512-${highEntropyBase64()}==`;
		const slashedSri = `sha512-${highEntropyBase64()}/${highEntropyBase64()}==`;
		expect(findHighEntropyStrings(`integrity: ${sri}`)).toHaveLength(0);
		expect(findHighEntropyStrings(`integrity: ${slashedSri}`)).toHaveLength(0);
		expect(findHighEntropyStrings(`token=${sri}`)).toHaveLength(1);
	});

	it("ignores canonical Git OIDs in public metadata contexts", () => {
		const sha40 = gitSha40();
		const sha64 = gitSha64();
		// 40-hex commit SHAs under explicit public metadata keys…
		expect(findHighEntropyStrings(`commit_sha: ${sha40}`)).toHaveLength(0);
		expect(findHighEntropyStrings(`oid: "${sha40}"`)).toHaveLength(0);
		expect(findHighEntropyStrings(`rev: ${sha40}`)).toHaveLength(0);
		// …and 64-hex SHA-256 OIDs under the same keys.
		expect(findHighEntropyStrings(`git_oid = "${sha64}"`)).toHaveLength(0);
		// `git log` output: bare `commit <oid>` line.
		expect(findHighEntropyStrings(`commit ${sha40}\nAuthor: Dev <dev@example.com>`)).toHaveLength(0);
	});

	it("ignores pinned GitHub Action refs (owner/repo@OID)", () => {
		const sha40 = gitSha40();
		const sha64 = gitSha64();
		expect(findHighEntropyStrings(`uses: actions/checkout@${sha40}`)).toHaveLength(0);
		// Repo names are also part of the canonical pin and must not be flagged.
		expect(findHighEntropyStrings(`uses: renovatebot/github-action@${sha40}`)).toHaveLength(0);
		expect(findHighEntropyStrings(`uses: org/repo@${sha64}`)).toHaveLength(0);
	});

	it("ignores Docker sha256 digests and explicit image/container IDs", () => {
		const sha64 = gitSha64();
		expect(findHighEntropyStrings(`image: alpine@sha256:${sha64}`)).toHaveLength(0);
		expect(findHighEntropyStrings(`digest: sha256:${sha64}`)).toHaveLength(0);
		expect(findHighEntropyStrings(`Image ID: sha256:${sha64}`)).toHaveLength(0);
		expect(findHighEntropyStrings(`image_id: ${sha64}`)).toHaveLength(0);
		expect(findHighEntropyStrings(`container_id: ${sha64}`)).toHaveLength(0);
	});

	it("ignores the canonical Docker Desktop build link", () => {
		expect(
			findHighEntropyStrings(
				"View build details: docker-desktop://dashboard/build/desktop-linux/desktop-linux/6xavvfljy663xxe99qw7gtrnd",
			),
		).toHaveLength(0);
	});

	it("does not let extra Docker Desktop URL syntax hide an opaque value", () => {
		const buildId = "abcdefghijklmnopqrstuv0123456789";
		expect(
			findHighEntropyStrings(`url=docker-desktop://dashboard/build/default/default/${buildId}/extra`).map(
				(f) => f.value,
			),
		).toContain(buildId);
	});

	it("does not let JSON or query-string credential keys hide digest-shaped values", () => {
		const sha64 = gitSha64();
		for (const text of [
			`{"secret":"sha256:${sha64}"}`,
			`https://example.test/?token=sha256:${sha64}`,
			`https://example.test/?x=1&api_key=sha256:${sha64}`,
			`x-api-key=sha256:${sha64}`,
			`auth-key=sha256:${sha64}`,
			`private-key=sha256:${sha64}`,
			`APIKey=sha256:${sha64}`,
		]) {
			expect(
				findHighEntropyStrings(text).map((finding) => finding.value),
				`expected detection in: ${text}`,
			).toContain(sha64);
		}
	});

	it("detects assigned high-entropy values longer than 200 characters", () => {
		const value = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/".repeat(4);
		const findings = findHighEntropyStrings(`X_SECRET=${value}`);
		expect(findings.map((finding) => finding.value)).toContain(value);
	});

	it("still detects Git OIDs under ambiguous or credential-bearing keys", () => {
		const sha40 = gitSha40();
		const sha64 = gitSha64();
		const detections = [
			// Bare ambiguous keys.
			`UNKNOWN=${sha40}`,
			`id=${sha40}`,
			`checksum: ${sha64}`,
			// Wrong lengths do not qualify for suppression, even under canonical keys.
			`commit_sha=${sha40.slice(0, 39)}`,
			`commit_sha: "${sha64.slice(0, 63)}"`,
			`sha1=${sha64}`,
			`sha256=${sha40}`,
			// Digest prefix with a truncated value.
			`digest: sha256:${sha64.slice(0, 63)}`,
			// Uppercase is outside the lowercase-only policy.
			`commit_sha=${sha40.toUpperCase()}`,
			// Credential-bearing keys always win, including nested digest syntax.
			`token=${sha40}`,
			`secret=${sha64}`,
			`ACCESS_TOKEN=${sha64}`,
			`token=sha256:${sha64}`,
		];
		for (const text of detections) {
			const r = findHighEntropyStrings(text);
			expect(r, `expected detection in: ${text}`).toHaveLength(1);
			// The flagged span must be exactly the hash value, not surrounding syntax.
			expect(text.slice(r[0]!.start, r[0]!.end)).toMatch(/^[0-9a-f]{39,64}$/i);
			expect(r[0]!.charSet).toBe("hex");
		}
	});

	it("suppresses safe shapes on single-line documents within the bounded context window", () => {
		// The safe-shape checks inspect a bounded neighborhood of each candidate
		// (see CONTEXT_BEFORE/CONTEXT_AFTER) so that single-line documents such as
		// minified bundles stay linear. A digest a few hundred characters after
		// its key on one line must still be suppressed.
		const sha64 = gitSha64();
		const filler = Buffer.from("filler ".repeat(120)).toString("base64");
		expect(findHighEntropyStrings(`digest: ${filler} sha256:${sha64}`)).toHaveLength(0);
		expect(findHighEntropyStrings(`image: alpine@sha256:${sha64}`)).toHaveLength(0);
	});

	it("flags a digest whose credential guard lies outside the bounded context window", () => {
		// Documented compromise: a credential assignment more than ~1024
		// characters earlier on the same line no longer overrides safe-shape
		// suppression. Realistic secret contexts are adjacent to their values.
		const sha64 = gitSha64();
		const filler = Buffer.from("filler ".repeat(600)).toString("base64");
		expect(findHighEntropyStrings(`token=x ${filler} sha256:${sha64}`)).toHaveLength(0);
	});

	it("scans pathological large documents in bounded time", () => {
		// Regression guard for the quadratic scan cost. Three shapes that used to
		// blow up (before the bounded-context fix these took ~14s, ~25s and ~24s
		// respectively): a document with many decodable Base64 values, one huge
		// Base64 blob that spawns a candidate at every "/" inside it, and a
		// single-line minified bundle where every candidate previously triggered
		// an unbounded line scan. Bounds are generous to stay CI-stable while
		// still failing hard on an O(candidates x document length) regression.
		const cases: Array<[string, string, number]> = [
			[
				"many Base64 values",
				JSON.stringify(
					Object.fromEntries(
						Array.from({ length: 2000 }, (_, i) => [
							`key${i}`,
							Buffer.from(`value number ${i} with some more prose text to decode`).toString("base64"),
						]),
					),
				),
				2000,
			],
			[
				"one huge Base64 blob",
				`data ${Buffer.from(Array.from({ length: 200 * 1024 }, () => (Math.random() * 256) | 0)).toString("base64")}`,
				1500,
			],
			[
				"minified single-line JS",
				Array.from(
					{ length: 4000 },
					(_, i) => `var e${i}="${Buffer.from(`module ${i} payload string here`).toString("base64")}",`,
				).join(""),
				4000,
			],
		];
		for (const [label, text, expectedFindings] of cases) {
			const started = performance.now();
			const result = scanText(text, { useEntropy: true });
			const elapsed = performance.now() - started;
			expect(result.findings.length, label).toBeGreaterThanOrEqual(expectedFindings);
			expect(elapsed, `${label} must scan in bounded time`).toBeLessThan(2000);
		}
	});

	it("detects malformed action pins without flagging the public repository slug", () => {
		const sha40 = gitSha40();
		// Truncated action pin: the @OID no longer matches the canonical pin shape,
		// so the malformed hash is flagged; the public owner/repo slug stays safe.
		expect(
			findHighEntropyStrings(`uses: renovatebot/github-action@${sha40.slice(0, 39)}`).map((f) => f.value),
		).toEqual([sha40.slice(0, 39)]);
	});

	it("detects a digest prefix with a non-64-hex value (malformed digest)", () => {
		const sha40 = gitSha40();
		expect(findHighEntropyStrings(`digest: sha256:${sha40}`).map((f) => f.value)).toEqual([sha40]);
	});

	it("extracts quoted high-entropy strings", () => {
		const text = `SECRET = "${highEntropyBase64()}"`;
		const r = findHighEntropyStrings(text);
		expect(r.length).toBeGreaterThanOrEqual(1);
	});
});

// ═══════════════════════════════════════════════════════════════════════
// SECRET_PATTERNS
// ═══════════════════════════════════════════════════════════════════════

describe("SECRET_PATTERNS", () => {
	function findPat(name: string) {
		return SECRET_PATTERNS.find((p) => p.name === name)!;
	}

	function mustDetect(name: string, text: string) {
		const p = findPat(name);
		p.regex.lastIndex = 0;
		expect(p.regex.test(text), `"${name}" should detect "${text}"`).toBe(true);
	}

	function mustNotDetect(name: string, text: string) {
		const p = findPat(name);
		p.regex.lastIndex = 0;
		const match = p.regex.exec(text);
		// A match that `rejectValue` suppresses (language-aware FP guard) counts as
		// not detected.
		const rejected =
			match !== null &&
			p.rejectValue?.(p.secretGroup === undefined ? match[0] : (match[p.secretGroup] ?? "")) === true;
		expect(!match || rejected, `"${name}" should NOT detect "${text}"`).toBe(true);
	}

	it("detects OpenAI API key", () => {
		mustDetect("OpenAI API Key", openAiKey());
	});

	it("detects AWS Access Key ID", () => {
		mustDetect("AWS Access Key ID", awsKey());
	});

	it("matches the full AWS Access Key ID rather than only its prefix", () => {
		const pattern = findPat("AWS Access Key ID");
		pattern.regex.lastIndex = 0;
		expect(pattern.regex.exec(awsKey())?.[0]).toBe(awsKey());
	});

	it("detects GitHub PAT classic", () => {
		mustDetect("GitHub Personal Access Token (classic)", githubPat());
	});

	it("detects Stripe Live key", () => {
		mustDetect("Stripe Live Secret Key", stripeLiveKey());
	});

	it("detects JWT token", () => {
		mustDetect("JSON Web Token", jwtToken());
	});

	it("detects URL credentials", () => {
		mustDetect("URL with Embedded Credentials", urlWithCreds());
	});

	it("detects Anthropic key", () => {
		mustDetect("Anthropic API Key", anthropicKey());
	});

	it("does NOT false-positive on safe placeholders", () => {
		mustNotDetect("Generic Password Assignment", "password=test");
		mustNotDetect("Generic Password Assignment", 'pwd: "changeme"');
		mustNotDetect("Generic Password Assignment", "api_key=xxx");
		mustNotDetect("Generic Password Assignment", `password=\${ENV_VAR}`);
	});

	it("does NOT false-positive on code references", () => {
		// Regression: these are real lines from provider code. Redacting them
		// destroyed the code the agent was supposed to read and edit.
		mustNotDetect(
			"Generic Password Assignment",
			'const[REDACTED:GENERIC_PASSWORD_ASSIGNMENT] ?? process.env.MISTRAL_API_KEY ?? "";',
		);
		mustNotDetect("Generic Password Assignment", "apiKey: kiloToken,");
		mustNotDetect("Generic Password Assignment", "credential: kiloToken,");
		mustNotDetect(
			"Generic Password Assignment",
			'const credential = opts?.credential ?? process.env.PI_GHOST_API_KEY ?? "ollama";',
		);
	});

	it("still detects literal generic credential assignments", () => {
		mustDetect("Generic Password Assignment", "PASSWORD=correct-horse-battery-staple");
		mustDetect("Generic Password Assignment", "apiKey: literal-api-key-value");
	});
});

// ═══════════════════════════════════════════════════════════════════════
// scanText
// ═══════════════════════════════════════════════════════════════════════

describe("scanText", () => {
	it("detects and redacts a GitHub PAT", () => {
		const key = githubPat();
		const text = `export GH_TOKEN=${key}`;
		const result = scanText(text);
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0]!.type).toBe("GitHub Personal Access Token (classic)");
		expect(result.redacted).not.toContain(key);
		expect(result.redacted).toContain("[REDACTED:");
	});

	it("does not corrupt text when provider-specific and generic matches overlap", () => {
		const result = scanText(`token=${githubPat()}`, { useEntropy: false });
		expect(result.redacted).toBe("token=[REDACTED:GITHUB_PERSONAL_ACCESS_TOKEN_(CLASSIC)]");
		expect(result.redactions).toHaveLength(1);
		expect(result.redactions[0]?.type).toBe("GitHub Personal Access Token (classic)");
	});

	it("redacts only the value of a generic assignment, keeping surrounding code", () => {
		const value = "live-" + "secret-" + "value-9f8e7d";
		const result = scanText(`const apiKey = "${value}";`, { useEntropy: false });
		expect(result.findings[0]?.type).toBe("Generic Password Assignment");
		expect(result.redacted).toBe(`const apiKey = "[REDACTED:GENERIC_PASSWORD_ASSIGNMENT]";`);
		expect(result.redacted).not.toContain(value);
	});

	it("reports an ambiguous Base64 candidate without redacting it", () => {
		const value = highEntropyBase64();
		const text = `UNKNOWN=${value}`;
		const result = scanText(text, { patterns: [], useEntropy: true });
		expect(result.findings).toEqual([
			expect.objectContaining({
				type: "High-Entropy BASE64",
				action: "report",
				context: "ambiguous",
				encoding: "base64",
				decodedKind: "non-printable",
			}),
		]);
		expect(result.redactions).toEqual([]);
		expect(result.redacted).toBe(text);
	});

	it("reports every occurrence of repeated ambiguous Base64 without redacting", () => {
		const value = highEntropyBase64();
		const text = `FIRST=${value}\nSECOND=${value}`;
		const result = scanText(text, { patterns: [], useEntropy: true });
		expect(result.findings).toHaveLength(2);
		expect(result.redactions).toHaveLength(0);
		expect(result.redacted).toBe(text);
	});

	it("does not redact benign Base64 source maps, quoted prose, or recognized binary files", () => {
		const prose = encodeBase64("The quick brown fox jumps over the lazy dog.");
		const sourceMap = sourceMapBase64();
		const png = pngBase64();
		const text = `sourceMap=${sourceMap}\nconst fixture = "${prose}";\nimage=${png}`;
		const result = scanText(text, { patterns: [], useEntropy: true });

		expect(result.redacted).toBe(text);
		expect(result.redactions).toHaveLength(0);
		expect(result.findings).toHaveLength(3);
		expect(result.findings.map((finding) => finding.action)).toEqual(["report", "report", "report"]);
		expect(result.findings.map((finding) => finding.decodedKind)).toEqual(["text", "text", "binary"]);
	});

	it("does not auto-redact standalone quoted or ordinary assignment Base64", () => {
		const value = encodeBase64("ordinary configuration fixture with enough varied printable text");
		for (const text of [`"${value}"`, `payload=${value}`]) {
			const result = scanText(text, { patterns: [], useEntropy: true });
			expect(result.findings).toHaveLength(1);
			expect(result.redactions).toHaveLength(0);
			expect(result.redacted).toBe(text);
		}
	});

	it("redacts Base64 in credential assignments regardless of decoded content or quoted key syntax", () => {
		const variants = [
			{ text: `token=${highEntropyBase64()}`, encoding: "base64" },
			{ text: `api_key=${highEntropyBase64()}-_Xy`, encoding: "base64url" },
			{
				text: `token=${encodeBase64("ordinary printable text that is still a token value")}`,
				encoding: "base64",
			},
			{
				text: `{"token":"${encodeBase64("ordinary printable text that is still a token value")}"}`,
				encoding: "base64",
			},
		];
		for (const { text, encoding } of variants) {
			const result = scanText(text, { patterns: [], useEntropy: true });
			expect(result.findings).toHaveLength(1);
			expect(result.redactions).toHaveLength(1);
			expect(result.findings[0]).toMatchObject({
				action: "redact",
				context: "credential-assignment",
				encoding,
			});
			expect(result.redacted).not.toContain(result.findings[0]?.value ?? "missing");
		}
	});

	it("redacts common key-management credential assignments", () => {
		const value = highEntropyBase64();
		for (const key of ["AUTH", "ACCESS_KEY", "ENCRYPTION_KEY", "MASTER_KEY", "SIGNING_KEY"]) {
			const result = scanText(`${key}=${value}`, { patterns: [], useEntropy: true });
			expect(result.findings[0]).toMatchObject({ action: "redact", context: "credential-assignment" });
			expect(result.redactions).toHaveLength(1);
			expect(result.redacted).toBe(`${key}=[REDACTED:HIGH-ENTROPY_BASE64]`);
		}
	});

	it("redacts a malformed opaque Base64-shaped value in immediate credential context", () => {
		const value = `${highEntropyBase64()}===`;
		const result = scanText(`token=${value}`, { patterns: [], useEntropy: true });
		expect(result.findings[0]).toMatchObject({
			action: "redact",
			context: "credential-assignment",
			decodedKind: "invalid",
		});
		expect(result.redacted).toBe("token=[REDACTED:HIGH-ENTROPY_BASE64]");
	});

	it("keeps credential context for multiline assignments", () => {
		const value = highEntropyBase64();
		const text = `client_secret:\n  ${value}`;
		const result = scanText(text, { patterns: [], useEntropy: true });
		expect(result.findings[0]).toMatchObject({ action: "redact", context: "credential-assignment" });
		expect(result.redacted).toBe("client_secret:\n  [REDACTED:HIGH-ENTROPY_BASE64]");
	});

	it("does not let a safe path-like shape override credential context", () => {
		const value = "aB3dE5fG7hI9jK1lM2nO/4pQ6rS8tU0vW";
		const result = scanText(`token=${value}`, { patterns: [], useEntropy: true });
		expect(result.findings[0]).toMatchObject({ action: "redact", context: "credential-assignment" });
		expect(result.redacted).toBe("token=[REDACTED:HIGH-ENTROPY_BASE64]");
	});

	it("redacts canonical Base64 in Basic authorization context", () => {
		const value = encodeBase64("admin:correct-horse-battery-staple");
		const result = scanText(`Authorization: Basic ${value}`, { patterns: [], useEntropy: true });
		expect(result.findings).toHaveLength(1);
		expect(result.redactions).toHaveLength(1);
		expect(result.findings[0]).toMatchObject({
			action: "redact",
			context: "basic-auth",
			decodedKind: "text",
		});
		expect(result.redacted).toBe("Authorization: Basic [REDACTED:HIGH-ENTROPY_BASE64]");
	});

	it("redacts quoted Basic authorization credentials", () => {
		const value = encodeBase64("admin:correct-horse-battery-staple");
		const result = scanText(`Authorization: Basic "${value}"`, { patterns: [], useEntropy: true });
		expect(result.findings[0]).toMatchObject({ action: "redact", context: "basic-auth" });
		expect(result.redacted).toBe('Authorization: Basic "[REDACTED:HIGH-ENTROPY_BASE64]"');
	});

	it("does not extend Basic authorization context across a newline", () => {
		const value = highEntropyBase64();
		const text = `Authorization: Basic\n"${value}"`;
		const result = scanText(text, { patterns: [], useEntropy: true });
		expect(result.findings).toEqual([expect.objectContaining({ action: "report", context: "ambiguous" })]);
		expect(result.redactions).toHaveLength(0);
		expect(result.redacted).toBe(text);
	});

	it("redacts the outer Base64 candidate when decoded text contains a credential assignment", () => {
		const value = encodeBase64("token=correct-horse-battery-staple-9f8e7d");
		const text = `payload=${value}`;
		const result = scanText(text, { patterns: [], useEntropy: true });
		expect(result.findings).toHaveLength(1);
		expect(result.redactions).toHaveLength(1);
		expect(result.findings[0]).toMatchObject({
			action: "redact",
			context: "encoded-credential",
			decodedKind: "credential",
		});
		expect(result.redacted).toBe("payload=[REDACTED:HIGH-ENTROPY_BASE64]");
	});

	it("inspects bounded ends of large decoded Base64 content for credentials", () => {
		const decoded = `${"ordinary text ".repeat(1500)}\ntoken=correct-horse-battery-staple-9f8e7d`;
		const value = encodeBase64(decoded);
		const result = scanText(`payload=${value}`, { patterns: [], useEntropy: true });
		expect(result.findings[0]).toMatchObject({ action: "redact", context: "encoded-credential" });
		expect(result.redactions).toHaveLength(1);
	});

	it("redacts the outer Base64 candidate when decoded text contains a named provider secret or private key", () => {
		const privateKey = ["-----BEGIN PRIVATE KEY-----", "abc1234567890", "-----END PRIVATE KEY-----"].join("\n");
		for (const decoded of [githubPat(), privateKey]) {
			const value = encodeBase64(decoded);
			const result = scanText(`payload=${value}`, { patterns: [], useEntropy: true });
			expect(result.redactions).toHaveLength(1);
			expect(result.findings[0]).toMatchObject({
				action: "redact",
				context: "encoded-credential",
				decodedKind: "credential",
			});
		}
	});

	it("preserves provider regex findings even when the value is also a high-entropy Base64 candidate", () => {
		const value = `${highEntropyBase64()}XyZ9QwRt`;
		const result = scanText(`AWS_SECRET_ACCESS_KEY=${value}`);
		expect(result.findings).toHaveLength(1);
		expect(result.redactions).toHaveLength(1);
		expect(result.findings[0]).toMatchObject({ source: "regex", type: "AWS Secret Access Key" });
		expect(result.redacted).toBe("AWS_SECRET_ACCESS_KEY=[REDACTED:AWS_SECRET_ACCESS_KEY]");
	});

	it("uses the full AWS Access Key ID for redaction and exact whitelisting", () => {
		const key = awsKey();
		const redacted = scanText(key, { useEntropy: false });
		expect(redacted.findings[0]?.value).toBe(key);
		expect(redacted.redacted).not.toContain(key);

		const allowed = scanText(key, { whitelist: new Set([key]), useEntropy: false });
		expect(allowed.findings).toHaveLength(0);
		expect(allowed.redacted).toBe(key);
	});

	it("redacts only the PEM block and preserves trailing text", () => {
		const pem = ["-----BEGIN PRIVATE KEY-----", "abc1234567890", "-----END PRIVATE KEY-----"].join("\n");
		const result = scanText(`before\n${pem}\nKEEP THIS`, { useEntropy: false });
		expect(result.redacted).toBe("before\n[REDACTED:PRIVATE_KEY_(PEM)]\nKEEP THIS");
	});

	it("is idempotent", () => {
		const once = scanText(`token=${githubPat()}`, { useEntropy: false }).redacted;
		expect(scanText(once, { useEntropy: false }).redacted).toBe(once);
	});

	it("handles a zero-length custom regex without looping", () => {
		const patterns = [{ name: "Empty", regex: /(?:)/g, confidence: "medium" as const }];
		expect(scanText("safe", { patterns, useEntropy: false }).redacted).toBe("safe");
	});

	it("returns clean text unchanged", () => {
		const text = "const x = 42;";
		const result = scanText(text);
		expect(result.findings).toHaveLength(0);
		expect(result.redacted).toBe(text);
	});

	it("detects multiple secrets in one text", () => {
		const text = `AWS=${awsKey()}\nGH=${githubPat()}`;
		const result = scanText(text);
		expect(result.findings.length).toBeGreaterThanOrEqual(2);
	});

	it("detects context-prefixed secrets (Twilio SID)", () => {
		const text = `TWILIO_ACCOUNT_SID=${twilioSid()}`;
		const result = scanText(text);
		const twilio = result.findings.find((f) => f.type === "Twilio Account SID");
		expect(twilio).toBeDefined();
	});

	it("suppresses the same OID only in the safe occurrence (occurrence-local)", () => {
		const sha = gitSha40();
		const text = `commit_sha: ${sha}\nUNKNOWN=${sha}`;
		const result = scanText(text);
		expect(result.findings).toHaveLength(1);
		expect(result.redactions).toHaveLength(1);
		// Exact output: the metadata occurrence survives verbatim, the ambiguous one is redacted.
		expect(result.redacted).toBe(`commit_sha: ${sha}\nUNKNOWN=[REDACTED:HIGH-ENTROPY_HEX]`);
		expect(result.findings[0]?.value).toBe(sha);
		expect(result.findings[0]?.type).toBe("High-Entropy HEX");
		expect(result.findings[0]?.charSet).toBe("hex");
	});

	it("leaves multi-line canonical artifact text unchanged", () => {
		const sha40 = gitSha40();
		const sha64 = gitSha64();
		const text = [
			`commit_sha: ${sha40}`,
			`uses: actions/checkout@${sha40}`,
			`image: alpine@sha256:${sha64}`,
			`Image ID: sha256:${sha64}`,
			`container_id: ${sha64}`,
			"View build details: docker-desktop://dashboard/build/desktop-linux/desktop-linux/6xavvfljy663xxe99qw7gtrnd",
		].join("\n");
		const result = scanText(text);
		expect(result.findings).toHaveLength(0);
		expect(result.redactions).toHaveLength(0);
		expect(result.redacted).toBe(text);
	});

	it("redacts credential contexts exactly even for OID-shaped values", () => {
		const sha40 = gitSha40();
		const sha64 = gitSha64();
		const token = scanText(`token=${sha40}`);
		expect(token.findings.map((f) => f.type)).toContain("Generic Password Assignment");
		// secretGroup 1: only the value is replaced, the assignment prefix stays
		// visible so the agent can still read the surrounding code.
		expect(token.redacted).toBe("token=[REDACTED:GENERIC_PASSWORD_ASSIGNMENT]");

		const secret = scanText(`secret=${sha64}`);
		expect(secret.redacted).toBe("secret=[REDACTED:GENERIC_PASSWORD_ASSIGNMENT]");
		expect(secret.redacted).not.toContain(sha64.slice(0, 8));
	});

	it("entropy detection can be disabled", () => {
		const text = `SECRET=${highEntropyBase64()}`;
		const withEntropy = scanText(text, { useEntropy: true, patterns: [] });
		const withoutEntropy = scanText(text, { useEntropy: false, patterns: [] });

		expect(withEntropy.findings.length).toBeGreaterThan(0);
		expect(withoutEntropy.findings).toHaveLength(0);
	});
});

// ═══════════════════════════════════════════════════════════════════════
// scanObject
// ═══════════════════════════════════════════════════════════════════════

describe("scanObject", () => {
	it("finds secrets in flat objects", () => {
		const obj = { apiKey: openAiKey() };
		const result = scanObject(obj);
		expect(result.hasFindings).toBe(true);
	});

	it("finds secrets in nested objects", () => {
		const obj = { config: { auth: { token: githubPat() } } };
		const result = scanObject(obj);
		expect(result.hasFindings).toBe(true);
	});

	it("redacts secrets in returned object", () => {
		const obj = { db: urlWithCreds(), other: "safe" };
		const result = scanObject(obj);
		const redacted = result.redactedObject as Record<string, unknown>;
		expect(String(redacted.db)).toContain("[REDACTED:");
		expect(String(redacted.db)).not.toContain("secretpassword");
		expect(redacted.other).toBe("safe");
	});

	it("handles null/undefined/numbers gracefully", () => {
		const obj = { a: null, b: undefined, c: 42, e: [7, githubPat()] };
		expect(scanObject(obj).hasFindings).toBe(true);
	});

	it("does not mutate the original", () => {
		const original = { key: githubPat() };
		const snapshot = JSON.stringify(original);
		scanObject(original);
		expect(JSON.stringify(original)).toBe(snapshot);
	});

	it("keeps digest syntax safe in object values while redacting credential syntax", () => {
		const sha64 = gitSha64();
		const safe = scanObject({ image_id: `sha256:${sha64}`, digest: `sha256:${sha64}` });
		expect(safe.hasFindings).toBe(false);
		expect(safe.redactedObject).toEqual({ image_id: `sha256:${sha64}`, digest: `sha256:${sha64}` });

		const unsafe = scanObject({ token: `token=${sha64}` });
		expect(unsafe.hasFindings).toBe(true);
		const redacted = unsafe.redactedObject as Record<string, string>;
		expect(redacted.token).toBe("token=[REDACTED:GENERIC_PASSWORD_ASSIGNMENT]");
	});

	it("skips string values under known path keys (edit-tool paths are not secrets)", () => {
		const obj = {
			path: "[REDACTED:HIGH-ENTROPY_MIXED].ts",
			filePath: "/Users/vk/src/inkubator/project/src/provider-factory.ts",
			workingDir: "/tmp/build-cache/a1b2c3d4e5f6",
			new_string: "safe",
		};
		const result = scanObject(obj);
		expect(result.hasFindings).toBe(false);
		expect(result.redactedObject).toEqual(obj);
	});

	it("still scans values under credential-bearing keys", () => {
		// `token` keys are never skipped like `path` keys are, even when the value
		// itself looks digest-like.
		const sha64 = gitSha64();
		const obj = { token: `token=${sha64}` };
		expect(scanObject(obj).hasFindings).toBe(true);
	});

	it("clean objects return hasFindings=false", () => {
		const obj = { name: "Alice", age: 30 };
		const result = scanObject(obj);
		expect(result.hasFindings).toBe(false);
		expect(result.findings).toHaveLength(0);
		expect(result.redactions).toHaveLength(0);
	});
});

// ═══════════════════════════════════════════════════════════════════════
// formatFindings
// ═══════════════════════════════════════════════════════════════════════

describe("formatFindings", () => {
	it("returns 'No secrets detected.' for empty", () => {
		expect(formatFindings([])).toBe("No secrets detected.");
	});

	it("shows confidence icons", () => {
		const r = formatFindings([{ type: "Test", source: "regex" as const, value: "x", confidence: "high" }]);
		expect(r).toContain("🔴");
		expect(r).toContain("Test");
	});

	it("deduplicates by type", () => {
		const f = { type: "X", source: "regex" as const, value: "a", confidence: "high" as const };
		const r = formatFindings([f, f]);
		expect(r.match(/X/g)).toHaveLength(1);
	});

	it("never leaks secret values", () => {
		const f = [{ type: "Z", source: "regex" as const, value: "super-secret-actual", confidence: "high" as const }];
		const r = formatFindings(f);
		expect(r).not.toContain("super-secret");
	});
});

// ═══════════════════════════════════════════════════════════════════════
// countByType
// ═══════════════════════════════════════════════════════════════════════

describe("countByType", () => {
	const f = (type: string) => ({ type, source: "regex" as const, value: "x", confidence: "high" as const });

	it("empty → {}", () => {
		expect(countByType([])).toEqual({});
	});

	it("single type", () => {
		expect(countByType([f("A"), f("A"), f("A")])).toEqual({ A: 3 });
	});

	it("multiple types", () => {
		expect(countByType([f("X"), f("X"), f("Y")])).toEqual({ X: 2, Y: 1 });
	});
});
