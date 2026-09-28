/**
 * End-to-end smoke test: run the REAL pi binary with this extension loaded
 * against a deterministic fake provider, and assert that
 *
 *   1. the extension loads cleanly ("Failed to load extension" never appears —
 *      this is what breaks when a newer pi version changes its extension API),
 *   2. before_provider_request redacts secrets planted in the user prompt,
 *   3. the tool_result hook redacts secrets pi read from disk,
 *   4. no secret value ever reaches the fake "provider".
 *
 * Requires pi (peer/dev dependency) — CI installs a specific pi version and
 * runs this against it, so extension breakage is caught per pi release.
 *
 * Run: pnpm smoke
 *
 * Note: pi is spawned asynchronously because the fake provider runs in THIS
 * process; a blocking spawnSync would deadlock the HTTP server.
 */
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { startFakeProvider } from "./fake-provider.mjs";

const repo = resolve(dirname(fileURLToPath(import.meta.url)), "..");

// ── Synthetic secrets (concatenated so this file never matches the scanner) ──
const fakeAwsKey = "AKIA" + "IOSFODNN7EXAMPLE"; // documented AWS example key
const promptSecret = "s3cr3t-" + "prompt-" + "value-x9";

// ── Isolated environment ─────────────────────────────────────────────────────
const workDir = mkdtempSync(join(tmpdir(), "pi-secret-scanner-smoke-"));
const agentDir = join(workDir, "agent");
const sessionDir = join(workDir, "sessions");
const secretFile = join(workDir, "planted-secret.txt");
mkdirSync(agentDir, { recursive: true });
mkdirSync(sessionDir, { recursive: true });

const fake = startFakeProvider(secretFile);
// Give the server a moment to bind.
await new Promise((r) => setTimeout(r, 150));

writeFileSync(
	join(agentDir, "models.json"),
	JSON.stringify({
		providers: {
			smoke: {
				baseUrl: `http://127.0.0.1:${fake.port}/v1`,
				api: "openai-completions",
				["apiKey"]: "smoke-dummy-key",
				models: [{ id: "smoke-model", name: "Smoke Model" }],
			},
		},
	}),
);

writeFileSync(secretFile, `# planted for the smoke test\nAWS_ACCESS_KEY_ID=${fakeAwsKey}\n`);

const prompt =
	`Read the file ${secretFile} and summarize it in one sentence. ` +
	`My backup password=${promptSecret} — never repeat it.`;

// ── Locate the pi binary (devDependency install, fallback to PATH) ───────────
const localPi = join(repo, "node_modules", ".bin", "pi");
const piBin = existsSync(localPi) ? localPi : "pi";

const env = {
	...process.env,
	PI_CODING_AGENT_DIR: agentDir,
	PI_CODING_AGENT_SESSION_DIR: sessionDir,
	PI_SKIP_VERSION_CHECK: "1",
	PI_OFFLINE: "1",
	PI_TELEMETRY: "0",
};

/** @returns {Promise<{ status: number | null, stdout: string, stderr: string, timedOut: boolean }>} */
function runPi(args, timeoutMs) {
	return new Promise((resolveSpawn) => {
		// stdin must be closed: pi's print/JSON mode waits for stdin EOF before
		// running the prompt.
		const child = spawn(piBin, args, { cwd: workDir, env, stdio: ["ignore", "pipe", "pipe"] });
		let stdout = "";
		let stderr = "";
		let timedOut = false;
		child.stdout.on("data", (d) => {
			stdout += d;
		});
		child.stderr.on("data", (d) => {
			stderr += d;
		});
		const timer = setTimeout(() => {
			timedOut = true;
			child.kill("SIGTERM");
		}, timeoutMs);
		child.on("close", (code) => {
			clearTimeout(timer);
			// Let the fake server drain anything pi sent before the kill.
			setTimeout(() => resolveSpawn({ status: code, stdout, stderr, timedOut }), 250);
		});
	});
}

const result = await runPi(
	["--mode", "json", "-e", join(repo, "index.ts"), "--provider", "smoke", "--model", "smoke-model", "-p", prompt],
	120_000,
);

// Give in-flight socket data one final tick before asserting.
await new Promise((r) => setTimeout(r, 250));
fake.close();

// ── Assertions ───────────────────────────────────────────────────────────────
const failures = [];
const check = (ok, label, detail) => {
	console.log(`${ok ? "  ✓" : "  ✗"} ${label}`);
	if (!ok) failures.push({ label, detail });
};

check(
	!result.timedOut,
	"pi finishes within timeout (extension must not block provider requests)",
	`stdout tail: ${result.stdout.slice(-500)}`,
);
check(result.status === 0, "pi exits 0", `status=${result.status}\nstderr=${result.stderr}`);
check(
	!result.stderr.includes("Failed to load extension"),
	"extension loads cleanly (no extension-API breakage)",
	result.stderr,
);
check(result.stdout.includes("SMOKE_OK"), "fake provider conversation completed", result.stdout);
check(
	fake.requests.length >= 2,
	`provider received >=2 requests (got ${fake.requests.length})`,
	result.stdout.slice(-800),
);

const outbound = fake.requests.map((r) => r.raw).join("\n");
check(
	outbound.includes("[REDACTED:GENERIC_PASSWORD_ASSIGNMENT]"),
	"before_provider_request redacted the planted prompt secret",
	outbound,
);
check(!outbound.includes(promptSecret), "prompt secret never reached the provider", outbound);
check(
	outbound.includes("[REDACTED:AWS_ACCESS_KEY_ID]"),
	"tool_result hook redacted the secret read from disk",
	outbound,
);
check(!outbound.includes(fakeAwsKey), "file secret never reached the provider", outbound);
check(!`${result.stdout}${result.stderr}`.includes(fakeAwsKey), "secret does not leak into pi's own output", "");

if (failures.length > 0) {
	for (const f of failures) {
		console.error(`\nFAILED: ${f.label}`);
		if (f.detail) console.error(String(f.detail).slice(0, 2000));
	}
	console.error(`\nWork dir kept for debugging: ${workDir}`);
	process.exit(1);
}
console.log("\nsmoke test passed");
