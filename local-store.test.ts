import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, utimesSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { persistProjectFingerprint } from "./local-store.ts";
import { tempDir } from "./testing/harness.ts";

const LOCAL = ".secret-scanner.local.json";
const FAST_LOCK = { attempts: 3, retryMs: 1, staleMs: 10_000 };

function gitRepo(): string {
	const root = tempDir();
	execFileSync("git", ["init", "-q"], { cwd: root });
	return root;
}

function readLocal(cwd: string): { whitelist: { value_hashes: string[]; values?: string[] } } {
	return JSON.parse(readFileSync(join(cwd, LOCAL), "utf-8"));
}

function exclude(root: string): string {
	return readFileSync(join(root, ".git", "info", "exclude"), "utf-8");
}

describe("persistProjectFingerprint", () => {
	it("creates an owner-only file with sorted, de-duplicated fingerprints", async () => {
		const cwd = tempDir();
		await persistProjectFingerprint(cwd, "sha256:bb");
		await persistProjectFingerprint(cwd, "sha256:aa");
		await persistProjectFingerprint(cwd, "sha256:bb");

		expect(readLocal(cwd).whitelist.value_hashes).toEqual(["sha256:aa", "sha256:bb"]);
		expect(statSync(join(cwd, LOCAL)).mode & 0o777).toBe(0o600);
	});

	it("preserves other fields in an existing local file", async () => {
		const cwd = tempDir({ [LOCAL]: JSON.stringify({ note: "kept", whitelist: { values: ["v"] } }) });
		await persistProjectFingerprint(cwd, "sha256:aa");

		const saved = JSON.parse(readFileSync(join(cwd, LOCAL), "utf-8"));
		expect(saved).toEqual({ note: "kept", whitelist: { values: ["v"], value_hashes: ["sha256:aa"] } });
	});

	it("leaves no lock or temporary files behind", async () => {
		const cwd = tempDir();
		await persistProjectFingerprint(cwd, "sha256:aa");
		expect(readdirSync(cwd)).toEqual([LOCAL]);
	});

	it("releases the lock and keeps the file intact when it cannot be parsed", async () => {
		const cwd = tempDir({ [LOCAL]: "{ broken" });

		await expect(persistProjectFingerprint(cwd, "sha256:aa")).rejects.toThrow(SyntaxError);
		expect(readdirSync(cwd)).toEqual([LOCAL]);
		expect(readFileSync(join(cwd, LOCAL), "utf-8")).toBe("{ broken");
	});
});

describe("locking", () => {
	it("waits for a live lock and then gives up with an actionable error", async () => {
		const cwd = tempDir({ [`${LOCAL}.lock`]: "" });

		await expect(persistProjectFingerprint(cwd, "sha256:aa", FAST_LOCK)).rejects.toThrow(
			/locked by another process; remove .*\.lock if none is running/,
		);
		expect(existsSync(join(cwd, `${LOCAL}.lock`))).toBe(true); // someone else's lock stays
		expect(existsSync(join(cwd, LOCAL))).toBe(false);
	});

	it("takes over a stale lock left by a crashed process", async () => {
		const cwd = tempDir({ [`${LOCAL}.lock`]: "" });
		const old = new Date(Date.now() - 60_000);
		utimesSync(join(cwd, `${LOCAL}.lock`), old, old);

		await persistProjectFingerprint(cwd, "sha256:aa", FAST_LOCK);
		expect(readLocal(cwd).whitelist.value_hashes).toEqual(["sha256:aa"]);
	});

	it("serializes concurrent writers without losing entries", async () => {
		const cwd = tempDir();
		const hashes = Array.from({ length: 8 }, (_, i) => `sha256:${i}`);
		await Promise.all(hashes.map((hash) => persistProjectFingerprint(cwd, hash)));

		expect(readLocal(cwd).whitelist.value_hashes).toEqual(hashes);
	});
});

describe("git exclusion", () => {
	// Temporary directories on macOS live under the /var -> /private/var
	// symlink, so these tests also cover symlinked project paths.
	it("adds the local file to .git/info/exclude exactly once", async () => {
		const root = gitRepo();
		await persistProjectFingerprint(root, "sha256:aa");
		await persistProjectFingerprint(root, "sha256:bb");

		expect(
			exclude(root)
				.split("\n")
				.filter((line) => line === `/${LOCAL}`),
		).toHaveLength(1);
		expect(execFileSync("git", ["status", "--porcelain"], { cwd: root, encoding: "utf-8" })).toBe("");
	});

	it("excludes the file relative to the repository root when Pi runs in a subdirectory", async () => {
		const root = gitRepo();
		const sub = join(root, "packages", "app");
		mkdirSync(sub, { recursive: true });
		await persistProjectFingerprint(sub, "sha256:aa");

		expect(exclude(root).split("\n")).toContain(`/packages/app/${LOCAL}`);
	});

	it("appends on a new line when the exclude file lacks a trailing newline", async () => {
		const root = gitRepo();
		writeFileSync(join(root, ".git", "info", "exclude"), "*.log");
		await persistProjectFingerprint(root, "sha256:aa");

		expect(exclude(root)).toBe(`*.log\n/${LOCAL}\n`);
	});

	it("refuses to write a local file that is tracked by Git", async () => {
		const root = gitRepo();
		writeFileSync(join(root, LOCAL), JSON.stringify({ whitelist: {} }));
		execFileSync("git", ["add", LOCAL], { cwd: root });

		await expect(persistProjectFingerprint(root, "sha256:aa")).rejects.toThrow(/already tracked by Git/);
		expect(readLocal(root).whitelist).toEqual({});
		expect(existsSync(join(root, `${LOCAL}.lock`))).toBe(false);
	});
});
