/**
 * Persists "Always allow in this project" decisions as SHA-256 fingerprints
 * in `.secret-scanner.local.json`. Plaintext values are never written.
 *
 * The file is owner-only (0600), excluded through the repository-local
 * `.git/info/exclude`, and updated under a lock file with an atomic rename
 * so concurrent Pi processes in one project cannot lose each other's entries.
 */

import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
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
import { join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";

import { LOCAL_CONFIG_NAME } from "./config.ts";

import type { WhitelistConfig } from "./config.ts";

export interface LockOptions {
	attempts: number;
	retryMs: number;
	/**
	 * A lock older than this was left behind by a crashed process; holding it
	 * never takes longer than one small synchronous read-modify-write.
	 */
	staleMs: number;
}

export const DEFAULT_LOCK_OPTIONS: LockOptions = { attempts: 40, retryMs: 25, staleMs: 10_000 };

function gitOutput(cwd: string, args: string[]): string {
	return execFileSync("git", args, { cwd, encoding: "utf-8", stdio: ["ignore", "pipe", "ignore"] }).trim();
}

function isTrackedByGit(root: string, relativePath: string): boolean {
	try {
		execFileSync("git", ["ls-files", "--error-unmatch", "--", relativePath], { cwd: root, stdio: "ignore" });
		return true;
	} catch {
		return false;
	}
}

/** Keep the local file out of Git without editing the shared `.gitignore`. */
function excludeFromGit(cwd: string): void {
	let root: string;
	try {
		root = gitOutput(cwd, ["rev-parse", "--show-toplevel"]);
	} catch {
		return; // Non-Git project.
	}

	// Ask Git for the path of cwd inside the work tree: comparing cwd with
	// --show-toplevel breaks when either side goes through a symlink (macOS
	// /var -> /private/var, symlinked project directories).
	const relativeConfigPath = `${gitOutput(cwd, ["rev-parse", "--show-prefix"])}${LOCAL_CONFIG_NAME}`;
	if (isTrackedByGit(root, relativeConfigPath)) {
		throw new Error(`${relativeConfigPath} is already tracked by Git; untrack it before saving local decisions`);
	}

	const excludePath = gitOutput(root, ["rev-parse", "--git-path", "info/exclude"]);
	if (!excludePath) throw new Error("Git did not return an info/exclude path");
	const absoluteExcludePath = join(root, excludePath);
	const pattern = `/${relativeConfigPath}`;
	const existing = existsSync(absoluteExcludePath) ? readFileSync(absoluteExcludePath, "utf-8") : "";
	if (!existing.split(/\r?\n/).includes(pattern)) {
		const separator = existing.length > 0 && !existing.endsWith("\n") ? "\n" : "";
		appendFileSync(absoluteExcludePath, `${separator}${pattern}\n`);
	}
}

function isStaleLock(lockPath: string, staleMs: number): boolean {
	try {
		return Date.now() - statSync(lockPath).mtimeMs > staleMs;
	} catch {
		return false; // Released between our open attempt and this check.
	}
}

async function acquireLock(lockPath: string, options: LockOptions): Promise<number> {
	for (let attempt = 0; attempt < options.attempts; attempt++) {
		try {
			return openSync(lockPath, "wx", 0o600);
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
			if (isStaleLock(lockPath, options.staleMs)) {
				rmSync(lockPath, { force: true });
				continue;
			}
			await sleep(options.retryMs);
		}
	}
	throw new Error(`${LOCAL_CONFIG_NAME} is locked by another process; remove ${lockPath} if none is running`);
}

/** Add one fingerprint to the project's local allowlist, preserving other fields. */
export async function persistProjectFingerprint(
	cwd: string,
	fingerprint: string,
	lockOptions: LockOptions = DEFAULT_LOCK_OPTIONS,
): Promise<void> {
	const configPath = join(cwd, LOCAL_CONFIG_NAME);
	const lockPath = `${configPath}.lock`;
	const lockFd = await acquireLock(lockPath, lockOptions);

	const temporaryPath = `${configPath}.tmp-${randomUUID()}`;
	try {
		excludeFromGit(cwd);
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
