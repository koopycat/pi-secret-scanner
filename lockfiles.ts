/**
 * Lockfiles are dense with public integrity hashes. Named rules still run on
 * them; only the entropy fallback is skipped.
 */

import { basename } from "node:path";

const LOCKFILE_NAMES = new Set([
	"pnpm-lock.yaml",
	"package-lock.json",
	"npm-shrinkwrap.json",
	"yarn.lock",
	"bun.lock",
	"go.sum",
	"flake.lock",
	"devenv.lock",
	"cargo.lock",
	"uv.lock",
	"poetry.lock",
	"pipfile.lock",
	"gemfile.lock",
	"composer.lock",
	"package.resolved",
]);

export function isLockfile(filePath: string): boolean {
	const name = basename(filePath).toLowerCase();
	return LOCKFILE_NAMES.has(name) || name.endsWith(".lock");
}
