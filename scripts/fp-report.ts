/**
 * False-positive report: scan files or directories the way the extension
 * scans `read` results and summarize what would be replaced or reported.
 *
 * Point it at code that should contain no secrets (a checkout, a lockfile
 * directory, saved command output) and every "replace" line is a false
 * positive worth a fixture in fixtures/benign/.
 *
 *   pnpm fp-report <path>... [--show-values]
 *
 * Values are hidden by default because real directories can contain real
 * secrets; --show-values prints them truncated. Requires Node >= 22.18.
 */

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";

import { isLockfile } from "../lockfiles.ts";
import { scanText } from "../scanner.ts";

const SKIPPED_DIRECTORIES = new Set([".git", "node_modules", ".venv", "target", "dist", ".direnv"]);
const MAX_FILE_BYTES = 2 * 1024 * 1024;
const SAMPLES_PER_GROUP = 5;

const args = process.argv.slice(2);
const showValues = args.includes("--show-values");
const roots = args.filter((arg) => arg !== "--show-values");
if (roots.length === 0) {
	console.error("usage: pnpm fp-report <path>... [--show-values]");
	process.exit(2);
}

function* walk(path: string): Generator<string> {
	const stat = statSync(path);
	if (stat.isFile()) {
		yield path;
		return;
	}
	if (!stat.isDirectory()) return;
	for (const entry of readdirSync(path, { withFileTypes: true })) {
		if (entry.isDirectory() && SKIPPED_DIRECTORIES.has(entry.name)) continue;
		// .env files are expected to hold secrets; they are not false positives.
		if (entry.name.startsWith(".env")) continue;
		yield* walk(join(path, entry.name));
	}
}

interface Group {
	count: number;
	samples: string[];
}

const groups = new Map<string, Group>();
let files = 0;
let bytes = 0;
const started = performance.now();

for (const root of roots) {
	for (const file of walk(root)) {
		if (statSync(file).size > MAX_FILE_BYTES) continue;
		const text = readFileSync(file, "utf-8");
		if (text.includes("\u0000")) continue; // binary
		files++;
		bytes += text.length;

		const result = scanText(text, { useEntropy: !isLockfile(file) });
		const replaced = new Set(result.redactions);
		for (const finding of result.findings) {
			const action = replaced.has(finding) ? "replace" : "report ";
			const key = `${action} ${finding.type}${finding.context ? ` (${finding.context})` : ""}`;
			const group = groups.get(key) ?? { count: 0, samples: [] };
			group.count++;
			if (group.samples.length < SAMPLES_PER_GROUP) {
				const where = relative(process.cwd(), file);
				group.samples.push(showValues ? `${where}: ${finding.value.slice(0, 80)}` : where);
			}
			groups.set(key, group);
		}
	}
}

const elapsed = Math.round(performance.now() - started);
console.log(`${files} files, ${(bytes / 1e6).toFixed(1)} MB, ${elapsed} ms\n`);
const sorted = [...groups.entries()].sort(([a, ga], [b, gb]) => a.localeCompare(b) || gb.count - ga.count);
for (const [key, group] of sorted) {
	console.log(`${String(group.count).padStart(7)}  ${key}`);
	for (const sample of group.samples) console.log(`           ${sample}`);
}
const replacements = sorted.filter(([key]) => key.startsWith("replace")).reduce((n, [, g]) => n + g.count, 0);
console.log(`\n${replacements} value(s) would be replaced`);
