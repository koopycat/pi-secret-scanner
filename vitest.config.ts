import { existsSync } from "node:fs";
import { createRequire } from "node:module";
import { homedir } from "node:os";
import { dirname, resolve } from "node:path";

import { defineConfig } from "vitest/config";

// Locate pi: prefer the devDependency install (self-contained, CI), fall back
// to a global install for older local setups.
function piRoot() {
	try {
		const req = createRequire(import.meta.url);
		return dirname(req.resolve("@earendil-works/pi-coding-agent/package.json"));
	} catch {
		const global = resolve(homedir(), ".npm-global", "lib", "node_modules", "@earendil-works", "pi-coding-agent");
		if (existsSync(global)) return global;
		throw new Error("pi-coding-agent not found (install as devDependency or globally)");
	}
}

const root = piRoot();
// Resolve pi's transitive deps through pi's own package context.
const piRequire = createRequire(resolve(root, "package.json"));
function piDep(name: string) {
	try {
		return dirname(piRequire.resolve(`${name}/package.json`));
	} catch {
		return name;
	}
}

export default defineConfig({
	resolve: {
		alias: {
			// Resolve pi packages through pi-coding-agent's own node_modules,
			// where its transitive deps (pi-tui, pi-ai, etc.) live.
			"@earendil-works/pi-tui": piDep("@earendil-works/pi-tui"),
			"@earendil-works/pi-ai": piDep("@earendil-works/pi-ai"),
			"@earendil-works/pi-coding-agent": root,
		},
		conditions: ["node", "import"],
	},
	test: {
		include: ["**/*.test.ts"],
		exclude: ["**/node_modules/**", "**/.kilo/**"],
	},
});
