import { homedir } from "node:os";
import { resolve } from "node:path";

import { defineConfig } from "vitest/config";

const piRoot = resolve(homedir(), ".npm-global", "lib", "node_modules", "@earendil-works", "pi-coding-agent");

export default defineConfig({
	resolve: {
		alias: {
			// Resolve pi packages through pi-coding-agent's own node_modules,
			// where its transitive deps (pi-tui, pi-ai, etc.) live.
			"@earendil-works/pi-tui": resolve(piRoot, "node_modules/@earendil-works/pi-tui"),
			"@earendil-works/pi-ai": resolve(piRoot, "node_modules/@earendil-works/pi-ai"),
			"@earendil-works/pi-coding-agent": piRoot,
		},
		conditions: ["node", "import"],
	},
	test: {
		include: ["**/*.test.ts"],
	},
});
