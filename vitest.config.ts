import { defineConfig } from "vitest/config";

export default defineConfig({
	resolve: {
		conditions: ["node", "import"],
	},
	test: {
		include: ["**/*.test.ts"],
		exclude: ["**/node_modules/**", "**/.kilo/**"],
		coverage: {
			provider: "v8",
			include: ["*.ts"],
			exclude: ["**/*.test.ts", "vitest.config.ts", "eslint.config.js"],
			reporter: ["text", "html"],
			// Floors, not goals: raise them when coverage improves.
			thresholds: { statements: 97, branches: 90, functions: 100, lines: 97 },
		},
	},
});
