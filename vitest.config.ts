import { defineConfig } from "vitest/config";

export default defineConfig({
	resolve: {
		conditions: ["node", "import"],
	},
	test: {
		include: ["**/*.test.ts"],
		exclude: ["**/node_modules/**", "**/.kilo/**"],
	},
});
