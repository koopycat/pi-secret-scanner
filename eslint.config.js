// @ts-check
import { homedir } from "node:os";
import { join } from "node:path";
import tseslint from "typescript-eslint";
import n from "eslint-plugin-n";
import importX from "eslint-plugin-import-x";
import prettierConfig from "eslint-config-prettier";

export default tseslint.config(
	// ---- Type-aware parser config (must come before type-aware presets) ----
	{
		languageOptions: {
			parserOptions: {
				projectService: true,
				tsconfigRootDir: import.meta.dirname,
			},
		},
	},

	// ---- Global ignores ----
	{
		ignores: ["**/dist/**", "**/node_modules/**", "**/*.js", "**/*.mjs", "**/*.cjs", "**/*.d.ts"],
	},

	// ---- Base: recommended + strict type-checked TS ----
	...tseslint.configs.recommendedTypeChecked,
	...tseslint.configs.strictTypeChecked,

	// ---- Node.js (ESM project) ----
	// @ts-expect-error - plugin config types differ
	n.configs["flat/recommended-module"],

	// ---- Import validation ----
	// @ts-expect-error - plugin config types differ
	importX.flatConfigs.recommended,

	// ---- Project overrides ----
	{
		settings: {
			"import-x/extensions": [".ts"],
			"import-x/external-module-folders": [
				join(homedir(), ".npm-global", "lib", "node_modules"),
				join(
					homedir(),
					".npm-global",
					"lib",
					"node_modules",
					"@earendil-works",
					"pi-coding-agent",
					"node_modules",
				),
			],
		},
		rules: {
			// =============================================================
			// TypeScript
			// =============================================================

			// Off: pi's dynamic API uses `any` in callback signatures; ~95% are unfixable noise.
			// The no-unsafe-* rules are already off for the same reason.
			"@typescript-eslint/no-explicit-any": "off",
			"@typescript-eslint/no-unsafe-assignment": "off",
			"@typescript-eslint/no-unsafe-member-access": "off",
			"@typescript-eslint/no-unsafe-call": "off",
			"@typescript-eslint/no-unsafe-return": "off",
			"@typescript-eslint/no-unsafe-argument": "off",

			// Downgraded: false positives with closure-based state (e.g., AbortSignal handlers)
			"@typescript-eslint/no-unnecessary-condition": ["warn", { allowConstantLoopConditions: true }],

			// Numbers and booleans in templates are intentional throughout the extension UI
			"@typescript-eslint/restrict-template-expressions": ["warn", { allowNumber: true, allowBoolean: true }],

			// Pi command handlers share a signature regardless of whether they await
			"@typescript-eslint/require-await": "off",

			// Allow but flag for review
			"@typescript-eslint/no-non-null-assertion": "warn",

			// Dead code prevention
			"@typescript-eslint/no-unused-vars": [
				"error",
				{ argsIgnorePattern: "^_", varsIgnorePattern: "^_", caughtErrorsIgnorePattern: "^_" },
			],
			// Suppress core no-unused-vars to avoid double-reporting with the TS version
			"no-unused-vars": "off",

			// Ban require in ESM
			"@typescript-eslint/no-require-imports": "error",

			// =============================================================
			// Node.js
			// =============================================================

			// process.exit kills the host agent — never acceptable in a pi extension
			"n/no-process-exit": "error",
			"n/hashbang": "off",
			// Target Node.js 26 (project runtime)
			"n/no-unsupported-features/node-builtins": ["error", { version: ">=26.0.0" }],
			// Off: pi packages resolve at runtime via global symlinks; tsx handles resolution.
			"n/no-missing-import": "off",

			// =============================================================
			// Imports
			// =============================================================

			// Off: pi packages resolve via global symlinks; tsx handles .ts imports at runtime.
			"import-x/no-unresolved": "off",
			// Disabled: pi's dynamic module resolution breaks static namespace/named analysis
			"import-x/namespace": "off",
			"import-x/named": "off",
			// Duplicate imports can cause live-binding confusion in ESM
			"import-x/no-duplicates": "warn",
			// Off: extensionless/.ts imports resolved by tsx at runtime.
			"import-x/extensions": "off",

			"import-x/order": [
				"warn",
				{
					groups: ["builtin", "external", "internal", "parent", "sibling", "index", "type"],
					"newlines-between": "always",
					alphabetize: { order: "asc", caseInsensitive: true },
				},
			],

			// =============================================================
			// General best practices
			// =============================================================

			"no-debugger": "error",
			curly: ["error", "all"],
			"no-console": ["warn", { allow: ["warn", "error"] }],
			eqeqeq: ["error", "always"],
			"prefer-const": "error",
			"no-var": "error",
			"prefer-template": "error",
			"object-shorthand": "error",
		},
	},

	// ---- Test file exceptions ----
	// Tests need relaxed type-safety: stubs, partial mocks, and `as any` assertions are normal.
	{
		files: ["**/*.test.ts", "**/*.spec.ts", "**/__tests__/**", "vitest.config.ts"],
		rules: {
			"@typescript-eslint/explicit-function-return-type": "off",
			"@typescript-eslint/no-non-null-assertion": "off",
			"@typescript-eslint/no-explicit-any": "off",
			"@typescript-eslint/no-unused-vars": "off",
			"@typescript-eslint/no-empty-function": "off",
			"n/no-process-exit": "off",
			// vitest and the config are dev-only; the package itself imports nothing unpublished
			"n/no-unpublished-import": "off",
			"no-console": "off",
		},
	},

	// ---- Dev scripts: CLI output is their purpose ----
	{
		files: ["scripts/**/*.ts"],
		rules: {
			"n/no-process-exit": "off",
			"no-console": "off",
		},
	},

	// ---- Prettier: disable all formatting rules (must be LAST) ----
	prettierConfig,
);
