import { writeFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it, vi } from "vitest";

import { isPathWhitelisted, loadWhitelist, mergeWhitelists, toJsRegex, whitelistSize } from "./config.ts";
import { createHarness, githubPat, tempDir } from "./testing/harness.ts";

const json = (whitelist: unknown) => JSON.stringify({ whitelist });

describe("toJsRegex", () => {
	it("translates leading gitleaks inline flags", () => {
		expect(toJsRegex("(?i)^abc$").flags).toBe("i");
		expect(toJsRegex("(?ims)x").flags).toBe("ims");
		expect(toJsRegex("(?i)(?m)x").flags).toBe("im");
		expect(toJsRegex("(?i)^ABC$").test("abc")).toBe(true);
	});

	it("leaves plain expressions unchanged", () => {
		expect(toJsRegex("^test_[a-z]+$").source).toBe("^test_[a-z]+$");
		expect(toJsRegex("^test_[a-z]+$").flags).toBe("");
	});
});

describe("loadWhitelist", () => {
	it("returns no whitelist and no errors without configuration", () => {
		expect(loadWhitelist(tempDir())).toEqual({ whitelist: null, errors: [] });
	});

	it("treats configuration without entries as no whitelist", () => {
		const cwd = tempDir({ ".secret-scanner.json": json({}), ".gitleaks.toml": "title = 'x'\n" });
		expect(loadWhitelist(cwd)).toEqual({ whitelist: null, errors: [] });
	});

	it("loads every field of .secret-scanner.json", () => {
		const cwd = tempDir({
			".secret-scanner.json": json({
				values: ["v"],
				value_hashes: ["sha256:ab"],
				value_regexes: ["^x"],
				paths: ["^fixtures/"],
				disable_rules: ["JSON Web Token"],
			}),
		});
		const { whitelist, errors } = loadWhitelist(cwd);

		expect(errors).toEqual([]);
		expect(whitelist?.values).toEqual(new Set(["v"]));
		expect(whitelist?.valueHashes).toEqual(new Set(["sha256:ab"]));
		expect(whitelist?.valueRegexes.map(String)).toEqual(["/^x/"]);
		expect(whitelist?.pathRegexes.map(String)).toEqual(["/^fixtures\\//"]);
		expect(whitelist?.disabledRules).toEqual(new Set(["JSON Web Token"]));
	});

	it("reads both [allowlist] and [[allowlists]] and lowercases stopwords", () => {
		const cwd = tempDir({
			".gitleaks.toml": [
				"[allowlist]",
				'stopwords = ["EXAMPLE"]',
				"regexes = ['''(?i)^dummy''']",
				"[[allowlists]]",
				"paths = ['''^test/''']",
				"",
			].join("\n"),
		});
		const { whitelist } = loadWhitelist(cwd);

		expect(whitelist?.valueSubstrings).toEqual(["example"]);
		expect(whitelist?.valueRegexes[0]?.flags).toBe("i");
		expect(whitelist?.pathRegexes.map(String)).toEqual(["/^test\\//"]);
	});

	it("merges all three sources", () => {
		const cwd = tempDir({
			".gitleaks.toml": '[allowlist]\nstopwords = ["a"]\n',
			".secret-scanner.json": json({ values: ["b"] }),
			".secret-scanner.local.json": json({ value_hashes: ["sha256:c"] }),
		});
		const { whitelist } = loadWhitelist(cwd);

		expect(whitelist?.valueSubstrings).toEqual(["a"]);
		expect(whitelist?.values).toEqual(new Set(["b"]));
		expect(whitelist?.valueHashes).toEqual(new Set(["sha256:c"]));
	});

	it("reports unreadable files and keeps the other sources", () => {
		const cwd = tempDir({
			".gitleaks.toml": "[allowlist\n",
			".secret-scanner.json": "{ nope",
			".secret-scanner.local.json": json({ values: ["kept"] }),
		});
		const { whitelist, errors } = loadWhitelist(cwd);

		expect(errors).toHaveLength(2);
		expect(errors[0]).toMatch(/^\.gitleaks\.toml: /);
		expect(errors[1]).toMatch(/^\.secret-scanner\.json: /);
		expect(whitelist?.values).toEqual(new Set(["kept"]));
	});

	it("drops invalid and non-string entries individually", () => {
		const cwd = tempDir({
			".secret-scanner.json": json({ value_regexes: ["(unclosed", 42, "^ok$"], paths: [null], values: ["v", 7] }),
		});
		const { whitelist, errors } = loadWhitelist(cwd);

		expect(whitelist?.valueRegexes.map(String)).toEqual(["/^ok$/"]);
		expect(whitelist?.pathRegexes).toEqual([]);
		expect(whitelist?.values).toEqual(new Set(["v"]));
		expect(errors).toEqual([
			expect.stringContaining('value_regexes: ignored invalid regex "(unclosed"'),
			".secret-scanner.json value_regexes: ignored non-string entry 42",
			".secret-scanner.json paths: ignored non-string entry null",
		]);
	});

	it("tolerates wrongly typed fields instead of iterating strings", () => {
		const cwd = tempDir({ ".secret-scanner.json": json({ values: "not-an-array", disable_rules: {} }) });
		expect(loadWhitelist(cwd)).toEqual({ whitelist: null, errors: [] });
	});
});

describe("whitelist helpers", () => {
	it("merges nothing to null and one source to itself", () => {
		expect(mergeWhitelists(null, null)).toBeNull();
		const only = loadWhitelist(tempDir({ ".secret-scanner.json": json({ values: ["v"] }) })).whitelist;
		expect(mergeWhitelists(null, only)).toBe(only);
	});

	it("counts every entry kind", () => {
		const cwd = tempDir({
			".gitleaks.toml": '[allowlist]\nstopwords = ["s"]\n',
			".secret-scanner.json": json({
				values: ["v"],
				value_hashes: ["h"],
				value_regexes: ["r"],
				paths: ["p"],
				disable_rules: ["d"],
			}),
		});
		expect(whitelistSize(loadWhitelist(cwd).whitelist!)).toBe(6);
	});

	it("matches paths even with global regexes that keep lastIndex state", () => {
		const whitelist = { ...loadWhitelist(tempDir({ ".secret-scanner.json": json({ values: ["v"] }) })).whitelist! };
		whitelist.pathRegexes = [/^fixtures\//g];

		expect(isPathWhitelisted(whitelist, "fixtures/a")).toBe(true);
		expect(isPathWhitelisted(whitelist, "fixtures/a")).toBe(true);
		expect(isPathWhitelisted(whitelist, "src/a")).toBe(false);
		expect(isPathWhitelisted(null, "fixtures/a")).toBe(false);
	});
});

describe("configuration in the extension", () => {
	it("applies .gitleaks.toml and .secret-scanner.json together", async () => {
		const secret = githubPat();
		const cwd = tempDir({
			".gitleaks.toml": '[allowlist]\nstopwords = ["unrelated"]\n',
			".secret-scanner.json": json({ values: [secret] }),
		});
		expect(await createHarness({ cwd }).provider({ p: secret })).toBeUndefined();
	});

	it("matches gitleaks stopwords as case-insensitive substrings of detected values", async () => {
		const cwd = tempDir({ ".gitleaks.toml": '[allowlist]\nstopwords = ["KLMNOP"]\n' });
		expect(await createHarness({ cwd }).provider({ p: githubPat() })).toBeUndefined();
	});

	it("shows configuration problems in the UI and still applies valid entries", async () => {
		const secret = githubPat();
		const cwd = tempDir({ ".secret-scanner.json": json({ values: [secret], value_regexes: ["(unclosed"] }) });
		const h = createHarness({ cwd });

		expect(h.ctx.ui.notify).toHaveBeenCalledWith(
			expect.stringContaining('ignored invalid regex "(unclosed"'),
			"error",
		);
		expect(await h.provider({ p: secret })).toBeUndefined();
	});

	it("reports configuration problems on stderr without a UI", () => {
		const error = vi.spyOn(console, "error").mockImplementation(() => {});
		const cwd = tempDir({ ".secret-scanner.json": "{ nope" });
		createHarness({ cwd, hasUI: false });

		expect(error).toHaveBeenCalledWith(
			expect.stringContaining("[secret-scanner] Secret scanner configuration problems"),
		);
		error.mockRestore();
	});

	it("picks up edited configuration on /secret-scanner reload", async () => {
		const secret = githubPat();
		const cwd = tempDir();
		const h = createHarness({ cwd });
		expect((await h.provider({ p: secret })).p).toContain("[REDACTED:");

		writeFileSync(join(cwd, ".secret-scanner.json"), json({ values: [secret] }));
		await h.run("reload");

		expect(h.lastNotify()).toEqual(["Secret scanner whitelist reloaded: loaded 1 entries", "info"]);
		expect(await h.provider({ p: secret })).toBeUndefined();
	});
});
