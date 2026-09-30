import { describe, expect, it } from "vitest";

import { USAGE, formatStatus } from "./commands.ts";
import { createHarness, githubPat, tempDir } from "./testing/harness.ts";

describe("/secret-scanner", () => {
	it.each(["off", "warn", "redact", "confirm"] as const)(
		"switches to %s mode and clears the scan cache",
		async (mode) => {
			const h = createHarness();
			await h.read(githubPat());
			expect(h.state.textCache.size).toBeGreaterThan(0);

			await h.run(mode);

			expect(h.state.mode).toBe(mode);
			expect(h.state.textCache.size).toBe(0);
			expect(h.lastNotify()).toEqual([
				`Secret scanner mode set to: ${mode}`,
				mode === "off" ? "warning" : "info",
			]);
		},
	);

	it("normalizes case and whitespace", async () => {
		const h = createHarness();
		await h.run("  Entropy   OFF ");
		expect(h.state.useEntropy).toBe(false);
	});

	it("toggles entropy detection and clears the cache", async () => {
		const h = createHarness();
		await h.run("entropy off");
		expect(h.state.useEntropy).toBe(false);
		expect(h.lastNotify()).toEqual(["Entropy-based detection: OFF", "info"]);

		await h.read(githubPat());
		await h.run("entropy on");
		expect(h.state.useEntropy).toBe(true);
		expect(h.state.textCache.size).toBe(0);
	});

	it("turns debug logging on and off and reports it", async () => {
		const h = createHarness();
		await h.run("debug on");
		expect(h.state.debug).toBe(true);
		expect(h.lastNotify()?.[1]).toBe("warning");
		expect(h.lastStatus()).toContain("+DEBUG");

		await h.run("debug");
		expect(h.lastNotify()).toEqual(["Secret scanner debug is on (unsafe)", "warning"]);

		await h.run("debug off");
		expect(h.state.debug).toBe(false);
		await h.run("debug");
		expect(h.lastNotify()).toEqual(["Secret scanner debug is off", "info"]);
	});

	it("resets counters", async () => {
		const h = createHarness();
		await h.provider({ p: githubPat() });
		await h.run("reset");

		expect(h.state.stats).toEqual({ scans: 0, findingsTotal: 0, reported: 0, redactions: 0, byType: {} });
	});

	it("reports when reload finds no configuration", async () => {
		const h = createHarness({ cwd: tempDir() });
		await h.run("reload");
		expect(h.lastNotify()).toEqual(["Secret scanner whitelist reloaded: no whitelist found", "info"]);
	});

	it.each(["", "status"])("shows status for %j", async (arg) => {
		const h = createHarness();
		await h.run(arg);
		expect(h.lastNotify()?.[0]).toMatch(/^🔐 Secret Scanner Status\n {2}Mode: {8}redact/);
	});

	it("rejects unknown subcommands with usage instead of showing status", async () => {
		const h = createHarness();
		await h.run("confrim");

		expect(h.lastNotify()).toEqual([`Unknown secret scanner command: confrim\n${USAGE}`, "warning"]);
		expect(h.state.mode).toBe("redact");
	});
});

describe("formatStatus", () => {
	it("shows counters, report-only findings, allowlist sizes, and types without values", async () => {
		const cwd = tempDir({
			".secret-scanner.json": JSON.stringify({ whitelist: { values: ["v"], paths: ["^x/"] } }),
		});
		const h = createHarness({ cwd });
		await h.provider({ p: githubPat() });
		h.state.stats.reported = 2;
		h.state.sessionWhitelistHashes.add("sha256:x");

		const status = formatStatus(h.state);

		expect(status).toContain("Findings:    1 (+2 report-only)");
		expect(status).toContain("Redactions:  1");
		expect(status).toContain("Values wl:   1");
		expect(status).toContain("Hash wl:     1");
		expect(status).toContain("Paths wl:    1");
		expect(status).toContain("GitHub Personal Access Token (classic): 1");
		expect(status).not.toContain(githubPat());
	});

	it("marks disabled mode and missing allowlists", async () => {
		const h = createHarness({ cwd: tempDir() });
		await h.run("off");

		const status = formatStatus(h.state);
		expect(status).toContain("Mode:        off  ⏸️  (disabled)");
		expect(status).toContain("Whitelist:   none");
	});
});
