import { createHash } from "node:crypto";
import { readFileSync, utimesSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

import { REDACTION_FLASH_MS } from "./feedback.ts";
import { REDACTION_NOTE } from "./hooks.ts";
import { createSecretScanner } from "./index.ts";
import { createState } from "./state.ts";
import { createHarness, githubPat, tempDir } from "./testing/harness.ts";

afterEach(() => {
	vi.useRealTimers();
	vi.restoreAllMocks();
});

describe("extension factory", () => {
	it("gives each state its own mode and counters", async () => {
		const a = createHarness();
		const b = createHarness();
		await a.run("warn");

		expect(a.state.mode).toBe("warn");
		expect(b.state.mode).toBe("redact");
	});

	it("keeps mode and counters when Pi calls the factory again for a new session", async () => {
		const state = createState();
		const first = createHarness({ state });
		await first.run("confirm");
		await first.provider({ p: "nothing secret here" });

		const second = createHarness({ state });
		expect(second.state.mode).toBe("confirm");
		expect(second.state.stats.scans).toBe(1);
	});

	it("registers the command and every hook it relies on", () => {
		const events: string[] = [];
		createSecretScanner(createState())({
			on: (name: string) => events.push(name),
			registerCommand: vi.fn(),
		} as any);
		expect(events.sort()).toEqual(
			[
				"before_agent_start",
				"before_provider_request",
				"context",
				"session_shutdown",
				"session_start",
				"tool_call",
				"tool_result",
			].sort(),
		);
	});
});

describe("session lifecycle", () => {
	it("clears session decisions and placeholders on a new session, but keeps them on reload", async () => {
		const h = createHarness();
		h.state.sessionWhitelistHashes.add("sha256:x");
		h.state.emittedPlaceholders.add("[REDACTED:X]");

		h.hook("session_start")({ reason: "reload" }, h.ctx);
		expect(h.state.sessionWhitelistHashes.size).toBe(1);
		expect(h.state.emittedPlaceholders.size).toBe(1);

		h.hook("session_start")({ reason: "new" }, h.ctx);
		expect(h.state.sessionWhitelistHashes.size).toBe(0);
		expect(h.state.emittedPlaceholders.size).toBe(0);
	});

	it("clears caches, decisions, and the footer on shutdown", async () => {
		const h = createHarness();
		await h.read(githubPat());
		h.state.sessionWhitelistHashes.add("sha256:x");

		h.hook("session_shutdown")({ reason: "quit" }, h.ctx);

		expect(h.state.textCache.size).toBe(0);
		expect(h.state.sessionWhitelistHashes.size).toBe(0);
		expect(h.state.emittedPlaceholders.size).toBe(0);
		expect(h.state.redactionFlash).toBeNull();
		expect(h.ctx.ui.setStatus).toHaveBeenLastCalledWith("secret-scanner", undefined);
	});
});

describe("modes", () => {
	it("does nothing at all when off", async () => {
		const h = createHarness();
		await h.run("off");

		expect(await h.read(githubPat())).toBeUndefined();
		expect(await h.provider({ p: githubPat() })).toBeUndefined();
		expect(h.hook("context")({ messages: [githubPat()] }, h.ctx)).toBeUndefined();
		expect(h.hook("before_agent_start")({ systemPrompt: "BASE" }, h.ctx)).toBeUndefined();
		expect(h.state.stats.scans).toBe(0);
	});

	it("counts findings in warn mode without changing content", async () => {
		const h = createHarness();
		await h.run("warn");

		expect(await h.read(githubPat())).toBeUndefined();
		expect(await h.provider({ p: githubPat() })).toBeUndefined();
		expect(h.hook("context")({ messages: [githubPat()] }, h.ctx)).toBeUndefined();
		expect(h.state.stats.findingsTotal).toBeGreaterThan(0);
		expect(h.state.stats.redactions).toBe(0);
		expect(h.state.emittedPlaceholders.size).toBe(0);
	});
});

describe("context hook", () => {
	it("sanitizes history in redact mode", () => {
		const h = createHarness();
		const result = h.hook("context")({ messages: [{ role: "user", content: githubPat() }] }, h.ctx);

		expect(result.messages[0].content).toContain("[REDACTED:");
		expect(h.state.stats.redactions).toBe(1);
	});

	it("leaves history to the provider hook in confirm mode", async () => {
		const h = createHarness();
		await h.run("confirm");

		expect(h.hook("context")({ messages: [githubPat()] }, h.ctx)).toBeUndefined();
		expect(h.select).not.toHaveBeenCalled();
	});

	it("does not count the same history twice across turns", () => {
		const h = createHarness();
		const messages = [{ role: "user", content: githubPat() }];
		h.hook("context")({ messages }, h.ctx);
		h.hook("context")({ messages: [...messages, { role: "user", content: "next" }] }, h.ctx);

		expect(h.state.stats.findingsTotal).toBe(1);
		expect(h.state.stats.redactions).toBe(1);
	});
});

describe("tool result scanning", () => {
	it("scans results of every tool, not only read and bash", async () => {
		const h = createHarness();
		const result = await h.hook("tool_result")(
			{
				toolName: "grep",
				input: { pattern: "TOKEN" },
				content: [{ type: "text", text: `a.env:1:${githubPat()}` }],
			},
			h.ctx,
		);

		expect(result.content[0].text).toContain("[REDACTED:");
	});

	it("leaves image content untouched", async () => {
		const h = createHarness();
		const image = { type: "image", data: "aGVsbG8=", mimeType: "image/png" };
		const result = await h.hook("tool_result")(
			{ toolName: "read", input: { path: "a.png" }, content: [image, { type: "text", text: githubPat() }] },
			h.ctx,
		);

		expect(result.content[0]).toBe(image);
		expect(result.content[1].text).toContain("[REDACTED:");
	});

	it("skips read results from allowlisted paths but still scans other tools", async () => {
		const cwd = tempDir({ ".secret-scanner.json": JSON.stringify({ whitelist: { paths: ["^fixtures/"] } }) });
		const h = createHarness({ cwd });

		expect(await h.read(githubPat(), "fixtures/token.txt")).toBeUndefined();
		const bash = await h.hook("tool_result")(
			{
				toolName: "bash",
				input: { command: "cat fixtures/token.txt" },
				content: [{ type: "text", text: githubPat() }],
			},
			h.ctx,
		);
		expect(bash.content[0].text).toContain("[REDACTED:");
	});

	it("skips entropy detection, but not named rules, for lockfiles", async () => {
		const h = createHarness();
		// Mixed-charset value that entropy detection redacts in ordinary files.
		const opaque = ["Zx9wQp7Vm4Kd2Rt8+Yb6Nc1", "Hs5Jg3Lf0Eu-_x"].join("");
		const lockText = `"value": "${opaque}"\n`;

		const ordinary = await h.read(lockText, "notes.txt");
		const lock = await h.read(lockText, "devenv.lock");
		const leaked = await h.read(githubPat(), "flake.lock");

		expect(ordinary.content[0].text).toContain("[REDACTED:HIGH-ENTROPY");
		expect(lock).toBeUndefined();
		expect(leaked.content[0].text).toContain("[REDACTED:");
	});
});

describe("feedback", () => {
	it("counts report-only entropy findings separately from redactable findings", async () => {
		const h = createHarness();
		// A SHA-256 under a generic metadata key is reported, never replaced.
		await h.read(`digest: ${createHash("sha256").update("artifact").digest("hex")}`);

		expect(h.state.stats.reported).toBe(1);
		expect(h.state.stats.findingsTotal).toBe(0);
		expect(h.state.stats.byType).toEqual({});
	});

	it("flashes new redactions in the footer and reverts after the timeout", async () => {
		vi.useFakeTimers();
		const h = createHarness();
		await h.read(githubPat());

		expect(h.lastStatus()).toBe("🔐 REDACTED 1 secret • read result • total:1");
		vi.advanceTimersByTime(REDACTION_FLASH_MS);
		expect(h.lastStatus()).toBe("🔍 secret-scanner: redact+entropy • 1 redacted");
	});

	it("logs exact values only in debug mode and only for fresh redactions", async () => {
		const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
		const h = createHarness();
		await h.provider({ p: githubPat() });
		expect(warn).not.toHaveBeenCalled();

		await h.run("debug on");
		await h.provider({ p: githubPat("ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890") });
		await h.provider({ p: githubPat("ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890") });

		expect(warn).toHaveBeenCalledTimes(1);
		expect(warn.mock.calls[0]?.[0]).toContain(githubPat("ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"));
	});
});

describe("confirm mode", () => {
	it("supports per-value redact and allow-once decisions", async () => {
		const h = createHarness();
		await h.run("confirm");

		const providerSecret = githubPat();
		h.select.mockResolvedValueOnce("Redact");
		const providerResult = await h.provider({ prompt: providerSecret });
		expect(h.select.mock.calls[0]?.[0]).toContain(`Value: "${providerSecret}"`);
		expect(providerResult.prompt).toContain("[REDACTED:");

		const readSecret = githubPat("ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890");
		h.select.mockResolvedValueOnce("Allow once");
		const readResult = await h.read(readSecret, "fixture.txt");
		expect(readResult.content[0].text).toBe(readSecret);

		h.select.mockResolvedValueOnce("Redact");
		await h.hook("tool_result")(
			{ toolName: "bash", input: { command: "print-secret" }, content: [{ type: "text", text: readSecret }] },
			h.ctx,
		);
		expect(h.select).toHaveBeenCalledTimes(3);
		expect(h.confirm).not.toHaveBeenCalled();
	});

	it("remembers an allowed value for the current session, including extension reloads", async () => {
		const h = createHarness();
		await h.run("confirm");
		const secret = githubPat();
		h.select.mockResolvedValueOnce("Allow for this session");

		const first = await h.provider({ prompt: secret });
		h.hook("session_start")({ reason: "reload" }, h.ctx);
		const second = await h.provider({ prompt: secret });

		expect(first).toBeUndefined();
		expect(second).toBeUndefined();
		expect(h.select).toHaveBeenCalledTimes(1);
	});

	it("shares one allow-once decision across tool-result content items", async () => {
		const h = createHarness();
		await h.run("confirm");
		const secret = githubPat();
		h.select.mockResolvedValueOnce("Allow once");

		const result = await h.hook("tool_result")(
			{
				toolName: "bash",
				input: { command: "print-secret" },
				content: [
					{ type: "text", text: secret },
					{ type: "text", text: `again: ${secret}` },
				],
			},
			h.ctx,
		);

		expect(result.content[0].text).toBe(secret);
		expect(result.content[1].text).toContain(secret);
		expect(h.select).toHaveBeenCalledTimes(1);
	});

	it("persists only a fingerprint for project decisions", async () => {
		const cwd = tempDir();
		const h = createHarness({ cwd });
		await h.run("confirm");
		const secret = githubPat();
		h.select.mockResolvedValueOnce("Always allow in this project");

		expect(await h.provider({ prompt: secret })).toBeUndefined();
		const localConfig = readFileSync(join(cwd, ".secret-scanner.local.json"), "utf-8");
		expect(localConfig).toContain("sha256:");
		expect(localConfig).not.toContain(secret);

		const next = createHarness({ cwd });
		await next.run("confirm");
		expect(await next.provider({ prompt: secret })).toBeUndefined();
		expect(next.select).not.toHaveBeenCalled();
	});

	it("keeps the value redacted and explains why when a project decision cannot be saved", async () => {
		const cwd = tempDir({ ".secret-scanner.local.json": "{ not json" });
		const h = createHarness({ cwd });
		await h.run("confirm");
		h.select.mockResolvedValueOnce("Always allow in this project");

		const result = await h.provider({ prompt: githubPat() });

		expect(result.prompt).toContain("[REDACTED:");
		expect(h.lastNotify()?.[0]).toContain("Could not save .secret-scanner.local.json");
		expect(h.lastNotify()?.[1]).toBe("error");
	});

	it("redacts on cancellation and when no UI is available", async () => {
		const h = createHarness();
		await h.run("confirm");
		const secret = githubPat();

		h.select.mockResolvedValueOnce(undefined);
		const cancelled = await h.provider({ prompt: secret });
		expect(cancelled.prompt).toContain("[REDACTED:");

		const headless = createHarness({ hasUI: false });
		await headless.run("confirm");
		const nonInteractive = await headless.provider({ prompt: githubPat("ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890") });
		expect(nonInteractive.prompt).toContain("[REDACTED:");
		expect(headless.select).not.toHaveBeenCalled();
		expect(h.confirm).not.toHaveBeenCalled();
	});

	it("does not ask again when history re-sends an allowed-once value", async () => {
		const h = createHarness();
		await h.run("confirm");
		const secret = githubPat();
		h.select.mockResolvedValue("Allow once");

		await h.read(secret, "a.txt");
		const turn1 = await h.provider({ messages: [secret] });
		const turn2 = await h.provider({ messages: [secret, "next question"] });

		expect(turn1).toBeUndefined();
		expect(turn2).toBeUndefined();
		expect(h.select).toHaveBeenCalledTimes(1);
	});

	it("keeps a redact decision for re-sent history without asking again", async () => {
		const h = createHarness();
		await h.run("confirm");
		const secret = githubPat();
		h.select.mockResolvedValue("Redact");

		const turn1 = await h.provider({ messages: [secret] });
		const turn2 = await h.provider({ messages: [secret, "more"] });

		expect(turn1.messages[0]).toContain("[REDACTED:");
		expect(turn2.messages[0]).toContain("[REDACTED:");
		expect(h.select).toHaveBeenCalledTimes(1);
	});

	it("recovers from a stale lock left by a crashed process", async () => {
		const cwd = tempDir();
		const lockPath = join(cwd, ".secret-scanner.local.json.lock");
		writeFileSync(lockPath, "");
		const old = new Date(Date.now() - 60_000);
		utimesSync(lockPath, old, old);

		const h = createHarness({ cwd });
		await h.run("confirm");
		h.select.mockResolvedValueOnce("Always allow in this project");

		expect(await h.provider({ p: githubPat() })).toBeUndefined();
		expect(readFileSync(join(cwd, ".secret-scanner.local.json"), "utf-8")).toContain("sha256:");
	});
});

describe("agent guidance", () => {
	async function redactedRead(text: string, path = ".env") {
		const h = createHarness();
		const result = await h.read(text, path);
		return { ...h, redacted: result.content[0].text as string };
	}

	it("blocks edits and writes that would copy an emitted placeholder over real values", async () => {
		const secret = githubPat();
		const h = await redactedRead(`GITHUB_TOKEN=${secret}\n`);
		writeFileSync(join(h.ctx.cwd, ".env"), `GITHUB_TOKEN=${secret}\n`);
		const placeholder = /\[REDACTED:[^\]]+\]/.exec(h.redacted)![0];

		const edit = h.hook("tool_call")(
			{
				toolName: "edit",
				input: { path: ".env", edits: [{ oldText: h.redacted, newText: `${h.redacted}X=1\n` }] },
			},
			h.ctx,
		);
		const write = h.hook("tool_call")(
			{ toolName: "write", input: { path: "copy.env", content: h.redacted } },
			h.ctx,
		);

		expect(edit.block).toBe(true);
		expect(edit.reason).toContain(placeholder);
		expect(write.block).toBe(true);
	});

	it("allows edits to files that literally contain the placeholder", async () => {
		const h = await redactedRead(`token=${githubPat()}\n`);
		writeFileSync(join(h.ctx.cwd, "notes.md"), `Example output: ${h.redacted}`);

		const edit = h.hook("tool_call")(
			{
				toolName: "edit",
				input: { path: "notes.md", edits: [{ oldText: h.redacted, newText: h.redacted.trim() }] },
			},
			h.ctx,
		);

		expect(edit).toBeUndefined();
	});

	it("does not guard while the scanner is off", async () => {
		const h = await redactedRead(`token=${githubPat()}\n`);
		await h.run("off");

		expect(
			h.hook("tool_call")({ toolName: "write", input: { path: "x", content: h.redacted } }, h.ctx),
		).toBeUndefined();
	});

	it("explains placeholders in the system prompt only while redaction is active", async () => {
		const h = createHarness();
		const active = h.hook("before_agent_start")({ systemPrompt: "BASE" }, h.ctx);
		await h.run("confirm");
		const confirming = h.hook("before_agent_start")({ systemPrompt: "BASE" }, h.ctx);
		await h.run("warn");
		const inactive = h.hook("before_agent_start")({ systemPrompt: "BASE" }, h.ctx);

		expect(active.systemPrompt).toBe(`BASE\n\n${REDACTION_NOTE}`);
		expect(confirming.systemPrompt).toBe(`BASE\n\n${REDACTION_NOTE}`);
		expect(inactive).toBeUndefined();
	});
});
