import { mkdtempSync, readFileSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

import secretScanner from "./index.ts";

function githubPat(suffix = "abcdefghijklmnopqrstuvwxyz1234567890"): string {
	return `ghp_${suffix}`;
}

const temporaryDirectories: string[] = [];

afterEach(() => {
	for (const directory of temporaryDirectories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function createHarness(cwd?: string) {
	if (!cwd) {
		cwd = mkdtempSync(join(tmpdir(), "pi-secret-scanner-test-"));
		temporaryDirectories.push(cwd);
	}
	const handlers = new Map<string, (...args: any[]) => any>();
	const commands = new Map<string, { handler: (...args: any[]) => Promise<void> }>();
	const pi = {
		on: (name: string, handler: (...args: any[]) => any) => {
			handlers.set(name, handler);
		},
		registerCommand: (name: string, command: { handler: (...args: any[]) => Promise<void> }) => {
			commands.set(name, command);
		},
	};
	secretScanner(pi as any);

	const confirm = vi.fn<(...args: string[]) => Promise<boolean>>();
	const select = vi.fn<(...args: any[]) => Promise<string | undefined>>();
	const ctx = {
		cwd,
		hasUI: true,
		mode: "tui",
		ui: {
			confirm,
			select,
			notify: vi.fn(),
			setStatus: vi.fn(),
			theme: { fg: (_color: string, text: string) => text },
		},
	};

	handlers.get("session_start")!({ reason: "startup" }, ctx);
	return { handlers, commands, confirm, select, ctx };
}

describe("confirm mode", () => {
	it("supports per-value redact and allow-once decisions", async () => {
		const { handlers, commands, confirm, select, ctx } = createHarness();
		await commands.get("secret-scanner")!.handler("confirm", ctx);

		const providerSecret = githubPat();
		select.mockResolvedValueOnce("Redact");
		const providerResult = await handlers.get("before_provider_request")!(
			{ payload: { prompt: providerSecret } },
			ctx,
		);
		expect(select.mock.calls[0]?.[0]).toContain(`Value: "${providerSecret}"`);
		expect(providerResult.prompt).toContain("[REDACTED:");

		const readSecret = githubPat("ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890");
		select.mockResolvedValueOnce("Allow once");
		const readResult = await handlers.get("tool_result")!(
			{ toolName: "read", input: { path: "fixture.txt" }, content: [{ type: "text", text: readSecret }] },
			ctx,
		);
		expect(readResult.content[0].text).toBe(readSecret);

		select.mockResolvedValueOnce("Redact");
		await handlers.get("tool_result")!(
			{ toolName: "bash", input: { command: "print-secret" }, content: [{ type: "text", text: readSecret }] },
			ctx,
		);
		expect(select).toHaveBeenCalledTimes(3);
		expect(confirm).not.toHaveBeenCalled();
	});

	it("remembers an allowed value for the current session, including extension reloads", async () => {
		const { handlers, commands, select, ctx } = createHarness();
		await commands.get("secret-scanner")!.handler("confirm", ctx);
		const secret = githubPat();
		select.mockResolvedValueOnce("Allow for this session");

		const first = await handlers.get("before_provider_request")!({ payload: { prompt: secret } }, ctx);
		handlers.get("session_start")!({ reason: "reload" }, ctx);
		const second = await handlers.get("before_provider_request")!({ payload: { prompt: secret } }, ctx);

		expect(first).toBeUndefined();
		expect(second).toBeUndefined();
		expect(select).toHaveBeenCalledTimes(1);
	});

	it("shares one allow-once decision across tool-result content items", async () => {
		const { handlers, commands, select, ctx } = createHarness();
		await commands.get("secret-scanner")!.handler("confirm", ctx);
		const secret = githubPat();
		select.mockResolvedValueOnce("Allow once");

		const result = await handlers.get("tool_result")!(
			{
				toolName: "bash",
				input: { command: "print-secret" },
				content: [
					{ type: "text", text: secret },
					{ type: "text", text: `again: ${secret}` },
				],
			},
			ctx,
		);

		expect(result.content[0].text).toBe(secret);
		expect(result.content[1].text).toContain(secret);
		expect(select).toHaveBeenCalledTimes(1);
	});

	it("persists only a fingerprint for project decisions", async () => {
		const cwd = mkdtempSync(join(tmpdir(), "pi-secret-scanner-test-"));
		temporaryDirectories.push(cwd);
		const { handlers, commands, select, ctx } = createHarness(cwd);
		await commands.get("secret-scanner")!.handler("confirm", ctx);
		const secret = githubPat();
		select.mockResolvedValueOnce("Always allow in this project");

		expect(await handlers.get("before_provider_request")!({ payload: { prompt: secret } }, ctx)).toBeUndefined();
		const localConfig = readFileSync(join(cwd, ".secret-scanner.local.json"), "utf-8");
		expect(localConfig).toContain("sha256:");
		expect(localConfig).not.toContain(secret);

		const next = createHarness(cwd);
		await next.commands.get("secret-scanner")!.handler("confirm", next.ctx);
		expect(
			await next.handlers.get("before_provider_request")!({ payload: { prompt: secret } }, next.ctx),
		).toBeUndefined();
		expect(next.select).not.toHaveBeenCalled();
	});

	it("redacts on cancellation and when no UI is available", async () => {
		const { handlers, commands, confirm, select, ctx } = createHarness();
		await commands.get("secret-scanner")!.handler("confirm", ctx);
		const secret = githubPat();

		select.mockResolvedValueOnce(undefined);
		const cancelled = await handlers.get("before_provider_request")!({ payload: { prompt: secret } }, ctx);
		expect(cancelled.prompt).toContain("[REDACTED:");

		const nonInteractive = await handlers.get("before_provider_request")!(
			{ payload: { prompt: secret } },
			{ ...ctx, hasUI: false, mode: "print" },
		);
		expect(nonInteractive.prompt).toContain("[REDACTED:");
		expect(confirm).not.toHaveBeenCalled();
	});
});

describe("confirm decisions across turns", () => {
	it("does not ask again when history re-sends an allowed-once value", async () => {
		const { handlers, commands, select, ctx } = createHarness();
		await commands.get("secret-scanner")!.handler("confirm", ctx);
		const secret = githubPat();
		select.mockResolvedValue("Allow once");

		await handlers.get("tool_result")!(
			{ toolName: "read", input: { path: "a.txt" }, content: [{ type: "text", text: secret }] },
			ctx,
		);
		const turn1 = await handlers.get("before_provider_request")!({ payload: { messages: [secret] } }, ctx);
		const turn2 = await handlers.get("before_provider_request")!(
			{ payload: { messages: [secret, "next question"] } },
			ctx,
		);

		expect(turn1).toBeUndefined();
		expect(turn2).toBeUndefined();
		expect(select).toHaveBeenCalledTimes(1);
	});

	it("keeps a redact decision for re-sent history without asking again", async () => {
		const { handlers, commands, select, ctx } = createHarness();
		await commands.get("secret-scanner")!.handler("confirm", ctx);
		const secret = githubPat();
		select.mockResolvedValue("Redact");

		const turn1 = await handlers.get("before_provider_request")!({ payload: { messages: [secret] } }, ctx);
		const turn2 = await handlers.get("before_provider_request")!({ payload: { messages: [secret, "more"] } }, ctx);

		expect(turn1.messages[0]).toContain("[REDACTED:");
		expect(turn2.messages[0]).toContain("[REDACTED:");
		expect(select).toHaveBeenCalledTimes(1);
	});
});

describe("project decisions", () => {
	it("recovers from a stale lock left by a crashed process", async () => {
		const cwd = mkdtempSync(join(tmpdir(), "pi-secret-scanner-test-"));
		temporaryDirectories.push(cwd);
		const lockPath = join(cwd, ".secret-scanner.local.json.lock");
		writeFileSync(lockPath, "");
		const old = new Date(Date.now() - 60_000);
		utimesSync(lockPath, old, old);

		const { handlers, commands, select, ctx } = createHarness(cwd);
		await commands.get("secret-scanner")!.handler("confirm", ctx);
		select.mockResolvedValueOnce("Always allow in this project");

		expect(await handlers.get("before_provider_request")!({ payload: { p: githubPat() } }, ctx)).toBeUndefined();
		expect(readFileSync(join(cwd, ".secret-scanner.local.json"), "utf-8")).toContain("sha256:");
	});
});

describe("configuration loading", () => {
	function projectWith(files: Record<string, string>): string {
		const cwd = mkdtempSync(join(tmpdir(), "pi-secret-scanner-test-"));
		temporaryDirectories.push(cwd);
		for (const [name, content] of Object.entries(files)) writeFileSync(join(cwd, name), content);
		return cwd;
	}

	it("merges .gitleaks.toml with .secret-scanner.json", async () => {
		const secret = githubPat();
		const cwd = projectWith({
			".gitleaks.toml": '[allowlist]\nstopwords = ["unrelated"]\n',
			".secret-scanner.json": JSON.stringify({ whitelist: { values: [secret] } }),
		});
		const { handlers, commands, ctx } = createHarness(cwd);
		await commands.get("secret-scanner")!.handler("redact", ctx);

		expect(await handlers.get("before_provider_request")!({ payload: { p: secret } }, ctx)).toBeUndefined();
	});

	it("matches gitleaks stopwords as case-insensitive substrings", async () => {
		const cwd = projectWith({ ".gitleaks.toml": '[allowlist]\nstopwords = ["klmnop"]\n' });
		const { handlers, commands, ctx } = createHarness(cwd);
		await commands.get("secret-scanner")!.handler("redact", ctx);

		expect(await handlers.get("before_provider_request")!({ payload: { p: githubPat() } }, ctx)).toBeUndefined();
	});

	it("drops only invalid regexes and reports them in the UI", async () => {
		const secret = githubPat();
		const cwd = projectWith({
			".secret-scanner.json": JSON.stringify({ whitelist: { values: [secret], value_regexes: ["(unclosed"] } }),
		});
		const { handlers, commands, ctx } = createHarness(cwd);
		await commands.get("secret-scanner")!.handler("redact", ctx);

		expect(ctx.ui.notify).toHaveBeenCalledWith(
			expect.stringContaining('ignored invalid regex "(unclosed"'),
			"error",
		);
		expect(await handlers.get("before_provider_request")!({ payload: { p: secret } }, ctx)).toBeUndefined();
	});
});

describe("commands", () => {
	it("rejects unknown subcommands instead of showing status", async () => {
		const { commands, ctx } = createHarness();
		await commands.get("secret-scanner")!.handler("confrim", ctx);

		expect(ctx.ui.notify).toHaveBeenLastCalledWith(
			expect.stringContaining("Unknown secret scanner command"),
			"warning",
		);
	});
});

describe("agent guidance", () => {
	async function redactedRead(text: string) {
		const harness = createHarness();
		await harness.commands.get("secret-scanner")!.handler("redact", harness.ctx);
		const result = await harness.handlers.get("tool_result")!(
			{ toolName: "read", input: { path: ".env" }, content: [{ type: "text", text }] },
			harness.ctx,
		);
		return { ...harness, redacted: result.content[0].text as string };
	}

	it("blocks edits and writes that would copy an emitted placeholder over real values", async () => {
		const secret = githubPat();
		const { handlers, ctx, redacted } = await redactedRead(`GITHUB_TOKEN=${secret}\n`);
		writeFileSync(join(ctx.cwd, ".env"), `GITHUB_TOKEN=${secret}\n`);
		const placeholder = redacted.match(/\[REDACTED:[^\]]+\]/)![0];

		const edit = handlers.get("tool_call")!(
			{ toolName: "edit", input: { path: ".env", edits: [{ oldText: redacted, newText: `${redacted}X=1\n` }] } },
			ctx,
		);
		const write = handlers.get("tool_call")!(
			{ toolName: "write", input: { path: "copy.env", content: redacted } },
			ctx,
		);

		expect(edit.block).toBe(true);
		expect(edit.reason).toContain(placeholder);
		expect(write.block).toBe(true);
	});

	it("allows edits to files that literally contain the placeholder", async () => {
		const { handlers, ctx, redacted } = await redactedRead(`token=${githubPat()}\n`);
		writeFileSync(join(ctx.cwd, "notes.md"), `Example output: ${redacted}`);

		const edit = handlers.get("tool_call")!(
			{ toolName: "edit", input: { path: "notes.md", edits: [{ oldText: redacted, newText: redacted.trim() }] } },
			ctx,
		);

		expect(edit).toBeUndefined();
	});

	it("explains placeholders in the system prompt only while redaction is active", async () => {
		const { handlers, commands, ctx } = createHarness();
		await commands.get("secret-scanner")!.handler("redact", ctx);
		const active = handlers.get("before_agent_start")!({ systemPrompt: "BASE" }, ctx);
		await commands.get("secret-scanner")!.handler("warn", ctx);
		const inactive = handlers.get("before_agent_start")!({ systemPrompt: "BASE" }, ctx);

		expect(active.systemPrompt).toMatch(/^BASE\n\nSecret scanner: .*\[REDACTED:TYPE\]/s);
		expect(inactive).toBeUndefined();
	});
});

describe("tool result scanning", () => {
	it("scans results of every tool, not only read and bash", async () => {
		const { handlers, commands, ctx } = createHarness();
		await commands.get("secret-scanner")!.handler("redact", ctx);

		const result = await handlers.get("tool_result")!(
			{
				toolName: "grep",
				input: { pattern: "TOKEN" },
				content: [{ type: "text", text: `a.env:1:${githubPat()}` }],
			},
			ctx,
		);

		expect(result.content[0].text).toContain("[REDACTED:");
	});

	it("skips entropy detection, but not named rules, for lockfiles", async () => {
		const { handlers, commands, ctx } = createHarness();
		await commands.get("secret-scanner")!.handler("redact", ctx);
		// Mixed-charset value that entropy detection redacts in ordinary files.
		const opaque = ["Zx9wQp7Vm4Kd2Rt8+Yb6Nc1", "Hs5Jg3Lf0Eu-_x"].join("");
		const lockText = `"value": "${opaque}"\n`;
		const readAs = (path: string, text: string) =>
			handlers.get("tool_result")!({ toolName: "read", input: { path }, content: [{ type: "text", text }] }, ctx);

		const ordinary = await readAs("notes.txt", lockText);
		const lock = await readAs("devenv.lock", lockText);
		const leaked = await readAs("flake.lock", githubPat());

		expect(ordinary.content[0].text).toContain("[REDACTED:HIGH-ENTROPY");
		expect(lock).toBeUndefined();
		expect(leaked.content[0].text).toContain("[REDACTED:");
	});
});
