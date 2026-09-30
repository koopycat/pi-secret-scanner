import { mkdtempSync, readFileSync, rmSync } from "node:fs";
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
