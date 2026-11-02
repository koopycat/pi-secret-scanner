import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

import secretScanner from "./index.ts";

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

function githubPat(suffix = "abcdefghijklmnopqrstuvwxyz1234567890"): string {
	return `ghp_${suffix}`;
}

const temporaryDirectories: string[] = [];

afterEach(() => {
	for (const directory of temporaryDirectories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function createHarness(cwd?: string, factory = secretScanner, reason = "startup") {
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
	// This harness implements only the registration APIs used by the extension.
	const extensionAPI = pi as unknown as ExtensionAPI;
	factory(extensionAPI);

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

	handlers.get("session_start")!({ reason }, ctx);
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
		handlers.get("session_shutdown")!({ reason: "reload" }, ctx);
		vi.resetModules();
		// A static import cannot exercise fresh module initialization during reload.
		const reloaded = await import("./index.ts");
		const next = createHarness(ctx.cwd, reloaded.default, "reload");
		await next.commands.get("secret-scanner")!.handler("confirm", next.ctx);
		const second = await next.handlers.get("before_provider_request")!({ payload: { prompt: secret } }, next.ctx);

		expect(first).toBeUndefined();
		expect(second).toBeUndefined();
		expect(select).toHaveBeenCalledTimes(1);
		expect(next.select).not.toHaveBeenCalled();

		next.handlers.get("session_shutdown")!({ reason: "new" }, next.ctx);
		next.handlers.get("session_start")!({ reason: "new" }, next.ctx);
		const newSession = await next.handlers.get("before_provider_request")!(
			{ payload: { prompt: secret } },
			next.ctx,
		);
		expect(newSession.prompt).toContain("[REDACTED:");
		expect(next.select).toHaveBeenCalledTimes(1);
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

	it.each([false, true])("persists Git-ignored project fingerprints (linked worktree: %s)", async (linked) => {
		// Pi's cwd and Git's root are canonical, including macOS /var aliases.
		const directory = realpathSync(mkdtempSync(join(tmpdir(), "pi-secret-scanner-test-")));
		temporaryDirectories.push(directory);
		const root = join(directory, "repository");
		mkdirSync(root);
		const git = (cwd: string, ...args: string[]) =>
			execFileSync("git", args, { cwd, encoding: "utf-8", stdio: ["ignore", "pipe", "pipe"] }).trim();
		git(root, "init", "--quiet");
		git(
			root,
			"-c",
			"user.name=Test",
			"-c",
			"user.email=test@example.invalid",
			"commit",
			"--allow-empty",
			"--quiet",
			"-m",
			"Test",
		);
		const cwd = linked ? join(directory, "worktree") : root;
		if (linked) git(root, "worktree", "add", "--detach", cwd);
		const { handlers, commands, select, ctx } = createHarness(cwd);
		await commands.get("secret-scanner")!.handler("confirm", ctx);
		const secret = githubPat();
		select.mockResolvedValueOnce("Always allow in this project");

		expect(await handlers.get("before_provider_request")!({ payload: { prompt: secret } }, ctx)).toBeUndefined();
		const localPath = join(cwd, ".secret-scanner.local.json");
		const localConfig = readFileSync(localPath, "utf-8");
		expect(JSON.parse(localConfig).whitelist.value_hashes).toEqual([
			`sha256:${createHash("sha256").update(secret).digest("hex")}`,
		]);
		expect(localConfig).not.toContain(secret);
		expect(statSync(localPath).mode & 0o777).toBe(0o600);
		expect(git(cwd, "check-ignore", ".secret-scanner.local.json")).toBe(".secret-scanner.local.json");

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
