import { describe, expect, it, vi } from "vitest";

import secretScanner from "./index.ts";

function githubPat(suffix = "abcdefghijklmnopqrstuvwxyz1234567890"): string {
	return `ghp_${suffix}`;
}

function createHarness() {
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
	const ctx = {
		cwd: process.cwd(),
		hasUI: true,
		mode: "tui",
		ui: {
			confirm,
			notify: vi.fn(),
			setStatus: vi.fn(),
			theme: { fg: (_color: string, text: string) => text },
		},
	};

	return { handlers, commands, confirm, ctx };
}

describe("confirm mode", () => {
	it("shows exact values for provider, read, and bash decisions", async () => {
		const { handlers, commands, confirm, ctx } = createHarness();
		await commands.get("secret-scanner")!.handler("confirm", ctx);

		const providerSecret = githubPat();
		confirm.mockResolvedValueOnce(true);
		const providerResult = await handlers.get("before_provider_request")!(
			{ payload: { prompt: providerSecret } },
			ctx,
		);
		expect(confirm.mock.calls[0]?.[1]).toContain(`Value: "${providerSecret}"`);
		expect(providerResult.prompt).toContain("[REDACTED:");

		const readSecret = githubPat("ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890");
		confirm.mockResolvedValueOnce(false);
		const readResult = await handlers.get("tool_result")!(
			{ toolName: "read", input: { path: "fixture.txt" }, content: [{ type: "text", text: readSecret }] },
			ctx,
		);
		expect(confirm.mock.calls[1]?.[1]).toContain(`Value: "${readSecret}"`);
		expect(readResult.content[0].text).toBe(readSecret);

		const bashSecret = githubPat("0123456789abcdefghijklmnopqrstuvwxyz");
		confirm.mockResolvedValueOnce(true);
		const bashResult = await handlers.get("tool_result")!(
			{ toolName: "bash", input: { command: "print-secret" }, content: [{ type: "text", text: bashSecret }] },
			ctx,
		);
		expect(confirm.mock.calls[2]?.[0]).toContain("bash output");
		expect(confirm.mock.calls[2]?.[1]).toContain(`Value: "${bashSecret}"`);
		expect(bashResult.content[0].text).toContain("[REDACTED:");
	});

	it("redacts without displaying values when no UI is available", async () => {
		const { handlers, commands, confirm, ctx } = createHarness();
		await commands.get("secret-scanner")!.handler("confirm", ctx);
		const secret = githubPat();

		const result = await handlers.get("before_provider_request")!(
			{ payload: { prompt: secret } },
			{ ...ctx, hasUI: false, mode: "print" },
		);

		expect(confirm).not.toHaveBeenCalled();
		expect(result.prompt).toContain("[REDACTED:");
	});
});
