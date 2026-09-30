/**
 * Test harness: a minimal stand-in for Pi's ExtensionAPI and context.
 *
 * Every harness gets a fresh ScannerState, so tests never leak mode,
 * counters, or caches into each other. Temporary directories are removed
 * when the current test finishes.
 */

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { onTestFinished, vi } from "vitest";

import { createSecretScanner } from "../index.ts";
import { createState } from "../state.ts";

import type { ScannerState } from "../state.ts";

type Handler = (...args: any[]) => any;

/** A GitHub classic PAT shape, built by concatenation so this file never matches. */
export function githubPat(suffix = "abcdefghijklmnopqrstuvwxyz1234567890"): string {
	return `ghp_${suffix}`;
}

/** A temporary directory removed after the current test. */
export function tempDir(files: Record<string, string> = {}): string {
	const dir = mkdtempSync(join(tmpdir(), "pi-secret-scanner-test-"));
	onTestFinished(() => {
		rmSync(dir, { recursive: true, force: true });
	});
	for (const [name, content] of Object.entries(files)) writeFileSync(join(dir, name), content);
	return dir;
}

export interface HarnessOptions {
	cwd?: string;
	state?: ScannerState;
	hasUI?: boolean;
	/** Fire session_start on creation (default true). */
	start?: boolean;
}

export function createHarness(options: HarnessOptions = {}) {
	const cwd = options.cwd ?? tempDir();
	const state = options.state ?? createState();
	const handlers = new Map<string, Handler>();
	const commands = new Map<string, { handler: (args: string, ctx: unknown) => Promise<void> }>();
	const pi = {
		on: (name: string, handler: Handler) => {
			handlers.set(name, handler);
		},
		registerCommand: (name: string, command: { handler: (args: string, ctx: unknown) => Promise<void> }) => {
			commands.set(name, command);
		},
	};
	createSecretScanner(state)(pi as any);

	const confirm = vi.fn<(...args: string[]) => Promise<boolean>>();
	const select = vi.fn<(...args: any[]) => Promise<string | undefined>>();
	const ctx = {
		cwd,
		hasUI: options.hasUI ?? true,
		mode: "tui",
		ui: {
			confirm,
			select,
			notify: vi.fn(),
			setStatus: vi.fn(),
			theme: { fg: (_color: string, text: string) => text },
		},
	};

	const hook = (name: string): Handler => {
		const handler = handlers.get(name);
		if (!handler) throw new Error(`no handler registered for ${name}`);
		return handler;
	};
	const run = (args: string) => commands.get("secret-scanner")!.handler(args, ctx);
	const read = (text: string, path = "notes.txt") =>
		hook("tool_result")({ toolName: "read", input: { path }, content: [{ type: "text", text }] }, ctx);
	const provider = (payload: unknown) => hook("before_provider_request")({ payload }, ctx);
	const lastNotify = () => ctx.ui.notify.mock.calls.at(-1) as [string, string] | undefined;
	const lastStatus = () => ctx.ui.setStatus.mock.calls.at(-1)?.[1] as string | undefined;

	if (options.start !== false) hook("session_start")({ reason: "startup" }, ctx);
	return { state, handlers, commands, confirm, select, ctx, hook, run, read, provider, lastNotify, lastStatus };
}
