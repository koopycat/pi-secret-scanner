import { homedir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { blockReason, foreignPlaceholders, resolveToolPath } from "./placeholder-guard.ts";

const P = "[REDACTED:GITHUB_PERSONAL_ACCESS_TOKEN_(CLASSIC)]";
const emitted = new Set([P]);
const noFile = () => "";

describe("foreignPlaceholders", () => {
	it("flags an emitted placeholder in write content for a new file", () => {
		expect(
			foreignPlaceholders({ toolName: "write", input: { path: "a", content: `x=${P}` } }, emitted, "/p", noFile),
		).toEqual([P]);
	});

	it("flags emitted placeholders in edit oldText or newText", () => {
		const edit = (oldText: string, newText: string) => ({
			toolName: "edit",
			input: { path: "a", edits: [{ oldText, newText }] },
		});
		expect(foreignPlaceholders(edit(`x=${P}`, "x=1"), emitted, "/p", noFile)).toEqual([P]);
		expect(foreignPlaceholders(edit("x=1", `x=${P}`), emitted, "/p", noFile)).toEqual([P]);
	});

	it("reports each placeholder once", () => {
		const content = `${P}\n${P}`;
		expect(
			foreignPlaceholders({ toolName: "write", input: { path: "a", content } }, emitted, "/p", noFile),
		).toEqual([P]);
	});

	it("allows placeholders the file already contains literally", () => {
		const call = { toolName: "write", input: { path: "a", content: `docs: ${P}` } };
		expect(foreignPlaceholders(call, emitted, "/p", () => `old docs: ${P}`)).toEqual([]);
	});

	it("ignores placeholders the scanner never emitted", () => {
		const call = { toolName: "write", input: { path: "a", content: "[REDACTED:AWS_ACCESS_KEY_ID]" } };
		expect(foreignPlaceholders(call, emitted, "/p", noFile)).toEqual([]);
	});

	it("does nothing before any redaction, for other tools, or for malformed input", () => {
		const content = `x=${P}`;
		expect(
			foreignPlaceholders({ toolName: "write", input: { path: "a", content } }, new Set(), "/p", noFile),
		).toEqual([]);
		expect(foreignPlaceholders({ toolName: "bash", input: { command: content } }, emitted, "/p", noFile)).toEqual(
			[],
		);
		expect(foreignPlaceholders({ toolName: "write", input: { content } }, emitted, "/p", noFile)).toEqual([]);
		expect(
			foreignPlaceholders({ toolName: "edit", input: { path: "a", edits: "nope" } }, emitted, "/p", noFile),
		).toEqual([]);
		expect(
			foreignPlaceholders(
				{ toolName: "edit", input: { path: "a", edits: [{ oldText: 1 }] } },
				emitted,
				"/p",
				noFile,
			),
		).toEqual([]);
	});

	it("reads the resolved target path", () => {
		const seen: string[] = [];
		foreignPlaceholders(
			{ toolName: "write", input: { path: "src/.env", content: P } },
			emitted,
			"/proj",
			(path) => {
				seen.push(path);
				return "";
			},
		);
		expect(seen).toEqual(["/proj/src/.env"]);
	});
});

describe("resolveToolPath", () => {
	it("resolves relative, absolute, home, and @-prefixed paths like Pi", () => {
		expect(resolveToolPath("/proj", "a/b")).toBe("/proj/a/b");
		expect(resolveToolPath("/proj", "/etc/x")).toBe("/etc/x");
		expect(resolveToolPath("/proj", "~/x")).toBe(join(homedir(), "x"));
		expect(resolveToolPath("/proj", "@src/x")).toBe("/proj/src/x");
	});
});

describe("blockReason", () => {
	it("names the placeholder and the path and tells the model what to do instead", () => {
		const reason = blockReason("edit", ".env", [P]);
		expect(reason).toContain(P);
		expect(reason).toContain(".env");
		expect(reason).toMatch(/excludes the redacted lines/);
	});
});
