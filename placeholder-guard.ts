/**
 * Guards Pi's `edit` and `write` tools against copying redaction
 * placeholders over the real values that still exist on disk.
 *
 * Only placeholders the scanner actually emitted this session count, and
 * only when the target file does not already contain that exact text, so
 * documentation and tests that literally mention placeholders stay editable.
 */

import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { resolve } from "node:path";

const PLACEHOLDER = /\[REDACTED:[^\]\s]+\]/g;

export interface WriteCall {
	toolName: string;
	input: Record<string, unknown>;
}

/** Resolve a tool path the way Pi does: `@` prefix stripped, `~` expanded, relative to cwd. */
export function resolveToolPath(cwd: string, filePath: string): string {
	const expanded = filePath.replace(/^@/, "").replace(/^~(?=$|[/\\])/, homedir());
	return resolve(cwd, expanded);
}

/** Text a write-like tool call would put into the file (or match against it). */
function writtenTexts(call: WriteCall): string[] {
	const texts: unknown[] =
		call.toolName === "write"
			? [call.input.content]
			: Array.isArray(call.input.edits)
				? call.input.edits.flatMap((edit: { oldText?: unknown; newText?: unknown }) => [
						edit.oldText,
						edit.newText,
					])
				: [];
	return texts.filter((text): text is string => typeof text === "string");
}

function readExisting(path: string): string {
	try {
		return readFileSync(path, "utf-8");
	} catch {
		return ""; // New or unreadable file: nothing on disk legitimizes a placeholder.
	}
}

/**
 * Placeholders the call would introduce that stand in for real values, or an
 * empty array when the call is safe.
 */
export function foreignPlaceholders(
	call: WriteCall,
	emitted: ReadonlySet<string>,
	cwd: string,
	readFile: (path: string) => string = readExisting,
): string[] {
	if (emitted.size === 0 || (call.toolName !== "edit" && call.toolName !== "write")) return [];
	if (typeof call.input.path !== "string") return [];

	const used = new Set<string>();
	for (const text of writtenTexts(call)) {
		for (const match of text.matchAll(PLACEHOLDER)) {
			if (emitted.has(match[0])) used.add(match[0]);
		}
	}
	if (used.size === 0) return [];

	const existing = readFile(resolveToolPath(cwd, call.input.path));
	return [...used].filter((placeholder) => !existing.includes(placeholder));
}

export function blockReason(toolName: string, path: string, placeholders: string[]): string {
	return (
		`Blocked by secret scanner: this ${toolName} would write ${placeholders.join(", ")} into ${path}. ` +
		"Placeholders stand in for secret values that were removed before you saw them; the file still holds the real values. " +
		"Do not copy placeholders into files. Choose edit oldText/newText that excludes the redacted lines, " +
		"or ask the user to change the secret themselves."
	);
}
