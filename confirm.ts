/**
 * Confirm mode: ask about each unique detected value once per operation.
 * Cancelling a dialog fails safe to redaction.
 */

import { LOCAL_CONFIG_NAME } from "./config.ts";
import { applyConfig } from "./feedback.ts";
import { persistProjectFingerprint } from "./local-store.ts";
import { formatConfirmFindings } from "./scanner.ts";
import { secretFingerprint } from "./state.ts";

import type { ProjectContext } from "./feedback.ts";
import type { Finding } from "./scanner.ts";
import type { ScannerState } from "./state.ts";

export const CONFIRM_REDACT = "Redact";
export const CONFIRM_ALLOW_ONCE = "Allow once";
export const CONFIRM_ALLOW_SESSION = "Allow for this session";
export const CONFIRM_ALLOW_PROJECT = "Always allow in this project";

/**
 * Ask about each unique value. Session and project decisions are stored
 * immediately; the returned fingerprints are allowed for this operation only.
 */
export async function chooseConfirmActions(
	state: ScannerState,
	ctx: ProjectContext,
	findings: Finding[],
	location: string,
): Promise<Set<string>> {
	const allowOnce = new Set<string>();
	const seen = new Set<string>();
	for (const finding of findings) {
		const fingerprint = secretFingerprint(finding.value);
		if (seen.has(fingerprint)) continue;
		seen.add(fingerprint);

		const choice = await ctx.ui.select(
			`🔐 Potential secret in ${location}\n\n${formatConfirmFindings([finding])}`,
			[CONFIRM_REDACT, CONFIRM_ALLOW_ONCE, CONFIRM_ALLOW_SESSION, CONFIRM_ALLOW_PROJECT],
		);
		if (choice === CONFIRM_ALLOW_ONCE) {
			allowOnce.add(fingerprint);
		} else if (choice === CONFIRM_ALLOW_SESSION) {
			state.sessionWhitelistHashes.add(fingerprint);
		} else if (choice === CONFIRM_ALLOW_PROJECT) {
			try {
				await persistProjectFingerprint(ctx.cwd, fingerprint);
				applyConfig(state, ctx);
				ctx.ui.notify(`Saved fingerprint to ${LOCAL_CONFIG_NAME}; plaintext was not stored`, "info");
			} catch (error) {
				const reason = error instanceof Error ? error.message : String(error);
				ctx.ui.notify(`Could not save ${LOCAL_CONFIG_NAME}; keeping the value redacted: ${reason}`, "error");
			}
		}
		// Escape/cancel returns undefined and therefore fails safe to redaction.
	}
	return allowOnce;
}
