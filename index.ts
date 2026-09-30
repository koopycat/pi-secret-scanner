/**
 * Secret Scanner Extension
 *
 * Scans outgoing LLM requests and tool results for secrets before they
 * leave the machine. Modes:
 *
 *   redact  – replace secrets with [REDACTED:TYPE] placeholders (default)
 *   warn    – record findings, let the data through unchanged
 *   confirm – ask the user before each redaction (redacts without a UI)
 *   off     – fully disabled, no scanning at all
 *
 * Module map:
 *   hooks.ts             – pi event hooks (where scanning happens)
 *   commands.ts          – the /secret-scanner command
 *   confirm.ts           – confirm-mode dialogs
 *   feedback.ts          – status line, counters, debug log, config problems
 *   state.ts             – mutable state and scan options derived from it
 *   config.ts            – allowlist loading (.gitleaks.toml, .secret-scanner*.json)
 *   local-store.ts       – persisted "Always allow in this project" fingerprints
 *   placeholder-guard.ts – edit/write guard against placeholder write-back
 *   scanner.ts, patterns.ts, entropy.ts, lockfiles.ts – detection
 */

import { registerCommands } from "./commands.ts";
import { registerHooks } from "./hooks.ts";
import { createState } from "./state.ts";

import type { ScannerState } from "./state.ts";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

/** Build an extension factory bound to one state object. */
export function createSecretScanner(state: ScannerState = createState()): (pi: ExtensionAPI) => void {
	return (pi) => {
		registerHooks(pi, state);
		registerCommands(pi, state);
	};
}

// Pi calls the factory again for `/new`, resume, and fork while reusing this
// module, so one shared state keeps the mode and counters for the process.
// `/reload` re-imports the module and therefore starts from the defaults.
export default createSecretScanner(createState());
