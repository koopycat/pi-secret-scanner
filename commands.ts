/**
 * The `/secret-scanner` command: status, mode, toggles, and config reload.
 */

import { whitelistSize } from "./config.ts";
import { applyConfig, updateStatus } from "./feedback.ts";
import { SECRET_PATTERNS } from "./patterns.ts";
import { emptyStats } from "./state.ts";

import type { ScannerState } from "./state.ts";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

export const USAGE =
	"Usage: /secret-scanner [off|warn|redact|confirm | entropy on|off | debug on|off | reset | reload]";

const MODES = new Set(["off", "warn", "redact", "confirm"] as const);

function isMode(arg: string): arg is ScannerState["mode"] {
	return (MODES as ReadonlySet<string>).has(arg);
}

export function formatStatus(state: ScannerState): string {
	const { stats, whitelist } = state;
	const typeBreakdown =
		Object.keys(stats.byType).length > 0
			? `\n\nTypes found:\n${Object.entries(stats.byType)
					.sort(([, a], [, b]) => b - a)
					.map(([t, n]) => `  ${t}: ${n}`)
					.join("\n")}`
			: "";

	const wlInfo = whitelist
		? `\n  Values wl:   ${whitelist.values.size + whitelist.valueSubstrings.length}\n` +
			`  Hash wl:     ${whitelist.valueHashes.size + state.sessionWhitelistHashes.size}\n` +
			`  Regex wl:    ${whitelist.valueRegexes.length}\n` +
			`  Paths wl:    ${whitelist.pathRegexes.length}\n` +
			`  Rules off:   ${whitelist.disabledRules.size}`
		: "\n  Whitelist:   none";

	return (
		`🔐 Secret Scanner Status\n` +
		`  Mode:        ${state.mode}${state.mode === "off" ? "  ⏸️  (disabled)" : ""}\n` +
		`  Entropy:     ${state.useEntropy ? "on" : "off"}\n` +
		`  Debug:       ${state.debug ? "on (logs exact secrets!)" : "off"}\n` +
		`  Patterns:    ${SECRET_PATTERNS.length} regex rules\n` +
		`  Scans:       ${stats.scans}\n` +
		`  Findings:    ${stats.findingsTotal}${stats.reported > 0 ? ` (+${stats.reported} report-only)` : ""}\n` +
		`  Redactions:  ${stats.redactions}${wlInfo}${typeBreakdown}`
	);
}

export function registerCommands(pi: ExtensionAPI, state: ScannerState): void {
	pi.registerCommand("secret-scanner", {
		description:
			"Show secret scanner status or set mode: warn | redact | confirm | entropy on/off | debug on/off | reset | reload",
		handler: async (args, ctx) => {
			const arg = args.trim().toLowerCase().replace(/\s+/g, " ");

			if (isMode(arg)) {
				state.textCache.clear();
				state.mode = arg;
				updateStatus(state, ctx);
				ctx.ui.notify(`Secret scanner mode set to: ${arg}`, arg === "off" ? "warning" : "info");
				return;
			}

			switch (arg) {
				case "entropy on":
				case "entropy off":
					state.textCache.clear();
					state.useEntropy = arg === "entropy on";
					updateStatus(state, ctx);
					ctx.ui.notify(`Entropy-based detection: ${state.useEntropy ? "ON" : "OFF"}`, "info");
					return;

				case "debug on":
					state.debug = true;
					updateStatus(state, ctx);
					ctx.ui.notify(
						"Secret scanner debug enabled: exact secret values will be written to terminal logs",
						"warning",
					);
					return;

				case "debug off":
					state.debug = false;
					updateStatus(state, ctx);
					ctx.ui.notify("Secret scanner debug disabled", "info");
					return;

				case "debug":
					ctx.ui.notify(
						`Secret scanner debug is ${state.debug ? "on (unsafe)" : "off"}`,
						state.debug ? "warning" : "info",
					);
					return;

				case "reset":
					state.stats = emptyStats();
					updateStatus(state, ctx);
					ctx.ui.notify("Secret scanner stats reset.", "info");
					return;

				case "reload": {
					state.textCache.clear();
					applyConfig(state, ctx);
					updateStatus(state, ctx);
					const size = state.whitelist ? whitelistSize(state.whitelist) : 0;
					const summary = state.whitelist ? `loaded ${size} entries` : "no whitelist found";
					ctx.ui.notify(`Secret scanner whitelist reloaded: ${summary}`, "info");
					return;
				}

				case "":
				case "status":
					ctx.ui.notify(formatStatus(state), "info");
					return;

				default:
					ctx.ui.notify(`Unknown secret scanner command: ${arg}\n${USAGE}`, "warning");
			}
		},
	});
}
