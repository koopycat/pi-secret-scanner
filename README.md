# Pi Secret Scanner

[![CI](https://github.com/koopycat/pi-secret-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/koopycat/pi-secret-scanner/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A [Pi coding agent](https://github.com/earendil-works/pi) extension that detects credentials in tool output and outgoing LLM requests, then redacts them before they leave your machine.

> [!IMPORTANT]
> Secret detection is heuristic. This extension is a last line of defense, not a replacement for keeping credentials out of prompts, files, logs, and shell output.

## How it works

Pi Secret Scanner:

- scans text returned by Pi's `read` and `bash` tools before it enters the conversation;
- scans the final provider request before it is sent to the LLM; and
- replaces detected values with typed placeholders such as `[REDACTED:AWS_ACCESS_KEY_ID]`.

Detection combines rules for known credential formats with entropy-based detection for unknown secrets. Entropy detection is enabled by default.

## Install

Requires Pi `0.74.0` or newer.

```bash
pi install git:github.com/koopycat/pi-secret-scanner@v0.2.4
```

The versioned tag keeps your installation reproducible. Check [Releases](https://github.com/koopycat/pi-secret-scanner/releases) and install a newer tag when you choose to upgrade.

To remove it:

```bash
pi remove git:github.com/koopycat/pi-secret-scanner@v0.2.4
```

Pi packages execute local code. Review third-party package source before installation.

## Usage

Redaction is enabled automatically. Run this inside Pi to check the current mode and counters:

```text
/secret-scanner
```

| Mode      | Behavior                                                                                                       |
| --------- | -------------------------------------------------------------------------------------------------------------- |
| `redact`  | Replaces detected secrets before sending them. **Default.**                                                    |
| `warn`    | Records detections but sends content unchanged.                                                                |
| `confirm` | Shows detected values and asks before redacting in interactive sessions; falls back to redaction without a UI. |
| `off`     | Disables scanning.                                                                                             |

```text
/secret-scanner off|warn|redact|confirm
/secret-scanner entropy on|off
/secret-scanner reload
/secret-scanner reset
```

The Pi footer shows the active mode and briefly highlights newly detected redactions. Modes, counters, and entropy settings are process-local and return to their defaults in a new Pi process. In `confirm` mode, each value can be redacted, allowed once, allowed for the session, or always allowed in the project. Persistent decisions store only SHA-256 fingerprints in the gitignored `.secret-scanner.local.json` file.

See [Usage](docs/usage.md) for visual feedback, command behavior, and debug logging.

## Configuration

Project-level allowlists can use either `.secret-scanner.json` or the supported allowlist fields in `.gitleaks.toml`:

```json
{
	"whitelist": {
		"values": ["exact-synthetic-secret"],
		"paths": ["^test/fixtures/"]
	}
}
```

Run `/secret-scanner reload` after changing the file. Never add real credentials to an allowlist.

See [Configuration](docs/configuration.md) for all fields, precedence rules, and Gitleaks compatibility.

## Security boundaries

- Detection can produce false positives and false negatives.
- Only `read` and `bash` results are scanned immediately; text from other tools is still inspected at the final provider boundary.
- File-path fields, image bytes, and provider replay signatures are intentionally left unchanged.
- `warn` mode does **not** prevent secrets from being sent.
- Allowlisted paths skip immediate `read` result scanning, but the final provider request is still scanned.

See [Detection and security](docs/detection.md) for supported credential categories, entropy behavior, exclusions, and false-positive controls.

## Development

```bash
pnpm install
pnpm check
pnpm smoke
```

`pnpm smoke` runs the extension in a real Pi session against a deterministic local provider; no LLM API key is required.

## License

[MIT](LICENSE)
