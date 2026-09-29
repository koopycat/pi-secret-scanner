# Secret Scanner

Scans outgoing provider payloads and text returned by the `read` and `bash` tools for credentials. The default mode replaces detected values before they are sent to the model.

## Visual feedback

The footer normally shows the scanner mode and cumulative redaction count. Whenever one or more values are actually replaced, it changes for five seconds to a prominent warning such as:

```text
🔐 REDACTED 1 secret • provider request • total:3
```

Tool-result redactions identify the source as `read result` or `bash result`. A newer redaction restarts the five-second timer. `warn` mode and rejected confirmations do not trigger the indicator because no replacement occurred.

## Commands

```text
/secret-scanner                         Show status
/secret-scanner off|warn|redact|confirm
/secret-scanner entropy on|off
/secret-scanner debug on|off
/secret-scanner reload                  Reload allowlist configuration
/secret-scanner reset                   Reset counters
```

## Debug mode

Debug mode logs every value that is **actually replaced**, after overlap resolution:

```text
/secret-scanner debug on
```

Example terminal output:

```text
[secret-scanner][debug] replaced GitHub Personal Access Token (classic) (regex) in provider request: "ghp_..."
```

Turn it off after verification:

```text
/secret-scanner debug off
```

> **Warning:** Debug mode writes exact secret values to standard error. Terminal capture, process supervisors, CI systems, and Pi logs may persist them. Use only with synthetic or already-revoked credentials. Debug mode is off by default and is not persisted between Pi processes.

Values are logged only when redaction is applied. `warn` mode and rejected confirmations do not log values because nothing was replaced.

## False-positive controls

Provider-specific regular expressions run first. Optional Shannon-entropy detection catches unknown credentials. It deliberately ignores a small set of intrinsically safe shapes such as UUIDs, timestamps, placeholders, and filesystem paths.

Ambiguous high-entropy HEX/MIXED values in generic metadata fields such as `id`, `digest`, `checksum`, `hash`, and `fingerprint` are reported but not replaced. Credential-bearing contexts still redact them. This avoids replacing public identifiers, source fixtures, and explanatory prose while preserving the credential guard. Pure-hex filesystem segments (git object files, Docker overlay layers, content-addressed caches) are ignored entirely; identifiers embedded in URL path segments and standalone hex values of MD5 length or longer pasted as free prose are reported but never replaced, since replacing them corrupts links and public hashes.

High-entropy Base64 is treated as an identification signal, not proof of a secret. Ambiguous candidates appear in findings but are left unchanged. Automatic Base64 redaction requires an immediate credential assignment (for example `token=` or `api_key=`), a recognized authentication context such as `Authorization: Basic`, or canonical Base64/Base64url whose decoded printable content contains a named provider secret, private key, or credential assignment. Canonically decoded prose/source/JSON and recognized binary file signatures are not automatically redacted. Named provider regex findings retain precedence.

During each provider request, the extension sanitizes the conversation context before the provider payload is assembled. It caches sanitized text by an in-memory SHA-256 fingerprint, so unchanged historical text is reused rather than rescanned. The cache is bounded and cleared when the session, mode, entropy setting, or whitelist changes. Provider-native opaque signatures (`thinkingSignature`, `textSignature`, `thoughtSignature`) and image bytes are passed through unchanged; they are not prompt text and altering them can invalidate provider replay data.

Some hash-like values are safe in recognizable public metadata contexts and are ignored there:

- **Canonical Git OIDs and GitHub Action pins.** Lowercase 40-hex SHA-1 and 64-hex SHA-256 OIDs are ignored only in explicit Git metadata positions, such as `commit_sha=<oid>` or `uses: actions/checkout@<oid>`. Short, malformed, and uppercase hashes are not ignored.
- **Canonical Docker/OCI digests.** `sha256:<64 lowercase hex>` is ignored in digest syntax, for example `image: alpine@sha256:<digest>`.
- **Explicit image/container IDs.** Lowercase 64-hex Docker IDs are ignored only under specific image/container ID labels such as `image_id` and `container_id`. Short Docker IDs are already below the entropy scanner's minimum length.
- **Strict Docker Desktop build links.** Canonical `docker-desktop://dashboard/build/<builder>/<target>/<id>` links are ignored; bare or similar-looking identifiers are not.

Outside those contexts, the same values remain detectable. Credential-bearing assignments such as `token=<40-hex>` and `secret=sha256:<64-hex>` are always scanned. Provider-specific rules are unaffected. If another public artifact format is still flagged, add a narrow project allowlist as a fallback.

Entropy detection is heuristic. If it still obscures ordinary project data, prefer these controls in order:

1. Add a narrow value or regex allowlist for the project.
2. Disable entropy detection with `/secret-scanner entropy off` while retaining named credential rules.
3. Disable one noisy named rule with `disable_rules` only when its protection is not needed.

Use `/secret-scanner debug on` only with synthetic or revoked values to identify the exact matched candidate.

## Allowlisting

Configuration is loaded from the working directory when a session starts. Run `/secret-scanner reload` after changing it.

### `.secret-scanner.json`

```json
{
	"whitelist": {
		"values": ["exact-synthetic-secret"],
		"value_regexes": ["^test_[A-Za-z0-9]{24}$"],
		"paths": ["^test/fixtures/"],
		"disable_rules": ["Generic Password Assignment"]
	}
}
```

- `values` skips exact detected values.
- `value_regexes` contains JavaScript regular expressions matched against detected values.
- `paths` skips `read` tool-result scanning for matching paths; the final provider request is still scanned.
- `disable_rules` disables named scanner rules.

Do not commit real credentials in allowlist files.

### `.gitleaks.toml`

```toml
[allowlist]
stopwords = ["exact-synthetic-secret"]
regexes = ['''^test_[A-Za-z0-9]{24}$''']
paths = ['''^test/fixtures/''']
```

Both `[allowlist]` and `[[allowlists]]` are accepted. A non-empty `.gitleaks.toml` allowlist takes precedence over `.secret-scanner.json`.
