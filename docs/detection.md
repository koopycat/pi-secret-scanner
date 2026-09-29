# Detection and security

Pi Secret Scanner is a heuristic safety net. It reduces the chance of sending credentials to an LLM provider, but it cannot guarantee that every secret is detected. Keep secrets out of prompts, source files, logs, and command output whenever possible.

Interactive `confirm` mode intentionally displays complete detected values in its confirmation dialog so you can make an informed decision. Values are escaped to prevent control and invisible formatting characters from altering the dialog. They remain hidden from ordinary status output; debug logging is the separate, explicitly enabled exception. Terminal scrollback or capture can retain TUI dialogs, and RPC clients receive the complete dialog contents, which may be retained in protocol or client logs.

## Scan points

The extension scans at two boundaries:

1. Text results from Pi's `read` and `bash` tools are inspected before they enter conversation history.
2. The final provider payload is inspected before it leaves the machine.

In `redact` mode, conversation context is also sanitized before provider payload assembly. A bounded, process-local cache reuses sanitized text based on a SHA-256 fingerprint; original secret values are not retained as cache keys. The cache is cleared when the session, mode, entropy setting, or allowlist changes.

Only `read` and `bash` have immediate tool-result scanning. Text from other tools can still be detected when it reaches the final provider request.

## Named rules

Named regular-expression rules detect:

- private keys;
- AWS, GitHub, Google, Stripe, Slack, Twilio, npm, Telegram, SendGrid, Mailchimp, Heroku, Databricks, OpenAI, and Anthropic credentials;
- JSON Web Tokens;
- generic password, secret, token, and API-key assignments; and
- URLs containing credentials.

Named rules take precedence over overlapping entropy findings.

## Entropy detection

Entropy detection is enabled by default and looks for unknown high-entropy values. It deliberately ignores common safe shapes such as UUIDs, timestamps, placeholders, and filesystem paths.

High entropy is evidence, not proof, so ambiguous candidates are handled conservatively:

- High-entropy hexadecimal or mixed values in generic metadata fields such as `id`, `digest`, `checksum`, `hash`, and `fingerprint` can be reported without replacement.
- Pure-hex filesystem segments are ignored.
- Hash-like URL path segments and standalone hexadecimal values of MD5 length or longer in free prose can be reported without replacement, except canonical lowercase 40-character Git SHA-1 object IDs, which are ignored.
- Ambiguous Base64 candidates can be reported without replacement.
- Base64 is automatically redacted when it appears in an immediate credential assignment, a recognized authentication context such as `Authorization: Basic`, or canonically decodes to content containing a named secret, private key, or credential assignment.
- Canonically decoded prose, source, JSON, and recognized binary file signatures are not automatically redacted.

Credential-bearing context takes priority over these public-identifier safeguards.

## Public identifiers

The scanner ignores narrowly recognized public identifiers in their expected contexts:

- lowercase 40-character SHA-1 Git object IDs by canonical shape, including bare command output, and lowercase 64-character SHA-256 Git object IDs in explicit Git metadata positions;
- canonical Docker/OCI `sha256:<64 lowercase hex>` digests;
- lowercase 64-character Docker image or container IDs under explicit ID labels; and
- canonical `docker-desktop://dashboard/build/<builder>/<target>/<id>` links.

Canonical lowercase 40-character SHA-1 values are ignored even without Git-specific context because Git commands commonly print bare object IDs. Lowercase 64-character SHA-256 values require explicit Git context. Credential assignments such as `token=<40-hex>` and `secret=sha256:<64-hex>` always take precedence and remain detectable. Named credential rules are unaffected.

## Intentionally unmodified data

The provider-payload walker leaves these values unchanged:

- strings under recognized filesystem-path keys;
- image bytes in typed image content; and
- provider-native `thinkingSignature`, `textSignature`, and `thoughtSignature` replay fields in their expected typed content.

Opaque signatures are required for provider replay and can become invalid if modified. Image bytes are not text. Avoid placing credentials in these fields.

## Reducing false positives

Use these controls in order:

1. Add a narrow exact-value or regular-expression allowlist for the project.
2. Disable entropy detection with `/secret-scanner entropy off` while retaining named credential rules.
3. Disable one noisy named rule with `disable_rules` only when its protection is unnecessary.

See [Configuration](configuration.md) for allowlist formats. If necessary, use debug logging only with synthetic or revoked values; see [Usage](usage.md#debug-logging).
