# Detection and security

Pi Secret Scanner is a heuristic safety net. It reduces the chance of sending credentials to an LLM provider, but it cannot guarantee that every secret is detected. Keep secrets out of prompts, source files, logs, and command output whenever possible.

Interactive `confirm` mode intentionally displays complete detected values in its selection dialog so you can make an informed per-value decision. Values are escaped to prevent control and invisible formatting characters from altering the dialog. “Allow for this session” and “Always allow in this project” retain only SHA-256 fingerprints; the project choice uses the local `.secret-scanner.local.json` file. They remain hidden from ordinary status output; debug logging is the separate, explicitly enabled exception. Terminal scrollback or capture can retain TUI dialogs, and RPC clients receive the complete dialog contents, which may be retained in protocol or client logs.

## Scan points

The extension scans at two boundaries:

1. Text results from every Pi tool are inspected before they enter conversation history.
2. The final provider payload is inspected before it leaves the machine.

In `redact` mode, conversation context is also sanitized before provider payload assembly. A bounded, process-local cache reuses sanitized text based on a SHA-256 fingerprint; original secret values are not retained as cache keys. The cache is cleared when the session, mode, entropy setting, or allowlist changes.

Lockfiles read with `read` (`pnpm-lock.yaml`, `package-lock.json`, `go.sum`, `flake.lock`, `devenv.lock`, `uv.lock`, `Cargo.lock`, and other `*.lock` files) skip entropy detection because they consist of public integrity hashes. Named credential rules still apply to them.

## Working with placeholders

While `redact` or `confirm` mode is active, the extension appends a short note to the system prompt: placeholders are opaque, must not be guessed, and must not be written into files.

It also guards Pi's `edit` and `write` tools. A call is blocked when its text contains a placeholder that the scanner emitted in this session and the target file does not already contain that exact placeholder text. The block reason tells the model to edit around the redacted lines or ask the user. Without this guard, a model that read a redacted `.env` file could overwrite real values with placeholders. Files that literally contain placeholder text, such as this project's tests and docs, remain editable.

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
- lowercase 64-character Docker image or container IDs under explicit ID labels;
- canonical `docker-desktop://dashboard/build/<builder>/<target>/<id>` links;
- Subresource Integrity digests (`sha1-`, `sha256-`, `sha384-`, `sha512-`) with the exact digest length, as used by npm lockfiles and Nix `hash`/`narHash` attributes;
- Nix store entries (`<32-character Nix base32 hash>-<name>` after a store directory), PATH-style path lists, and `-flag=/path=/path` path mappings; and
- a single host label directly after a URL scheme, such as `https://docs-site.example`.

Canonical lowercase 40-character SHA-1 values are ignored even without Git-specific context because Git commands commonly print bare object IDs. Lowercase 64-character SHA-256 values require explicit Git context. Credential assignments such as `token=<40-hex>` and `secret=sha256:<64-hex>` always take precedence and remain detectable. Named credential rules are unaffected.

Credential context comes from the value's own key or its assignment chain (`token=sha256:<value>`). Assignments earlier on the line that end at a value boundary (`,`, `;`, `&`, brackets) or on previous lines do not apply, so a `PASSWORD=` line no longer turns the values below it into credentials.

## Intentionally unmodified data

The provider-payload walker leaves these values unchanged:

- strings under recognized filesystem-path keys;
- image bytes in typed image content; and
- provider-native `thinkingSignature`, `textSignature`, and `thoughtSignature` replay fields in their expected typed content.

Opaque signatures are required for provider replay and can become invalid if modified. Image bytes are not text. Avoid placing credentials in these fields.

## Reducing false positives

To find false positives, run the scanner over files that should contain no secrets:

```bash
pnpm fp-report ~/src/some-project        # counts and file names only
pnpm fp-report ./ci-output --show-values # also prints truncated values
```

Every `replace` line in the output is a false positive worth a synthetic sample in `fixtures/benign/`; the test suite asserts that nothing in that directory is replaced.

Use these controls in order:

1. Add a narrow exact-value or regular-expression allowlist for the project.
2. Disable entropy detection with `/secret-scanner entropy off` while retaining named credential rules.
3. Disable one noisy named rule with `disable_rules` only when its protection is unnecessary.

See [Configuration](configuration.md) for allowlist formats. If necessary, use debug logging only with synthetic or revoked values; see [Usage](usage.md#debug-logging).
