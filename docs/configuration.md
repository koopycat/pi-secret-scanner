# Configuration

Pi Secret Scanner loads project configuration from the session's working directory at startup. Run the following command after editing a configuration file:

```text
/secret-scanner reload
```

Never commit real credentials in allowlist files.

## Native configuration

Create `.secret-scanner.json`:

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

| Field           | Behavior                                                                                                     |
| --------------- | ------------------------------------------------------------------------------------------------------------ |
| `values`        | Skips an exact detected value.                                                                               |
| `value_regexes` | Skips detected values matching a JavaScript regular expression.                                              |
| `paths`         | Skips immediate `read` tool-result scanning for matching paths. The final provider request is still scanned. |
| `disable_rules` | Disables named scanner rules. Use this only when their protection is not needed.                             |

Invalid JSON or regular expressions are reported to standard error and leave the scanner without an active allowlist.

## Gitleaks allowlist compatibility

The scanner recognizes a subset of `.gitleaks.toml` allowlist configuration:

```toml
[allowlist]
stopwords = ["exact-synthetic-secret"]
regexes = ['''^test_[A-Za-z0-9]{24}$''']
paths = ['''^test/fixtures/''']
```

Both `[allowlist]` and `[[allowlists]]` are accepted. The supported fields are:

| Gitleaks field | Scanner behavior                            |
| -------------- | ------------------------------------------- |
| `stopwords`    | Treated as exact detected values.           |
| `regexes`      | Applied to detected values.                 |
| `paths`        | Applied to paths passed to the `read` tool. |

This is allowlist compatibility, not general Gitleaks configuration support. Rule definitions and other Gitleaks settings are ignored. Expressions are evaluated by JavaScript's regular-expression engine; leading `(?i)`, `(?m)`, and `(?s)` flags are translated where possible.

## Precedence

A non-empty `.gitleaks.toml` allowlist takes precedence over `.secret-scanner.json`. If `.gitleaks.toml` has no supported allowlist entries, the scanner falls back to `.secret-scanner.json`.
