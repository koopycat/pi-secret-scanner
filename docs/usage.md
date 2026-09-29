# Usage

Pi Secret Scanner starts in `redact` mode with entropy detection enabled. Settings and counters are process-local and return to their defaults when a new Pi process starts.

## Commands

```text
/secret-scanner                         Show status and counters
/secret-scanner off|warn|redact|confirm
/secret-scanner entropy on|off
/secret-scanner debug on|off
/secret-scanner reload                  Reload allowlist configuration
/secret-scanner reset                   Reset counters
```

## Modes

| Mode      | Behavior                                                                                           |
| --------- | -------------------------------------------------------------------------------------------------- |
| `redact`  | Replaces detected values before sending them to the model. This is the default.                    |
| `warn`    | Records findings but leaves content unchanged. Detected secrets can reach the provider.            |
| `confirm` | Asks whether to redact newly detected values. Without an interactive UI, it redacts automatically. |
| `off`     | Disables all scanning.                                                                             |

Changing the mode or entropy setting clears the in-memory scan cache.

## Visual feedback

The footer normally shows the current mode and the number of newly detected redactions. When a new value is replaced, the footer displays a warning for five seconds:

```text
🔐 REDACTED 1 secret • provider request • total:3
```

Tool-result redactions identify their source as `read result` or `bash result`. A newer redaction restarts the timer. Warn-only findings and rejected confirmations do not trigger the indicator because no replacement occurred.

Counts represent newly scanned findings and redactions. Repeated content may be served from the bounded in-memory scan cache and is not counted again.

## Debug logging

Debug mode writes exact, newly detected values to standard error when they are replaced:

```text
/secret-scanner debug on
```

Example:

```text
[secret-scanner][debug] replaced GitHub Personal Access Token (classic) (regex) in provider request: "ghp_..."
```

Disable it after verification:

```text
/secret-scanner debug off
```

> [!WARNING]
> Debug output can expose credentials to terminal capture, process supervisors, CI systems, and Pi logs. Use it only with synthetic or revoked credentials. Debug mode is disabled by default and is not persisted between Pi processes.

Only fresh, uncached redactions are logged. Warn mode and rejected confirmations do not log values because no replacement occurs.
