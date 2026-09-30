# AGENTS.md — pi-secret-scanner

Standalone [pi coding agent](https://github.com/mariozechner/pi-coding-agent) extension that scans
outgoing LLM requests and `read`/`bash` tool results for secrets and redacts them before they leave
the machine. Extracted from the `pi_extensions` monorepo; this repo is the single source of truth.

## Commands

```bash
pnpm install        # Install dependencies (pnpm only, never npm/yarn)
pnpm check          # Prettier + ESLint (zero warnings) + typecheck + tests
pnpm test           # Run vitest
pnpm test:coverage  # Vitest with v8 coverage and enforced thresholds (CI, Node 24)
pnpm smoke          # End-to-end: real pi session + deterministic fake provider
pnpm fp-report <p>  # False-positive report over real files (Node >= 22.18)
pnpm typecheck      # tsc --noEmit
pnpm lint           # ESLint — must pass with zero warnings
pnpm format         # Prettier write
pnpm format:check   # Prettier dry-run
```

If `pnpm install` exits with code 1 about ignored build scripts, run
`pnpm approve-builds esbuild unrs-resolver koffi` then `pnpm install` again.

## CI (`.github/workflows/ci.yml`)

- `check` job — `pnpm check` on Node 22/24.
- `smoke` job — runs `pnpm check` + `pnpm smoke` against **two pi versions**:
  the minimum supported (`0.74.0`, matches the peerDependency range) and
  `latest`. A scheduled weekly run catches extension-API breakage in new pi
  releases before users hit it.

The smoke test (`smoke/run.mjs`) boots a real pi session in JSON mode with the
extension loaded and a local OpenAI-compatible fake provider
(`smoke/fake-provider.mjs`) that scripts a two-turn conversation (read tool
call → final text). It asserts the extension loads cleanly and that both
redaction hooks (`before_provider_request`, `tool_result`) actually redact
in-flight, and that no secret reaches the provider. No LLM API key required.
pi is installed as a devDependency so everything is self-contained.

## Package layout

Extension (wiring and I/O):

- `index.ts` — entry point (the only file in the `pi` manifest). `createSecretScanner(state)` builds the
  factory; the default export shares one `ScannerState` per process on purpose: pi re-runs the factory on
  `/new`, resume, and fork with the same module, so mode and counters persist; `/reload` re-imports it.
- `hooks.ts` — pi event hooks: where content is scanned, redacted, and guarded.
- `commands.ts` — `/secret-scanner` subcommands and the status text.
- `confirm.ts` — confirm-mode dialogs and decision handling.
- `feedback.ts` — footer status, redaction flash, counters, debug log, config problems.
- `state.ts` — all mutable state in one object, plus `buildScanOptions` (cache policy lives here).
- `config.ts` — loads and merges `.gitleaks.toml`, `.secret-scanner.json`, `.secret-scanner.local.json`;
  never throws, returns errors.
- `local-store.ts` — persists project fingerprints (lock, atomic rename, `.git/info/exclude`).
- `placeholder-guard.ts` — pure check behind the `edit`/`write` block.

Detection (pure, no pi imports):

- `scanner.ts` — core scan/redact logic and overlap resolution.
- `patterns.ts` — curated named secret patterns (AWS, GitHub, Stripe, …).
- `entropy.ts` — Shannon-entropy fallback with contextual public-identifier exclusions
  (Git OIDs, Docker digests/IDs, SRI, Nix store paths, GitHub Action pins, Docker Desktop build links).
- `lockfiles.ts` — lockfile names whose `read` results skip entropy detection.

Tests and tooling:

- `*.test.ts` next to each module. `hooks.test.ts`, `commands.test.ts`, and `config.test.ts` drive the
  extension through `testing/harness.ts` (fake `ExtensionAPI`/context, fresh state and temp dirs per test).
- Synthetic secrets are built by concatenation so test sources never match the scanner.
- `fixtures/fake-secrets.txt` — intentionally invalid synthetic values for manual testing.
- `fixtures/benign/` — synthetic false-positive corpus; `scanner.test.ts` asserts nothing in it is replaced.
  Keep these files byte-exact (they are in `.prettierignore`; minified JSON is intentional).
- `scripts/fp-report.ts` — `pnpm fp-report <path>` summarizes what would be replaced/reported in real files.
- `vitest.config.ts` — resolves `@earendil-works/*` through pi's own node_modules; coverage thresholds.

## Invariants

- Runtime dependency: only `smol-toml`. Everything from `@earendil-works/*` stays a peer dependency.
- The `pi` manifest lists exactly `./index.ts`; test files and fixtures are never loaded by pi.
- No module-level mutable state outside `index.ts`'s shared `ScannerState`; pass state explicitly.
- Credential-bearing keys (`token`, `secret`, `api-key`, …) always win over public-identifier
  exclusions — never weaken the guard in `entropy.ts`.
- Named provider rules take precedence over entropy findings in `scanner.ts` overlap resolution.
- Every false-positive fix needs a sample in `fixtures/benign/` and a test showing the same shape
  under a credential key is still detected.
- Never log or persist actual redacted values except in opt-in `/secret-scanner debug on` mode.

## Install (as a pi package)

```bash
pi install git:github.com/koopycat/pi-secret-scanner@v0.1.0   # pinned git tag
# or
pi install npm:pi-secret-scanner                              # after npm publish
```

## Release

1. Bump `version` in `package.json`.
2. `pnpm check` must pass.
3. Single-line commit, tag `vX.Y.Z`, push with tags.
