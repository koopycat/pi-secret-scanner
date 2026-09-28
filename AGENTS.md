# AGENTS.md — pi-secret-scanner

Standalone [pi coding agent](https://github.com/mariozechner/pi-coding-agent) extension that scans
outgoing LLM requests and `read`/`bash` tool results for secrets and redacts them before they leave
the machine. Extracted from the `pi_extensions` monorepo; this repo is the single source of truth.

## Commands

```bash
pnpm install        # Install dependencies (pnpm only, never npm/yarn)
pnpm check          # Prettier + ESLint (zero warnings) + typecheck + tests
pnpm test           # Run vitest
pnpm smoke          # End-to-end: real pi session + deterministic fake provider
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

- `index.ts` — extension entry point (registered via the `pi` manifest in `package.json`).
- `scanner.ts` — core scan/redact logic and overlap resolution.
- `patterns.ts` — curated named secret patterns (AWS, GitHub, Stripe, …).
- `entropy.ts` — Shannon-entropy fallback with contextual public-identifier exclusions
  (Git OIDs, Docker digests/IDs, GitHub Action pins, Docker Desktop build links).
- `scanner.test.ts` — vitest suite; builds synthetic secrets by concatenation so the
  source itself never matches.
- `fixtures/fake-secrets.txt` — intentionally invalid synthetic values for manual testing.
- `vitest.config.ts` — resolves `@earendil-works/*` through pi's own node_modules.

## Invariants

- Runtime dependency: only `smol-toml`. Everything from `@earendil-works/*` stays a peer dependency.
- The `pi` manifest lists exactly `./index.ts`; test files and fixtures are never loaded by pi.
- Credential-bearing keys (`token`, `secret`, `api-key`, …) always win over public-identifier
  exclusions — never weaken the guard in `entropy.ts`.
- Named provider rules take precedence over entropy findings in `scanner.ts` overlap resolution.
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
