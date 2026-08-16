# Contributing to Agent Secrets

Thanks for wanting to help. Before anything else, please read
[`CLAUDE.md`](CLAUDE.md) — it is the execution contract for this repository, it is
short, and every review starts from it.

This is a security product. The cost of a careless change here is a leaked production
credential, not a red build. That colours everything below.

---

## Setup

Requirements: Node **>= 22.11**, pnpm (the repository pins `pnpm@11.5.0` via
`packageManager`), and macOS if you want to exercise the Keychain paths.

```bash
git clone https://github.com/Brissux-Labs/agent-secrets.git
cd agent-secrets
pnpm install
pnpm build
```

You do **not** need a Bitwarden account to develop. Integration tests run against a
fake `bws` binary and a fake Keychain from `@bx-labs/agent-secrets-test-helpers`.
Never point a test at a real vault.

Build a single package:

```bash
npx tsc --build packages/core
```

Run one test file:

```bash
npx vitest run --project unit packages/core/test/unit/scope.test.ts
```

## Quality gates

Every one of these must be green before a change is done. `pnpm verify` runs the whole
sequence.

```bash
pnpm lint            # Biome: format + lint
pnpm typecheck       # tsc --build --force across the workspace
pnpm test            # unit
pnpm test:integration
pnpm scan:secrets    # canary + credential scan over the working tree
```

A red gate blocks the change. It is never worked around by relaxing the gate, adding
an ignore comment, or marking a test `.skip`. If you believe a gate is wrong, say so
in the pull request and leave it red — do not quietly disarm it.

> **Currently:** `scripts/scan-secrets.mjs` does not exist yet, so `pnpm scan:secrets`
> fails. Writing it is roadmap item **A10** and it is one of the most useful first
> contributions available. Until it lands, run the rest of the sequence and scan your
> diff by eye.

## Test-driven, without exception for executable code

1. Write the failing test.
2. Write the minimal implementation.
3. Refactor.

Security behaviour that is not covered by a test does not exist. In practice that
means:

- Every leak-relevant path gets a **canary test**: generate an
  `ASECRET_CANARY_<random>` value at runtime, run the flow, then assert the canary
  appears in none of stdout, stderr, the audit file, the SQLite database, generated
  config, or the git working tree.
- Every error path asserts the *sanitized* message and the stable `code`, not the
  underlying cause.
- Every schema change adds a case proving that a forbidden field fails to parse.

Tests live in `<package>/test/unit/**` and `<package>/test/integration/**`; the split
is enforced by `vitest.config.ts`. Unit tests are pure — no child processes, no
filesystem beyond a temp directory. Vitest globals are off, so import from `'vitest'`
explicitly.

## Code conventions

- **ESM only**, `"type": "module"`, NodeNext resolution. Relative imports carry the
  `.js` extension (`./scope.js`).
- **`import type`** for type-only imports (`verbatimModuleSyntax`).
- **No enums, no parameter properties** (`erasableSyntaxOnly`).
- **No `any`**, no non-null assertions, no `@ts-expect-error` without a comment naming
  the upstream issue.
- **Zod for every external input**: CLI arguments, HTTP bodies, Telegram updates, MCP
  tool arguments, manifest and policy files, and `bws` stdout. Parsing backend stdout
  with a schema is a security control, not a nicety.
- **Cross-package imports** use the package name
  (`@bx-labs/agent-secrets-core`), never a deep `src/` path.
- **Every `expose()` call site carries a `// expose: <reason>` comment.** Reviewers
  grep for `expose(` before reading anything else. A call site without a reason is
  rejected on sight.
- **Fail closed.** Unknown manifest key, unreachable backend, ambiguous policy,
  missing environment → refuse and exit non-zero. Never degrade to a permissive path.
- **Comments explain why, not what.** Read `packages/core/src/policy.ts` for the house
  style: dense, purposeful, and about the security decision rather than the syntax.

Biome enforces single quotes, semicolons, trailing commas, 100 columns and two-space
indentation. Run `pnpm lint:fix` rather than arguing with it.

## Commits and pull requests

Conventional commits, one coherent commit per change:

```
feat(cli): add doctor command
fix(backend-bitwarden): map malformed bws stdout to BACKEND_UNAVAILABLE
docs(threat-model): record the bws argument-vector exposure window
test(core): cover SecretValue serialization tripwire
chore(ci): run the secret scan on pull requests
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `build`, `ci`, `chore`.
Scopes match the package or app directory. A breaking change carries a `!` and a
`BREAKING CHANGE:` footer — **note that an exit code change is always breaking**, as
is any change to the JSON envelope.

In your pull request, state plainly:

- what security property the change touches, if any;
- which gates you ran;
- whether you added an `expose()` call site, and why.

Before every commit, inspect `git status` and the full diff, and run the secret scan
over the working tree. Never force-push, never rewrite published history.

## Documentation duties

- Durable behaviour changed → update [`DOC.md`](DOC.md).
- You made a decision someone will wonder about later → append a dated entry to
  [`CONTEXT.md`](CONTEXT.md).
- You ticked something off → update [`ROADMAP.md`](ROADMAP.md), and only tick a box
  that a reader can verify from the tree.
- A new threat, or a new residual risk → [`docs/threat-model.md`](docs/threat-model.md).
  Understating a risk there is a worse defect than a crash.

Do not reference a document that a reader cannot open. The public docs stand alone by
design.

---

## Hard boundaries

These are not negotiable and a pull request that crosses one will be closed rather
than reviewed. If you think one of them is wrong, open a discussion — but do not open
it as a patch.

1. **Do not add cryptography without design review.** No custom encryption, no
   home-made KDF, no bespoke MAC, no "just a quick HMAC here". `node:crypto`
   primitives for randomness, hashing and constant-time comparison, and nothing more.
   Changing one-time token generation, binding or consumption needs a human decision
   before you write the code.

2. **Do not add telemetry.** Not analytics, not crash reporting, not "anonymous usage
   counts", not opt-in, not disabled-by-default plumbing "for later". V1 makes no
   network call other than to your Bitwarden instance, your own API host, and the
   Telegram API when you run the bot.

3. **Do not weaken redaction or canary tests.** Not to make CI green, not to unblock
   a release, not "temporarily". A canary test that fails has found a leak; the leak
   is the bug. Deleting, skipping, narrowing or loosening one of these tests is
   treated as an attempt to ship a disclosure.

4. **Do not introduce a raw-value tool into the default MCP build.** The default
   toolset is exactly seven tools and none of them returns a value. That is a
   structural guarantee with a test that enumerates the inventory. Adding a
   value-returning tool — under any name, behind any flag, "for debugging" — requires
   an explicit, human-approved design change. The same applies to the CLI JSON output
   and the HTTP API.

5. **Do not commit real keys.** Not in tests, not in fixtures, not in docs, not in a
   demo, not "expired", not "it's only my personal account". Tests that need a value
   generate an `ASECRET_CANARY_<random>` at runtime. Docs use obvious placeholders and
   `.invalid` hostnames. If you commit one by accident, say so immediately and rotate
   it — we would much rather have an awkward message than a quiet history rewrite.

6. **Do not make production actions implicit.** No inferred environment, no
   production default, no `--force` that skips a production gate, no environment
   variable that quietly targets `production`, no policy fallback that becomes
   permissive when a file is missing or malformed. Turning on production mutation must
   remain something a human writes down in a policy file and commits.

7. **Do not log a value or anything derived from it** — length, size, hash, digest,
   prefix, suffix, entropy estimate, character-class summary. See
   [`docs/logging.md`](docs/logging.md) for why length and hash count as disclosure.

8. **Do not use a shell.** Every child process — `bws`, `security`, user commands — is
   spawned with an argument array through `execFile`/`spawn`. Never `exec`, never
   `shell: true`, never string interpolation into a command line.

9. **Do not add a dependency that can observe a value** without human review. New
   dependencies go in the `pnpm-workspace.yaml` catalog with a pinned version and a
   note in the pull request explaining what it does and why nothing already present
   suffices.

## Things that need a human decision before you start

Implement freely, but stop and ask first if your change touches:

- authentication or authorization logic;
- one-time token generation, binding, or consumption;
- redaction rules or logging sinks;
- production policy gates;
- a dependency that can observe a value;
- publishing a release, or making the repository public.

## Reporting a vulnerability

Not here. [`SECURITY.md`](SECURITY.md), privately, and **never with a real credential
attached**.

## Code of conduct

Participation is governed by [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

## License

By contributing you agree that your contributions are licensed under Apache-2.0, the
license of this project.
