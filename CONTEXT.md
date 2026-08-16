# Project context

Living state of the Agent Secrets repository. Whoever picks this up next — human or
agent — should be able to read this file and know exactly where the work stopped,
what was left unfinished on purpose, and what is simply missing.

Append a dated entry to the intervention timeline at the end of every session. Do not
rewrite history in this file; correct it with a later entry.

---

## Where things stand

**Overall: pre-release. One package of eight is implemented.**

| Area                          | State                                                        |
| ----------------------------- | ------------------------------------------------------------ |
| Monorepo skeleton             | Complete. Workspace, catalog, tsconfig references, Biome, Vitest projects. |
| `@bx-labs/agent-secrets-core` | **Implemented and compiling.** Untested — see the gaps below. |
| `@bx-labs/agent-secrets-redaction` | Empty `src/`. Not started.                             |
| `@bx-labs/agent-secrets-test-helpers` | Empty `src/`. Not started.                          |
| `@bx-labs/agent-secrets-backend-bitwarden` | Partial: subprocess helper, `bws` schemas and client wrapper are being written. No `index.ts`, no `SecretBackend` implementation, no tests. |
| `@bx-labs/agent-secrets` (CLI) | Empty `src/`. Not started.                                  |
| `@bx-labs/agent-secrets-mcp`  | Empty `src/`. Not started.                                   |
| `apps/api`                    | Empty `src/`. Not started.                                   |
| `apps/telegram`               | Empty `src/`. Not started.                                   |
| Public documentation          | Complete as a design contract; describes far more than exists. |
| CI                            | `.github/workflows/` exists and is empty.                    |

The core package is the frozen contract everything else builds against. Its public
API is exported from `packages/core/src/index.ts`; treat that export list as the
interface and do not widen it casually.

## What is deliberately unfinished

These are decisions, not oversights. Do not "fix" them without a human saying so.

- **Production mutation is off.** `defaultPolicy()` gives `production` exactly `list`
  and `describe`. Enabling create/rotate/delete there requires an explicit
  `agent-secrets.policy.yaml`. This stays off through V1.
- **There is no `resolveOne` on `SecretBackend`.** The batch-only shape is
  intentional: it makes "resolve one secret and print it" awkward to write, which is
  the point.
- **`SecretValue.toJSON()` throws instead of returning `[secret]`.** A serializer
  reaching a value is a defect we want loud in tests, not silently masked.
- **`dispose()` is best effort.** JavaScript strings are immutable and
  garbage-collected. We say so in `docs/threat-model.md` rather than pretending.
- **No telemetry hook exists, not even a disabled one.** Adding the plumbing "for
  later" is how telemetry ships.
- **Only one backend.** The `SecretBackend` interface is narrow on purpose so a second
  backend is an addition, not a redesign — but V1 ships Bitwarden only.
- **macOS only for device enrolment.** The Keychain path is the V1 path. A Linux
  secret-service adapter is post-V1.

## Known gaps — the honest list

Ordered by how much they should worry you.

1. **The domain core has no unit tests.** `packages/core/test/unit/` contains a build
   probe and nothing else. Every security property in `secret-value.ts`, `policy.ts`,
   `metadata.ts` and `value-rules.ts` is currently asserted by reading the source.
   Per `CLAUDE.md` §4, security behaviour without a test does not exist. This is the
   single highest-priority item in the repository.
2. **`pnpm scan:secrets` is broken.** `package.json` points it at
   `scripts/scan-secrets.mjs`, which does not exist. `pnpm verify` therefore fails at
   its last step, which means the "run the gates before committing" rule cannot
   currently be satisfied in full. Either write the script or stop claiming the gate.
3. **No canary harness.** The whole leak-detection strategy described in `CLAUDE.md`
   §4.3 depends on `@bx-labs/agent-secrets-test-helpers`, which is empty.
4. **No CI.** Nothing enforces the gates on a pull request.
5. **The `bws` value-passing mechanism is unresolved.** The backend adapter must
   deliver a value to the Bitwarden CLI. If that CLI only accepts the value as a
   command-line argument, the value is briefly visible in the process table on that
   machine. Whoever finishes `packages/backend-bitwarden` must determine what `bws`
   actually supports, pick the least-exposing option available, and write the result
   into `docs/threat-model.md` as either a mitigation or a residual risk. **Do not
   let this ship undocumented.**
6. **`security@bxlabs.ai` and `conduct@bxlabs.ai` are not confirmed to exist.** They
   are published in `SECURITY.md` and `CODE_OF_CONDUCT.md`. A disclosure address that
   bounces is worse than no address. Blocking for going public.
7. **The exit semantics of `agent-secrets run` are a documented decision, not yet a
   tested one.** `DOC.md` and `docs/exit-codes.md` state that the CLI exits 9 when the
   child fails rather than forwarding the child's own status. Implement it that way or
   change both documents; do not let code and docs diverge.
8. **No `.github` templates.** The issue template that tells reporters not to paste
   credentials does not exist yet, and that is exactly the template that matters.

## Conventions worth knowing before you touch anything

- ESM only, NodeNext. Relative imports carry `.js`. Type-only imports use
  `import type`. No enums, no parameter properties (`erasableSyntaxOnly`).
- Cross-package imports go through the package name, never a deep `src/` path.
- Zod v4: `z.iso.datetime()`, `z.record(keySchema, valueSchema)`, `error.issues`.
- Tests split into `test/unit/**` and `test/integration/**`; the split is enforced by
  `vitest.config.ts`. Vitest globals are off — import from `'vitest'`.
- Every `expose()` call site carries a `// expose: <reason>` comment. Reviewers grep
  for `expose(` before reading anything else.
- Documentation is English. It is the public-facing language of this project.

## A note on the missing requirements document

The product requirements document that specifies this project is intentionally not in
this repository, and it is not going to be. It carries positioning, personas and
commercial strategy that belong internally. A few source comments still cite
requirement identifiers (`FR-SCOPE-004`, `FR-ADD-009`, and similar) — treat those as
historical labels, not as pointers to something you can open.

The practical consequence: **the public documents in this repository must stand on
their own.** If a behaviour is not written down in `DOC.md`, `docs/architecture.md` or
`docs/threat-model.md`, then for every purpose that matters it is not specified. When
you implement something whose rationale lives only in your head, write the rationale
down here or in `DOC.md` before you finish.

---

## Intervention timeline

### 2026-08-16 — Handing the human a command instead of a shrug

With no one-time form API running — the normal state for a single-machine setup —
`secret_add_request` answered "Secure input links are not configured. The human can
add the secret with `agent-secrets add` on their machine instead." True, and not
actionable: the agent then had to *compose* the command line itself.

That composition is the part worth being careful about. A command line written by a
language model is a command line a prompt injection can shape, and the human pastes it
into a shell. The failure mode is not the tool disclosing anything — `add` has no
`--value` flag — it is `bws secret create KEY <value> <project>` arriving inside a
plausible reply, or the right command carrying `--env production`.

So `handoffCommand()` builds it in the server, from a reference `makeRef` has already
validated. The grammar admits no space, quote, semicolon, backtick, `$` or newline, so
the string cannot become a second command and nothing needs escaping. The tool result
tells the agent to relay it verbatim and not to run it. Read-only mode hands over
nothing: an operator who said "this agent causes no writes" is not routed around
through the human's keyboard.

**Also corrected:** `docs/threat-model.md` §5.16 still claimed `secret_add_request`
returns the one-time link to the model. It has not since the adversarial review — the
URL is deliberately absent from the result. The section now states the residual risk
that does remain, which is that an agent can *cause* a request a human then acts on.

### 2026-08-16 — First enrolment against a real vault, and what it found

The first attempt to enrol a real machine against a real Bitwarden organisation
(EU cloud, `bws` 2.1.0 installed in `~/.local/bin`) failed at the backend probe with:

```
The backend rejected this token, or is unreachable.
Check the token and the project ID. Nothing was saved.
```

The token and the project ID were both correct. **`bws` was never executed.**

**Root cause.** `minimalEnv()` gives the child a fixed `SAFE_PATH`
(`/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin`), and `BwsClient`
defaults its executable to the bare name `bws`. `execFile` resolves a bare name
against the *child's* `PATH`, so an install in `~/.local/bin` is invisible: `ENOENT`,
mapped to `BackendUnavailableError`, flattened by `health()` into
`{ reachable: false }`, and reported by `init` with a sentence naming the token. The
adapter had only ever run against the fake `bws`, which every test addresses by
absolute path — so no test exercised name resolution, and `scripts/preflight.mjs`
reported `bws` as present because it uses the caller's `PATH`.

Not causes, and each checked rather than assumed: the `bws` 2.1.0 argument syntax and
ordering (`project list`, `secret list <uuid>`, trailing `--output json`) all parse;
its JSON is camelCase and matches `bws-schemas.ts`; and `BWS_SERVER_URL=https://vault.bitwarden.eu`
is right for the EU cloud — `<base>/api/alive` and `<base>/identity/.well-known/openid-configuration`
both answer 200. The `--value-stdin` transport does **not** exist in 2.1.0, so writes
fall back to argv exactly as §5.13 of the threat model already describes.

**Fixed.**

- `BackendHealth` gained `reason`: a closed vocabulary
  (`executable-not-found`, `unauthenticated`, `permission-denied`, `not-found`,
  `unreachable`, `timeout`, `rate-limited`, `incompatible-response`, `unknown`)
  tagged onto errors through a non-enumerable symbol so it cannot reach a sink by
  accident, and derived from the *shape* of a failure — never from `bws` text.
- `init` maps each reason to its own message and to the exit code
  `docs/exit-codes.md` assigns it. It used to exit 3 for a missing binary.
- A token `bws` refuses to *parse* — truncated paste, wrong number of parts, bad
  base64 — is now `AUTH_REQUIRED` rather than `INTERNAL`. None of those messages
  contain the words the old classifier looked for, and "file a bug" was the wrong
  advice for "paste it again".
- `AGENT_SECRETS_BWS_PATH` is now implemented. DOC.md §8.1 had documented it since
  the bootstrap; nothing read it.
- `scripts/preflight.mjs` gained `bws-reachable`, which is the check that would have
  turned this session into thirty seconds.

**Found while checking the 2.1.0 response shapes, and fixed in the same pass.**
`bws secret list` returns the **value** of every secret — that is what makes its
`-o env` output format possible — and `bwsSecretListItemSchema` was `.loose()`.
Passthrough keeps undeclared keys, so every value in the project stayed attached to
the objects `#loadIndex` caches for the lifetime of the command, as plain strings
outside `SecretValue`. Nothing printed them (`toMetadata` builds an explicit object)
and no test could have caught it, because the assertion everyone writes is about
output. The schema is now in Zod's default strip mode: still forward-compatible with
a field a future `bws` adds, no longer keeping a copy of it. The comment above it
claimed the opposite of the truth — "`bws secret list` omits the value in recent
versions" — which is how it survived review.

**One precedence decision worth not reversing.** `AGENT_SECRETS_BWS_PATH` fills a
gap; it does not override a path pinned at enrolment. `config.json` is `0600` and was
written by a deliberate `init`, whereas an environment variable is ambient and
inherited by every process — letting it choose the binary that receives the access
token would reopen the substitution `SAFE_PATH` exists to prevent. There is a unit
test pinning that order.

**Deliberately not done.** `SAFE_PATH` was left alone. Adding `~/.local/bin` would
put a user-writable directory into the list the tool trusts for the binary it hands
the access token to; pointing at that binary explicitly is the operator's call to
make, once, in the open.

**Still true:** no real Bitwarden credential has been used by an agent in this
repository, and none should be. The enrolment above is run by the human at a hidden
prompt.

### 2026-08-16 — V1 implementation, then an adversarial review of it

**What was built.** The whole V1 surface: the domain core, the redaction package,
the Bitwarden adapter over a hardened subprocess runner, the CLI
(`init`/`doctor`/`logout`/`add`/`list`/`describe`/`rotate`/`delete`/`run`), the
single-tenant API with the one-time secure form, the Telegram adapter, and the
stdio MCP server. 503 tests; lint, typecheck, secret scan and the no-raw-getter
guard are green.

**Then it was attacked.** Six independent review passes over the finished code —
leak paths, auth and one-time tokens, injection, policy bypass, local state, and
whether the documentation tells the truth — with every candidate finding handed to
a separate agent whose job was to refute it. 33 candidates, 20 survived. The ones
that mattered, all now fixed and pinned by tests:

- **`run` never redacted child output.** `stdio` was `inherit`, so a child that
  printed its own environment printed it to the terminal, the CI log, and any
  agent transcript — while three documents said the opposite. The redacting
  transform existed and was imported only to be re-exported. stdout and stderr are
  now piped through it; `--pass-through-output` is the documented, warned escape
  hatch for commands that need a real terminal.
- **The output cap sliced values before redaction.** Truncating first was a
  chosen-prefix oracle: pad to one byte short of the budget and the first
  character of the secret survives, because exact-match redaction can no longer
  see a whole occurrence. Repeat with one more byte and walk the prefix forward.
  Redaction now runs on the intact buffer, with headroom, before truncation.
- **The child inherited our own credentials.** `AGENT_SECRETS_ADAPTER_TOKEN` and
  `BWS_ACCESS_TOKEN` were passed to a command the agent chose, whose output goes
  back to the model. They are now stripped and tracked for redaction.
- **A `run` decision with no executable skipped the deny list entirely** — the
  list was effectively opt-in from the call site. Now denied outright.
- **A bare-name allow list matched any path** with the same basename, so
  `/tmp/evil/npm` satisfied `["npm"]`. Allow-list matching is strict now.
- **Manifest approvals were a stub** that was never persisted or consulted, and
  once implemented were keyed by an unresolved path, so a relative `--cwd` made one
  approval transferable to any repository. Approvals are now stored, keyed by the
  realpath plus a content digest, and `--yes` deliberately cannot waive them.
- **`cause` was enumerable**, so `console.error(error)` printed raw `bws` stderr.
- **`assertNoValueFields` crashed on a cyclic object** and missed non-enumerable
  and getter-defined fields.
- **The MCP server wrote no audit at all**, and its `readOnly` mode still minted
  vault-write links. Both fixed; it now shares the CLI's audit file.
- **The one-time link was returned in the MCP tool result** — a two-minute write
  capability sitting in the model's context. It now goes to the human out of band,
  which is what `docs/mcp.md` always said.
- **`/health/ready` was unauthenticated and spawned two `bws` processes per
  request.** Cached and rate limited.
- **SQLite and its WAL/SHM sidecars were world-readable.**

**Documentation was corrected in the same pass**, because a threat model that
oversells is a defect: the argv write window, the Keychain write window, the
plaintext credential store on non-macOS, the fact that Bitwarden grants are
per-project so environment isolation is policy-engine-only, and the residual risk
of `--pass-through-output` are all now in §5 rather than absent or filed as open
questions.

**What is deliberately not done.** No real Bitwarden credential has been used —
everything runs against a fake `bws` executable, so the adapter is proven against
a model of the real thing and not the real thing. `bws` is not installed on this
machine. Nothing has been published to npm. The repository has had no external
security review.

**Decided along the way.** The npm name `agent-secrets` was already taken, so the
CLI publishes as `@bx-labs/agent-secrets` with the binary still called
`agent-secrets`. `run` does not forward the child's exit code by default, because
an agent branching on exit 4 must be able to read it as "policy denied";
`--propagate-exit-code` is there for shell and CI callers.


### 2026-08-16 — Bootstrap

Created the repository from nothing.

**Established:**

- pnpm workspace with six packages and two apps, a version catalog in
  `pnpm-workspace.yaml`, root TypeScript project references, Biome 2.5.8, Vitest 4
  with the enforced unit/integration split, and a `.gitignore` that refuses `.env`,
  key material, SQLite files and the local-only `internal/` directory.
- `CLAUDE.md`, the non-negotiable execution contract: the one rule (a raw value never
  reaches a log, a terminal, an error, a tool result, a model context, a database row,
  a process argument, a git object, or a test artifact), the three legitimate
  destinations for a value, and the list of absolute prohibitions.
- `@bx-labs/agent-secrets-core`, complete and compiling: `SecretValue`, canonical
  reference grammar, sanitized error hierarchy with the stable exit-code mapping,
  strict metadata schemas with `assertNoValueFields`, the audit event schema, the
  `SecretBackend` contract, the deny-by-default policy engine, and value rules.
- The Apache-2.0 `LICENSE` and `NOTICE`.
- The full public documentation set: `README.md`, `ROADMAP.md`, this file, `DOC.md`,
  `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, and the ten documents under
  `docs/`.

**Decided, and not to be re-opened without a human:**

- Bitwarden Secrets Manager is the V1 backend, driven through the official `bws` CLI
  in a hardened subprocess with argument arrays and no shell. One Bitwarden project
  holds every record; the canonical scope is encoded in the Bitwarden secret key.
- The canonical reference format is `backend/project/environment/name`.
- Environments are `development`, `preview`, `production`, and an omitted environment
  is an error. Production is never inferred.
- The default policy is restrictive: full lifecycle in development, read-plus-run in
  preview, list-and-describe only in production.
- One-time links carry at least 256 bits of CSPRNG randomness, are stored only as a
  hash, are bound to user/project/environment/name/action, expire in two minutes, are
  single use, and are claimed atomically.
- The CLI audit sink is append-only JSONL at `0600` so the globally installed package
  carries no native dependency; the API uses SQLite.
- Exit codes 0/2/3/4/5/6/7/8/9/10 are a public contract.
- No telemetry in V1, not even opt-in.
- The default MCP toolset is exactly seven tools and none of them returns a value.
  Adding a raw-value tool requires a human-approved design change.

**Left open, in priority order:** unit tests for the core, `scripts/scan-secrets.mjs`,
the canary harness, CI, the `bws` value-passing question, and confirming the two
`@bxlabs.ai` mailboxes. See the gap list above.

**Note on this snapshot:** the bootstrap ran several workstreams in parallel, so the
tree moved while this file was being written. The state table above reflects
`packages/backend-bitwarden` as partial; check the tree rather than trusting this
paragraph if you are reading it later.
