# Roadmap

Atomic, checkbox-tracked work items for Agent Secrets V1.

**How to read this file.** A box is ticked only when the thing exists in the
repository *and* is covered by tests where it is executable code. "Designed",
"specified" and "obvious" do not count. If you tick a box, you are asserting that
someone can verify it by reading the tree and running `pnpm verify`.

**State captured:** 2026-08-16, immediately after the bootstrap intervention. Phases
run A → G; within a phase, items are roughly ordered by dependency.

---

## Phase A — Repository and governance

- [x] **A1** pnpm workspace with `packages/*` and `apps/*`, `packageManager` pinned,
      `engines.node >= 22.11.0`.
- [x] **A2** Shared `tsconfig.base.json`: NodeNext, `strict`, `noUncheckedIndexedAccess`,
      `exactOptionalPropertyTypes`, `verbatimModuleSyntax`, `erasableSyntaxOnly`,
      project references wired from the root `tsconfig.json`.
- [x] **A3** Biome 2.5.8 configured: single quotes, semicolons, trailing commas, 100
      columns, `noExplicitAny`, `noNonNullAssertion`, `noConsole` (allowing
      `console.error`) with the CLI/MCP overrides.
- [x] **A4** Vitest 4 with the enforced `unit` / `integration` project split.
- [x] **A5** Version catalog in `pnpm-workspace.yaml` so third-party dependency
      review is a one-file exercise.
- [x] **A6** `.gitignore` refuses `.env`, `*.pem`, `*.key`, `*.sqlite`, `data/`,
      and the local-only `internal/` directory.
- [x] **A7** `CLAUDE.md` execution contract.
- [x] **A8** Apache-2.0 `LICENSE` and `NOTICE` at the repository root.
- [x] **A9** Public documentation set: `README.md`, `DOC.md`, `CONTEXT.md`,
      `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, and `docs/*`.
- [ ] **A10** `scripts/scan-secrets.mjs` — canary and credential scan over the working
      tree, wired to `pnpm scan:secrets`. *The script is referenced by
      `package.json` and by `pnpm verify` but does not exist yet, so `pnpm verify`
      currently fails at its last step.*
- [ ] **A11** GitHub Actions CI: lint, typecheck, unit, integration, secret scan, on
      Node 22 and Node 24. (`.github/workflows/` exists and is empty.)
- [ ] **A12** Issue and pull-request templates, including a "no credentials in this
      report" banner. (`.github/ISSUE_TEMPLATE/` exists and is empty.)
- [ ] **A13** Dependency review policy: pinned versions, `pnpm audit` in CI, an
      explicit rule that any dependency able to observe a value needs human review.
- [ ] **A14** Release tooling: changesets or equivalent, provenance-enabled npm
      publish, tag signing.

**A is done when** a clean clone runs `pnpm install && pnpm verify` green in CI, and
a contributor can find the security policy, the code of conduct and the threat model
without asking.

---

## Phase B — Security primitives and domain core

- [x] **B1** `SecretValue`: private field, no `toJSON` (it throws), `toString`,
      `Symbol.toPrimitive` and `util.inspect.custom` all return `[secret]`,
      greppable `expose()`, best-effort `dispose()`.
- [x] **B2** Constant-time `secretValuesEqual` built on `node:crypto.timingSafeEqual`,
      with buffers zeroed in a `finally`.
- [x] **B3** Canonical references: `BACKENDS`, `ENVIRONMENTS`, name and slug patterns,
      `makeRef` / `makeScope` / `parseRef` / `formatRef` / `formatScope`, and the rule
      that an omitted environment is an error.
- [x] **B4** Sanitized error hierarchy with stable `code` and `exitCode`, plus
      `toSafeError` which keeps the original throwable on `cause` and contributes
      nothing from it to the message.
- [x] **B5** Metadata schemas, `.strict()`, with `FORBIDDEN_METADATA_FIELDS` and the
      recursive `assertNoValueFields` guard.
- [x] **B6** Audit event schema and `buildAuditEvent`, metadata only, with the
      `AuditSink` interface and a `nullAuditSink`.
- [x] **B7** `SecretBackend` contract: batch-only `resolveMany`, `describe` returns
      `null` for a missing record, health probe shape.
- [x] **B8** Policy engine: deny-by-default, `PolicyDocument` schema, the built-in
      per-environment rules, executable deny/allow lists, `evaluate` and `assert`.
- [x] **B9** Value rules: empty rejected, 64 KiB cap, surrounding whitespace rejected,
      with error messages that disclose neither size nor content.
- [ ] **B10** Unit tests for B1–B9. *Only a build probe exists under
      `packages/core/test/unit/`. This is the largest open gap in the repository:
      the core is written but unproven.*
- [ ] **B11** `@bx-labs/agent-secrets-redaction`: a stream transform that replaces
      registered values with `[secret]`, and the canary helpers.
      (`packages/redaction/src/` exists and is empty.)
- [ ] **B12** `@bx-labs/agent-secrets-test-helpers`: fake `bws` binary, fake Keychain,
      `ASECRET_CANARY_<random>` generator, temp-HOME fixtures.
      (`packages/test-helpers/src/` exists and is empty.)
- [ ] **B13** Canary harness: run a flow with a generated canary and assert its
      absence from stdout, stderr, log sinks, the SQLite file, generated config, and
      the git working tree.
- [ ] **B14** Serialization tripwire test: `JSON.stringify` on any public result
      containing a `SecretValue` must throw, not emit a placeholder.

**B is done when** every core behaviour above has a unit test, and the canary harness
passes on a flow that deliberately tries to leak.

---

## Phase C — Bitwarden backend and device enrollment

- [ ] **C1** Hardened subprocess helper: `execFile`/`spawn` with argument arrays,
      `shell: false`, explicit timeout, output size cap, and errors mapped to
      `BackendUnavailableError` without echoing stderr.
      (`packages/backend-bitwarden/src/subprocess.ts` is in progress.)
- [ ] **C2** Zod schemas for every `bws` stdout shape — parsing backend output is a
      security control, not a nicety. (`src/bws-schemas.ts` is in progress.)
- [ ] **C3** `bws` client wrapper: locate the binary, check its version, refuse to run
      if it is missing. (`src/bws-client.ts` is in progress.)
- [ ] **C4** Key encoding: the canonical `project/environment/name` scope is encoded
      into the Bitwarden secret key, inside one Bitwarden project.
- [ ] **C5** `BitwardenBackend implements SecretBackend`: `health`, `list`,
      `describe`, `create`, `update`, `delete`, `resolveMany`.
- [ ] **C6** Values wrapped in `SecretValue` at the parse boundary, never held as a
      plain string beyond the adapter's own frame.
- [ ] **C7** Keychain adapter: `security add-generic-password` /
      `find-generic-password` / `delete-generic-password` via argument arrays,
      service `Agent Secrets Bitwarden Access Token`, account `<device-id>:<project-id>`.
- [ ] **C8** `agent-secrets init`: hidden TTY prompt for the access token, Keychain
      write, device id generation, `config.json` at `0600`.
- [ ] **C9** `agent-secrets logout`: Keychain entry removal, local state cleanup,
      audit event.
- [ ] **C10** Multi-device: a second machine enrols with its own token; revoking one
      device's token leaves the others working.
- [ ] **C11** Integration tests against the fake `bws` binary, including the failure
      modes: missing binary, expired token, network error, malformed stdout.

**C is done when** a Mac can enrol, `doctor` reports a healthy backend, the adapter
round-trips a canary through a fake `bws`, and revoking a device token produces
`AUTH_REQUIRED` on that device only.

---

## Phase D — CLI lifecycle

- [ ] **D1** `bin.js` entry point, Commander wiring, global flags (`--json`,
      `--project`, `--env`, `--config`, `--no-audit`, `--quiet`).
- [ ] **D2** The JSON envelope `{ schemaVersion: 1, status, data }`, with
      `assertNoValueFields` run before every write to stdout.
- [ ] **D3** Exit-code mapping from `AgentSecretsError.exitCode`, with a top-level
      handler that converts anything unexpected into `INTERNAL` / exit 10.
- [ ] **D4** JSONL audit sink: append-only, `0600`, under the user's config directory,
      no native dependency in the globally installed package.
- [ ] **D5** `agent-secrets doctor`: Node version, `bws` presence and version,
      Keychain entry, backend reachability, config permissions, policy validity.
- [ ] **D6** `agent-secrets add`: hidden prompt, confirmation prompt compared with
      `secretValuesEqual`, value rules, conflict detection.
- [ ] **D7** `agent-secrets list` and `describe`: metadata only, both human and JSON
      output.
- [ ] **D8** `agent-secrets rotate`: same ingestion path as `add`, requires the record
      to exist.
- [ ] **D9** `agent-secrets delete`: explicit confirmation, never implicit in
      production.
- [ ] **D10** `agent-secrets run`: manifest resolution, policy assertion, batch
      resolve, child environment block, redacted stdio, disposal after spawn,
      documented exit semantics.
- [ ] **D11** Manifest loader for `agent-secrets.yaml`: strict schema, fail-closed on
      unknown keys, approval gate for a manifest from an untrusted repository.
- [ ] **D12** Policy loader for `agent-secrets.policy.yaml`, with a malformed file as
      a hard failure.
- [ ] **D13** Canary tests over every command: nothing reaches stdout, stderr, the
      audit file, or the config directory.

**D is done when** the full lifecycle works against a fake backend, every command
honours the exit-code contract, and a canary survives none of the code paths.

---

## Phase E — Telegram and the one-time form API

- [ ] **E1** Fastify server, Helmet, strict CSP, `no-store`, `Referrer-Policy:
      no-referrer`, HTTPS-only cookies, and a hard body size limit.
- [ ] **E2** SQLite schema: `one_time_requests` and `audit_events`. No value column
      exists at any point in the schema history.
- [ ] **E3** One-time token: at least 256 bits from `crypto.randomBytes`, stored only
      as a hash, bound to user/project/environment/name/action, 2-minute TTL.
- [ ] **E4** Atomic single-use claim: one `UPDATE … WHERE consumed_at IS NULL AND
      expires_at > ?`, with the "zero rows affected" branch mapping to
      `EXPIRED_OR_CONSUMED` / exit 8.
- [ ] **E5** The secure form: no external resources, no analytics, no autofill, no
      query-string echo of the value, anti-CSRF token bound to the request row.
- [ ] **E6** Submission path: body parsed into `SecretValue` at the boundary, value
      rules applied, backend write, disposal, audit event.
- [ ] **E7** Telegram bot: allowlisted numeric user ids, Zod-validated updates,
      commands `/add`, `/rotate`, `/delete`, `/list`, `/describe`, `/health`.
- [ ] **E8** Rate limits: per-user and per-IP, on both the bot and the form endpoints.
- [ ] **E9** Pasted-value handling: detect a message that looks like a credential,
      refuse it, tell the user it is now exposed on Telegram's side, and advise
      rotation.
- [ ] **E10** Integration tests: replay a consumed link, replay an expired link, forge
      a token, submit from a foreign origin, submit an oversized body.

**E is done when** a canary typed into the form reaches Bitwarden and appears in no
log, no database row, no Telegram message and no server response body, and every
replay attempt returns exit-code-8 semantics.

---

## Phase F — MCP server

- [ ] **F1** MCP server bootstrap over stdio with the official SDK.
- [ ] **F2** `secret_list`, `secret_describe`, `secret_health`.
- [ ] **F3** `secret_add_request`, `secret_rotate_request`, `secret_delete_request` —
      returning a request id and an expiry, and delivering the one-time link out of
      band, never in the tool result.
- [ ] **F4** `run_with_secrets`: policy-checked execution with redacted output.
- [ ] **F5** Structural guarantee that no default tool can return a value:
      `assertNoValueFields` on every tool result plus a test that enumerates the
      registered tools and asserts the inventory is exactly the seven above.
- [ ] **F6** Policy mode that disables production mutation and execution for MCP
      callers regardless of the project policy file.
- [ ] **F7** Prompt-injection test corpus: tool arguments and repository content that
      instruct the server to reveal a value, and the assertion that the answer is a
      `POLICY_DENIED` every time.
- [ ] **F8** Client wiring documentation and config snippets for Claude Code, Codex
      and generic MCP clients.

**F is done when** the tool inventory test passes, no tool result can carry a value,
and the injection corpus produces zero disclosures.

---

## Phase G — Public release

- [ ] **G1** Confirm `security@bxlabs.ai` and `conduct@bxlabs.ai` are real, monitored
      mailboxes. **Blocking: the repository must not go public before this.**
- [ ] **G2** Full-tree secret scan and a history scan before the first push.
- [ ] **G3** External review of `docs/threat-model.md` by someone who did not write it.
- [ ] **G4** npm publish dry run for all scoped packages; verify `files`, `bin` and
      `publishConfig.access`.
- [ ] **G5** Publish `@bx-labs/agent-secrets` and the supporting scoped packages with
      provenance.
- [ ] **G6** Signed release tag and a documented signing key, with the key-loss
      runbook in `docs/recovery.md` verified.
- [ ] **G7** Repository made public, with the security policy, code of conduct and
      private disclosure path live.
- [ ] **G8** Post-release: decide whether production mutation graduates from
      "explicitly opt-in" to a first-class documented workflow.

**G is done when** the packages install from npm on a clean machine, `agent-secrets
doctor` passes there, and a vulnerability reported to `security@bxlabs.ai` reaches a
human within one business day.

---

## Explicitly out of scope for V1

Recorded here so nobody re-opens them mid-flight:

- Any storage backend other than Bitwarden Secrets Manager.
- Linux and Windows credential stores (V1 device enrolment is macOS Keychain).
- Custom environments beyond `development` / `preview` / `production`.
- Telemetry of any kind, including opt-in.
- A raw-value getter in the CLI JSON output, the HTTP API, or the MCP toolset.
- Multi-tenant hosting of the form API. It is single-tenant, self-hosted.
- Secret sharing between organisations, approval workflows, or an RBAC model.
