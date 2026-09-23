# Project context

Living state of the Agent Secrets repository. Whoever picks this up next — human or
agent — should be able to read this file and know exactly where the work stopped,
what was left unfinished on purpose, and what is simply missing.

Append a dated entry to the intervention timeline at the end of every session. The
timeline is history: do not rewrite an entry, correct it with a later one.

Everything *above* the timeline is state, not history. Correct it in place, in the
same pass, the moment your work makes it wrong. This file spent a day claiming that
one package of eight existed while the whole product was implemented and passing 500
tests, because every session dutifully appended an entry and nobody touched the table.

---

## Where things stand

**Overall: pre-release, feature-complete for V1, and in daily use against a real
vault on two machines since mid-August 2026.** Not published to npm, not externally
reviewed.

| Area                          | State                                                        |
| ----------------------------- | ------------------------------------------------------------ |
| Monorepo skeleton             | Complete. Workspace, catalog, tsconfig references, Biome, Vitest projects. |
| `@bx-labs/agent-secrets-core` | Implemented, 7 test files.                                    |
| `@bx-labs/agent-secrets-redaction` | Implemented, 5 test files.                              |
| `@bx-labs/agent-secrets-test-helpers` | Implemented: fake `bws`, fake Keychain, canary generator, temp-HOME fixtures. |
| `@bx-labs/agent-secrets-backend-bitwarden` | Implemented. Tested against the fake `bws`, and exercised against real `bws` 2.1.0 and the Bitwarden EU cloud on 2026-08-16. |
| `@bx-labs/agent-secrets` (CLI) | Implemented: `init`/`doctor`/`logout`/`add`/`list`/`describe`/`rotate`/`delete`/`copy`/`run`. |
| `@bx-labs/agent-secrets-mcp`  | Implemented. Eight tools, none returning a value.             |
| `apps/api`                    | Implemented. **One integration suite — the thinnest coverage in the tree, on the component that handles a value in transit.** Never run against a real vault. |
| `apps/telegram`               | Implemented. One integration suite. Never run against a real bot, and **not wired to the policy engine** — nothing sets `approvalGranted`, so every `humanApproval` action is denied permanently. |
| Public documentation          | Complete, and now corrected where it had drifted from the code. |
| CI                            | `.github/workflows/ci.yml` and `release.yml`. CI runs lint, typecheck, build, unit, integration, the secret scan and the raw-getter guard, and is green on `main`. Dependabot is active. |

**605 tests across 26 files.** `pnpm verify` is green.

The core package is the frozen contract everything else builds against. Its public
API is exported from `packages/core/src/index.ts`; treat that export list as the
interface and do not widen it casually.

## What is deliberately unfinished

These are decisions, not oversights. Do not "fix" them without a human saying so.

- **Destructive production mutation is off.** `defaultPolicy()` gives `production`
  `list`, `describe`, `create` and `request-create`. Enabling `rotate`, `delete`,
  `run` or `copy` there requires an explicit policy file. This stays off through V1. `create` was in that list until
  2026-08-19 and is not any more — see the timeline entry for the reasoning, which
  turns on `add` refusing to overwrite and on the MCP toolset having no path to the
  action at all.
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

Ordered by how much they should worry you. **Rewritten 2026-08-16**: every item on
the previous list had been closed by the V1 implementation without this section being
corrected, so it described a repository that had not existed for a day. If you close
one of these, edit it here in the same pass — a stale gap list is worse than none,
because it is the first thing the next reader trusts.

1. **No external security review.** Nobody who did not write this code has looked at
   it, and the threat model has not been reviewed by anyone who did not write it.
   `SECURITY.md` says so; it remains true, and it is the reason not to put a
   production credential behind this yet. Roadmap G3.
2. **`apps/api` and `apps/telegram` have one test suite each.** They are the thinnest
   coverage in the tree and they are the components where a value transits a process
   and a network. Neither has ever run against a real vault or a real bot.
3. **Nothing is published.** No npm release, no signed tag, no documented signing key,
   and `release.yml` has never run a real release. Roadmap G4–G6.
4. **`ROADMAP.md` understates the tree.** Its boxes were captured just after the
   bootstrap and were never re-ticked when V1 shipped. Treat the table above as
   authoritative until that file gets a verification pass.
5. **The history scan was targeted, not exhaustive.** On 2026-08-16 the full commit
   history was grepped for credential shapes and came back clean — only obvious
   placeholders. That is not the same as running a dedicated tool over every blob.
   Roadmap G2.
6. **Policy denials leave no trace.** Neither the CLI nor the MCP server records an
   `outcome: denied` audit event, so a refused action cannot be diagnosed afterwards —
   the 2026-09-17 audit of a production blockage could not say which gate fired.
   Found 2026-09-17, not yet fixed. (The MCP result dropping the hint, found the same
   day, is fixed: every handler now renders the stable code and the hint.)
7. **One machine is enrolled, on one backend, in one region.** Real-vault behaviour
   is proven for macOS + `bws` 2.1.0 + the Bitwarden EU cloud, and for nothing else.
   The multi-device revocation story (C10) has not been exercised with real tokens.
8. **`docs/manifests.md` and `docs/mcp.md` describe an older shape.** The manifest
   doc still shows top-level `environments:` and `commands.<name>.executable/args`;
   the code takes `commands.<name>.environment/secrets/command`. The MCP doc shows
   `run_with_secrets` with `command` + `args`; the tool takes one `command` array.
   `DOC.md` and `agent-secrets.example.yaml` match the code. Found 2026-09-23, not
   yet rewritten — the 2026-09-23 entry only added the shared-project sections.

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

### 2026-09-23 — Keys shared across projects (`project/NAME`), and copying into one

**What happened.** An agent told the operator that a key had to be retyped into
`bxlabs`, the project they use as an organisation-wide store: `copy` only moved a
value between environments of one project, and a command could only read its own
project. The operator asked for organisation-level keys — one provider key used
everywhere — and chose, when asked, explicit `bxlabs/NAME` references over a
machine-local `@org` alias, and cross-project copy in the same pass.

**No organisation level was added to storage.** A shared project stays an ordinary
project: same grammar, same Bitwarden key encoding, same policy. What changed is
consumption. `resolveSelectors` (core) turns `NAME` or `project/NAME` into references
**in the command's environment** — a selector cannot name one, so a development
command can never reach `bxlabs/production` — and rejects two selectors that would
inject the same variable. There is deliberately no fallback from a missing bare name
to the shared project. Accepted by `run --keys`, manifest `secrets:`, and MCP
`run_with_secrets`.

**Authorisation, which is why the operator was asked first.** `run` is now asserted on
every scope a command reads (`scopesOf`), before the vault is contacted, so a shared
project decides whether its keys may be injected. `copy` across projects
(`--to-project`, MCP `toProject`) is level-or-upward, never down, never overwriting,
and asserts `copy` on the source as well as the target. Same-project copy is
unchanged. `run` audits one event per scope, so a shared key is attributed to its
project. Manifest approvals of existing entries are untouched; the selector is part
of `commandDigest`, so moving a key to a shared project is a new approval, and the
prompt names the shared projects.

**Not a widening of the manifest threat.** A manifest could already set `project:` to
any slug, so naming `bxlabs/NAME` reaches nothing a hostile manifest could not reach
before; the per-scope policy check is strictly more restrictive than what existed.

**Tests.** 18 new: selector grammar and ordering (core), cross-project `run` with
canaries, environment confinement, policy on the shared project with zero vault calls,
duplicate names, manifest selectors, dry run (CLI), cross-project copy direction and
source policy (CLI), and both MCP tools. 605 tests, `pnpm verify` green.

**Found on the way:** `docs/manifests.md` and `docs/mcp.md` document an older manifest
and tool shape — gap 8 above.

### 2026-09-17 (later) — Approval per command, the hint reaches the agent, and asking is allowed

**What happened.** Two more refusals in the same afternoon. The operator asked why
every production command of `olvia` had to be re-approved, and an agent was refused
`secret_add_request` for `VERCEL_TOKEN` in `ezjob/production` and could only relay
"the vault forbids it". Both were on the morning's list; the operator said yes.

**Manifest approval is now keyed per command.** `commandDigest` hashes a canonical
serialisation of the entry — project, command name, environment, secret names,
argument vector — and `isApproved`/`recordApproval` compare on that instead of the
file digest. Editing a command still revokes its own approval; adding or editing
another one, or a description, no longer touches it. Approvals recorded under the old
key simply stop matching and are asked once more — fail closed, one prompt. The
gate's security argument is unchanged: it is consent to a specific command line, and
that is now literally what is hashed. Pinned by four integration tests, including one
that plants an old-style file-digest approval and expects a refusal.

**The MCP path renders errors itself.** Every tool handler is wrapped by `guarded`,
which turns a throwable into `fail("<CODE>: <message> <hint>")` via `toSafeError`. A
policy denial now reaches the agent with the file and the exact key to add; an
unexpected throwable — the kind whose message can embed a value — reaches it as the
sanitised `INTERNAL` sentence rather than verbatim, which the SDK's default would
have forwarded. Tested both ways.

**`request-create` is allowed in production by default.** It is `create` one step
earlier: a link, or a hand-over command, that a human fills in out of band, reading
the name before typing. Denying it while allowing `create` meant an agent could not
even *ask* for a production secret, which is how `VERCEL_TOKEN` was about to travel
through a chat. `request-rotate` stays closed: it touches a live value. Threat model
§5 item 16 now names both. Decided by Antoine, 2026-09-17.

**Local policy** (same backup as the morning): `ezjob` and `4bl1ty` gain
`request-create` in production.

**Not done.** Denials are still not audited (gap 6). The Mac mini's policy file still
lists its own production `allow` for `ezjob`, which replaces the default rather than
extending it — `request-create` must be added there by hand.

### 2026-09-17 — A production blockage, and the copy that removes its commonest cause

**What happened.** The operator reported an agent refusing to work with
`olvia/production` and asked for the rules to be loosened. An audit came first, and
its main finding was that this machine's policy already granted `run` there: the
blockage was one of four other gates — the Mac mini's policy (which has no `olvia`
entry at all), `request-create`/`request-rotate` (granted to `bxlabs` only),
manifest approvals (every one of olvia's had been invalidated by later edits to
`agent-secrets.yaml`, and `realtime-brancher-openai` was never approved), or the
non-TTY production confirmation. Which one could not be determined, because
**no policy denial is ever audited** — the schema has `outcome: denied`, nothing
writes it — and the MCP path drops `PolicyDeniedError.hint`, so the agent could only
report "the vault forbids it". Both are now in the gap list above.

**The real cost, in the operator's words.** The same key serves development and
production; a policy that lets an agent *ask* for the production copy still sends the
human back to the provider — or to wherever they kept the value in between — to type
it a second time. That second trip is the store this product exists to replace.

**What was built: `copy`.** A new policy action and a matching command on both
surfaces:

* `agent-secrets copy NAME --project P --from development --to production`, and the
  MCP tool `secret_copy`. Both call one function, `copySecret` in
  `packages/cli/src/copy.ts`, so they make the same decisions in the same order:
  direction, policy on the target, source exists, target does not, resolve, create,
  dispose.
* The value goes backend → backend through the adapter. The CLI registers it with
  its redaction scope; the MCP handler never holds it where a result is built. Tests
  on both surfaces run the flow with a canary and assert it is absent from stdout,
  stderr, the tool result, the audit file and the config home — and present, intact,
  in the fake vault under the target key.
* **Upward only** (`development → preview → production`), same project, same name,
  **never overwrites** (`CONFLICT`, use `rotate`). Metadata rides along.
* **Default policy:** allowed into `preview`, denied into `production`. Unlike
  `create`, `copy` is reachable from the MCP toolset, so an injected agent could seed
  production with a name nobody asked for; opening it is a per-project line in a
  policy file, like `run`. `docs/threat-model.md` §5 item 16 records the residual
  risk.
* The MCP inventory is now **eight** tools. Still none returns a value; the count is
  corrected everywhere it was stated as a contract, and the enumeration test pins it.
* Audit operation `copy`, on the target reference.

**Decided by Antoine, 2026-09-17, and applied to this machine's policy file** (backup
at `policy.yaml.bak-2026-09-17`): `olvia/production` gains `request-create`,
`request-rotate` and `copy`; `ezjob`, `bxlabs` and `4bl1ty` gain `copy`. `rotate` and
`delete` stay closed everywhere in production.

**Not done.** Audit of denials, the MCP hint, per-command manifest approvals, and the
two 2026-08-29 findings — each is a gate or a sink and waits for a human decision. The
Mac mini's policy was not touched from here; `olvia` must be added there too or the
agent on that machine keeps hitting the built-in defaults. Also noticed:
`docs/mcp.md` §4 describes an `--mcp-policy strict|project` flag that `bin.ts` does
not implement — the only clamp is `AGENT_SECRETS_MCP_READ_ONLY=1`.

### 2026-08-29 — Two weeks of real use, two policy files, and a gate that is a wall

**What happened.** The operator reported the product in daily use for about two weeks
across two machines — a MacBook Air as the main personal computer, a Mac mini running
the AI agents — and confirmed the flow that matters works: the CLI hands over a
command, the human types the value at a hidden prompt, the application receives it,
and no value passes through a clipboard or a conversation. That is the first
sustained operational report this project has. Verifying it surfaced two defects,
both found by reading the code the operator's own policy file cited.

**The setup, and the divergence it created.** `config.json`, `policy.yaml` and
`audit.jsonl` all live under `~/.config/agent-secrets/`
(`packages/cli/src/config.ts:90-98`), so all three are per-machine. The Bitwarden
vault is the only shared state. Two machines therefore means two enrolments, two
policy files that nothing reconciles, and an audit trail split into halves that no
command joins.

This is not hypothetical. Read in-session on the MacBook Air: a 5698-byte
`policy.yaml`, last modified 2026-08-24, granting `run` in production to `ezjob`,
`bxlabs` and `olvia`, `request-create` to `bxlabs` alone, with `allowExecutables`
empty and `denyExecutables` re-declared by hand. The Mac mini's file was reported
second-hand as covering `bxlabs`, `ezjob` and `scaleway`, with an executable
allow-list of `aws`, `node`, `vercel`, `browser-use`, `pnpm` and `double`. The two
files share neither their project list nor their command lists. The same report held
that the Air might carry no policy file at all and fall back to the built-in
defaults; it carries one, and on production `run` it is the more permissive of the
two. Neither machine can see the other, so nobody could have known.

**Finding 1: `humanApproval` denies permanently. It does not gate.** `evaluate()`
refuses while the action sits in `humanApproval` and `context.approvalGranted` is not
true (`packages/core/src/policy.ts:238`). `approvalGranted` is set to `true` in
exactly four places, all of them in `packages/core/test/unit/policy.test.ts`. None of
the eleven `assert()` call sites — `commands/lifecycle.ts`, `commands/run.ts`,
`mcp-server/src/server.ts:114,137,158,181,213,250` — passes the field. `apps/telegram`,
the intended out-of-band channel, never touches it either. Three consequences:

* **The built-in default carries a dead branch.** `DEFAULT_ENVIRONMENT_RULES.preview`
  lists `request-create` and `request-rotate` under `humanApproval`
  (`packages/core/src/policy.ts:135`). On a fresh install with no policy file, the two
  MCP tools that exist to put a human in the loop are therefore denied permanently in
  `preview`, under a hint telling the caller to obtain approval and retry. Retrying
  cannot succeed.
* **The shipped example walks the reader into it.**
  `agent-secrets.policy.example.yaml:88-90` says to add `run` to this list *and* to
  `humanApproval` to allow a production deploy. Following that advice disables the
  deploy for good.
* **The tests prove a door works that nothing ever knocks on.** The unit suite grants
  an approval no caller grants, which is why 565 green tests never caught this.

The operator worked it out independently, left `humanApproval` empty deliberately, and
wrote the reasoning into the policy file header. That is the right local call. It is
also the product quietly losing a control it advertises: `docs/threat-model.md` leans
on human approval, and no deployment can currently use it. Nothing leaks as a result —
it fails closed, the correct direction — but the documented human-in-the-loop story is
fiction, and operators who follow the example are pushed to route around it.

**Finding 2: writing a policy file silently removes the executable deny-list.**
`defaultPolicy()` blocks `env`, `printenv` and six shells
(`packages/core/src/policy.ts:113`). The *file* schema defaults `denyExecutables` to
`[]`, and the whole `commands` block to `{ denyExecutables: [], allowExecutables: [] }`
(`packages/core/src/policy.ts:71-77`). A policy file with no `commands:` block
therefore permits `agent-secrets run -- env`, which prints every injected secret into
whatever is reading. The act of writing a policy — something people do to tighten a
grant — silently loosens the one list that stops the commonest accident, and it
contradicts the fail-closed rule the rest of this codebase keeps. The operator caught
it, re-declared the list by hand and added `eval`; nothing in the product would have
told them.

**Not done.** Nothing was fixed here. Both findings touch a production policy gate and
the approval path, which `CLAUDE.md` §8 reserves for a human decision. Four items
follow, none of which exists:

* wire `approvalGranted` to a real channel, or delete `humanApproval` and stop
  advertising it — the current middle state is the worst of the three;
* make the file schema inherit the built-in `denyExecutables` rather than defaulting
  to empty, or refuse a `commands` block that omits it;
* give the operator a way to see policy across machines: `doctor` reports on the
  machine it runs on, nothing reveals that two machines disagree, and nothing lints a
  policy for a rule that undoes itself;
* read the Mac mini's policy file on the Mac mini. If its `allowExecutables` really is
  `aws, node, vercel, browser-use, pnpm, double`, the list bounds the name of the
  binary and not what it does — `node` and `pnpm` both run arbitrary code — while
  `run` is allowed in production there.

### 2026-08-19 — The default that taught people to store credentials elsewhere

**What happened.** Running `agent-secrets add CLOUDFLARE_REGISTRAR_API_TOKEN --project
bxlabs --env production` was refused: `Action "create" is not allowed in
bxlabs/production`. Nothing was wrong with the command. `bxlabs` was simply not
declared in the operator's policy file, so evaluation fell back to
`DEFAULT_ENVIRONMENT_RULES`, where `production` allowed `list` and `describe` and
nothing else.

**Why the default was wrong.** It was written to keep an agent away from production
credentials, but it never did that, because an agent cannot reach `create` in the
first place. The MCP server asserts `request-create` and `request-rotate`
(`packages/mcp-server/src/server.ts:158,181`); there is no tool that asserts `create`.
And `create` is the one write that cannot destroy anything: `runAdd` refuses an
existing name with `ConflictError` (FR-ADD-005), so it adds or it fails. What the
default actually did was charge the human at the keyboard a hand-written YAML file for
the product's most ordinary act — which is how a credential ends up in a `.env`
instead.

**What changed.** `DEFAULT_ENVIRONMENT_RULES.production.allow` is now `list`,
`describe`, `create`. `rotate`, `delete` and `run` stay closed: each touches a value
production is already using, and opening one should leave a trace in a reviewed
commit. The narrowed promise is recorded in the threat model — an injected agent can
now talk a human into *storing* a credential nobody asked for, though it adds a name
rather than replacing one and the value never reaches the agent.

**The second bug, found on the way.** `PolicyDeniedError`'s hint said *"Adjust
agent-secrets.policy.yaml"* — a relative path nothing reads. `loadPolicy` opens only
`paths.policyFile` under the config home, deliberately, so a cloned repository cannot
grant itself production access (`packages/cli/src/context.ts:155`). Following that
hint meant editing a file in your project directory and seeing the same denial again,
which reads as a broken tool rather than a decision you can change. `PolicyEngine` now
takes an optional `policyFile`, passed by the CLI and the MCP binary, and the hint
names the absolute path and the exact key: `Add "delete" to
projects.ezjob.environments.production.allow in /…/policy.yaml`.

**Also.** `scripts/demo.mjs` step 6 demonstrated the refusal with a production `add`,
which now succeeds; it demonstrates a production `rotate` instead. `README.md`,
`DOC.md` §6.1, `docs/recovery.md`, `docs/threat-model.md` and
`agent-secrets.policy.example.yaml` were corrected in the same pass.

**Not done.** There is still no way to edit policy without hand-writing YAML in a
hidden directory. An `agent-secrets policy allow <project> <env> <action>` command
would close that; the corrected hint is a mitigation, not a fix.

### 2026-08-16 — The portable process: what every MCP client is told

Wiring the server into a client makes the tools reachable. It does not make an agent
*use* them, and an agent that never thinks to involve Agent Secrets solves a
credential problem the way credential problems have always been solved — a `.env`, a
shell variable, a value pasted into a chat — without breaking a single rule this
package enforces.

The server's `instructions`, sent once at initialize, are the only guidance that
reaches every client before the model has decided anything. They were nine lines. They
are now a card: what counts as a secret, that no tool returns a value, which action
answers which need, the four things never to do with a value (including *taking* one
from a `.env` as a fallback), what to say when a value lands in context anyway, and
that names reach the application unchanged. `SERVER_INSTRUCTIONS` is exported and
unit-tested rule by rule, with a length cap — a rule nobody reads is a rule that does
not exist.

Nothing was special-cased per client, and no tool was added: still exactly seven,
still no raw getter.

**Two documentation defects found while doing it.** `docs/mcp.md` §3 documented
`args: ["--project", "ezjob"]` and a `--policy` flag for `agent-secrets-mcp`. Neither
has ever existed — `bin.ts` reads no command-line arguments at all, taking the project
from the enrolment and the policy from `<config-dir>/policy.yaml`. Anyone following
that page built a mental model of a scope a client could choose, which is the opposite
of the design. The same file still carried the "planned, `src/` is empty" banner.

**And one defect of our own, caught by actually running the checks.** The
`bws-reachable` check added this morning ignored the path `init` pins in
`config.json`, so this very machine — enrolled, working, `doctor` green — was reported
`ready: false` with an instruction to export a variable it does not need. Fixed:
a pinned path satisfies the check. Both branches were re-run, enrolled and not.

**Limits, stated where they belong rather than implied.** `docs/mcp.md` §3 now has an
"Available is not the same as applied" section: a client may never surface
`instructions`; MCP cannot see what an agent does outside it, so a shell can write or
read a `.env` with no server involved; what is enforced in code is narrower and
absolute. The lever for turning the second half into a guarantee is the environment
the agent runs in — a sandbox, a separate OS user, an executable allow-list — not a
longer prompt.

Per-client configuration is now labelled by what we have actually run: Claude Code
(run here), Codex, OpenClaw and Hermes (documented shape, not executed). A snippet
nobody has run is a bug report waiting to happen.

### 2026-08-16 — The disclosure address exists, and the state sections were a year behind

`security@bxlabs.ai` was created. `bxlabs.ai` carries a Google Workspace MX record, so
the domain receives mail; the mailbox itself is the maintainer's word plus that
record, which is as far as verification goes without sending someone a test message.
`SECURITY.md` needed no change — it was simply true now. Roadmap G1 is ticked, with
the ordering violation recorded rather than tidied away: the repository went public
*before* the box that existed to prevent exactly that.

`conduct@bxlabs.ai` turned out to be a phantom. No published document references it —
`CODE_OF_CONDUCT.md` routes reports to `security@bxlabs.ai` — so G1 was asking for a
mailbox nothing pointed at. Requirement dropped rather than satisfied.

**The larger finding.** Checking that one gap exposed that the whole "Where things
stand" table and the entire "Known gaps" list had been false since the V1 commit:
they described a repository with one implemented package, no CI, no canary harness, a
broken `pnpm scan:secrets` and no issue templates. In reality every package ships, CI
runs the full gate set on every push and is green, and there are 540 tests. Every
session had followed `CLAUDE.md` §4.6 to the letter — append a dated entry — and the
letter only ever covered the timeline. Both sections are now rewritten, and §4.6 says
to correct state in the same pass, because the top of this file is what the next
reader trusts.

A targeted grep of the full commit history for credential shapes came back clean:
only obvious placeholders. G2 is marked partial — a pattern grep is not a dedicated
scanner over every blob, and saying otherwise would be the kind of overclaim this
file exists to prevent.

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
