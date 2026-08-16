# Exit codes

Exit codes are a **public contract**. Scripts branch on them and agents branch on
them, so changing one is a breaking change and requires a major version bump.

They are defined once, in `EXIT_CODES` in `@bx-labs/agent-secrets-core`, and every
domain error carries the code it maps to. There is no path by which an unexpected
throwable escapes as exit 1: the CLI's top-level handler converts anything it does not
recognise into `INTERNAL` / exit 10.

> **Status.** The mapping and the error hierarchy are implemented in the core. The CLI
> that emits these codes is **planned**.

---

## The table

| Exit | Error code            | Meaning                                              | Retry? |
| ---- | --------------------- | ---------------------------------------------------- | ------ |
| 0    | —                     | Success.                                              | —      |
| 2    | `INVALID_INPUT`       | Malformed reference, missing environment, failed value rule, bad flag. | No — fix the input |
| 3    | `AUTH_REQUIRED`       | Not enrolled, or the device credential was rejected.  | No — enrol or re-enrol |
| 4    | `POLICY_DENIED`       | Policy said no, or a human approval is required.      | No — not without a policy change or an approval |
| 5    | `NOT_FOUND`           | No such secret, project, or device entry.             | No |
| 6    | `CONFLICT`            | The record already exists, or enrolment collides.     | No — use the other verb |
| 7    | `BACKEND_UNAVAILABLE` | `bws` missing, unreachable, or answering unusably.    | **Yes**, with backoff |
| 8    | `EXPIRED_OR_CONSUMED` | A one-time request is past its TTL or already claimed.| No — request a new link |
| 9    | `CHILD_FAILED`        | The `run` child exited non-zero or died on a signal.  | Depends on the child |
| 10   | `INTERNAL`            | Sanitized catch-all. Details withheld on purpose.     | Once, then escalate |

Note the gap: **1 is never used deliberately.** If you see exit 1 from an
`agent-secrets` process, something crashed before our handler was installed, or you
are looking at a different program. Treat it as exit 10 and report it.

---

## Code by code

### 0 — Success

The operation completed. With `--json`, stdout carries exactly one envelope with
`"status": "ok"`.

An empty result is success, not `NOT_FOUND`: `list` on a scope with no secrets exits
0 with an empty array. "There are none" is a valid answer to "which are there".

**What to do:** proceed.

---

### 2 — `INVALID_INPUT`

**Emitted when:**

- the reference is malformed — a project slug that is not
  `^[a-z0-9][a-z0-9-]{0,62}$`, a name that is not `^[A-Z][A-Z0-9_]{0,127}$`, an
  unknown backend;
- **the environment is missing.** It is never inferred, and `production` is never
  guessed;
- a value rule fails: empty, over 64 KiB, or with leading/trailing whitespace;
- `run` resolves an empty secret set;
- a flag combination is contradictory;
- the policy file or the manifest fails to parse — a malformed policy is a hard
  failure, never a fall back to permissive defaults.

**What a script should do:** fix the invocation. Retrying identical input produces an
identical failure. The error carries `field` naming the rejected input — and never its
content, so do not expect the message to tell you what you typed.

**What an agent should do:** re-read the reference grammar, correct the argument, and
try once. If the same field is rejected twice, stop and ask the human; do not begin
permuting values.

---

### 3 — `AUTH_REQUIRED`

**Emitted when:**

- no Keychain entry exists for this device and project — the machine is not enrolled;
- the Bitwarden access token is expired, revoked, or rejected;
- the Keychain is locked and access cannot be obtained.

**What a script should do:** stop. This needs a human at a terminal running
`agent-secrets init`. Do not retry in a loop — a revoked token will not un-revoke, and
repeated attempts against the backend look like an attack.

**What an agent should do:** report to the human that enrolment is required, and stop.
An agent must never attempt to obtain or supply a credential itself; there is
deliberately no environment variable and no flag that would let it.

**Related:** [`device-enrollment.md`](device-enrollment.md), [`recovery.md`](recovery.md).

---

### 4 — `POLICY_DENIED`

**Emitted when:**

- the action is not in the applicable `allow` list — most commonly a mutation in
  `production`, which the default policy denies;
- the project or environment has no rule at all, and deny-by-default applies;
- the executable is on `denyExecutables`, or `allowExecutables` is non-empty and the
  executable is not on it;
- the action requires human approval and none has been granted.

The error's `hint` distinguishes the two remedies: adjust
`agent-secrets.policy.yaml`, or obtain approval through a channel the agent does not
control.

**What a script should do:** stop and surface the reason. A policy denial is a
decision, not a transient condition.

**What an agent should do:** **stop, and report the denial verbatim.** Do not retry
with different arguments, do not try a different environment, do not try a different
command that achieves the same effect, and do not ask the user to relax the policy as
part of completing the current task. Policy is enforced in code precisely so that no
amount of reasoning changes the answer — an agent that treats a denial as an obstacle
to route around is exhibiting the behaviour this product exists to contain.

---

### 5 — `NOT_FOUND`

**Emitted when:** `describe`, `rotate` or `delete` targets a secret that does not
exist; `run` names a secret that does not exist in scope; `logout` targets an
explicitly named project with no entry.

Not emitted for an empty `list` (that is 0), and not for an unenrolled device (that
is 3).

**What a script should do:** if you were rotating, the secret may need `add` instead.
Check the reference before assuming absence — a typo in `environment` produces exactly
this.

**What an agent should do:** `list` the scope to see what actually exists, then either
correct the reference or tell the human the secret must be created. Do not create a
production secret to resolve a `NOT_FOUND`; that decision belongs to a human.

---

### 6 — `CONFLICT`

**Emitted when:** `add` targets a reference that already exists; `init` finds an
existing Keychain entry without `--force`.

**What a script should do:** use `rotate` to replace a value, or `--force` to
re-enrol. The distinction between `add` and `rotate` is deliberate: replacing a live
credential should require saying so.

**What an agent should do:** report the conflict. Do not silently escalate `add` to
`rotate` — the human asked to create something, and something else is already there,
which is information they need.

---

### 7 — `BACKEND_UNAVAILABLE`

**Emitted when:** the `bws` binary is missing or not executable; Bitwarden is
unreachable or times out; the backend returns a response that fails schema validation;
the subprocess exceeds its timeout or output cap.

Note the third case: **unparsable output is treated as unavailability**, not as a
parsing curiosity. We fail closed rather than guess at a malformed response.

**What a script should do:** this is the one code worth retrying. Exponential backoff,
a small number of attempts, then escalate. In CI, fail the job — do not fall back to
an environment variable, which is exactly the degradation Agent Secrets exists to
remove.

**What an agent should do:** retry once or twice with backoff, then report an outage
and stop. Do not work around it by reading credentials from another source.

**Related:** [`recovery.md`](recovery.md) — Bitwarden outage runbook.

---

### 8 — `EXPIRED_OR_CONSUMED`

**Emitted when:** a one-time link is opened or submitted after its 2-minute TTL; or it
has already been claimed. Both cases return the same code and the same message on
purpose — distinguishing "expired" from "already used" tells an attacker whether they
found a real link.

This is the code produced by the atomic claim affecting zero rows. When it fires, **no
backend call was made**: nothing was written.

**What a script should do:** request a new link. Never build a retry loop that
re-submits the same token; every attempt is audited and rate-limited.

**What an agent should do:** report that the request expired and that a new one is
needed. The agent cannot open the link itself — it never receives one — so this is
always a message to a human.

---

### 9 — `CHILD_FAILED`

**Emitted when:** the child spawned by `agent-secrets run` exits non-zero, is killed
by a signal, or fails to start.

**`run` does not forward the child's exit code.** With `--json`, the child's real
status is in `data.childExitCode` and `data.signal`; the process itself exits 9.

The reason: exit codes 2–10 belong to this tool. If `run` forwarded a child's exit
code 4, a caller could not distinguish "policy denied" from "the child returned 4" —
and the caller most likely to get that wrong is an automated one making a security
decision.

`--propagate-exit-code` exists for callers who want the ambiguity: with it,
`agent-secrets run -- pytest` exits exactly as `pytest` would. Use it in a shell or a
CI step where you are the one reading the result; do not use it where an agent
branches on the code.

**What a script should do:** treat 9 as "your command failed" and read
`data.childExitCode` for the detail. Critically: **9 means the secrets were resolved,
policy passed, and the child ran.** The failure is in your command, not in the broker.

**What an agent should do:** debug the child command normally. Do not re-run with
different secrets, and do not conclude that a credential is wrong from exit 9 alone —
read the child's own output, which is available (redacted).

---

### 10 — `INTERNAL`

**Emitted when:** anything unexpected happens. `toSafeError` wraps the original
throwable, keeps it on `cause` for local debugging, and takes **nothing** from its
message, because a `bws` or `spawn` failure message can embed a value or a token.

The message you see is deliberately unhelpful: *"An internal error occurred. Details
were withheld to avoid leaking a secret value."* That is not politeness; it is the
control. An error message is a sink like any other.

**What a script should do:** retry once in case it was transient, then escalate. Do
not parse the message — it is a constant.

**What an agent should do:** stop and report. Do not try variations to "see if it
works this time"; an internal error means the tool is in a state it does not
understand, and a security tool in an unknown state should not be prodded.

**Reporting one:** include the command, the reference, the version, and the timestamp
so it can be matched against the audit record. **Do not include a real credential**,
and do not attach a debugger's `cause` output without reading it first — see
[`SECURITY.md`](../SECURITY.md).

---

## Branching on exit codes

Shell:

```bash
agent-secrets run --project ezjob --env development -- pnpm test
case $? in
  0)  echo "ok" ;;
  2)  echo "bad invocation — fix the arguments"; exit 1 ;;
  3)  echo "this machine is not enrolled: run agent-secrets init"; exit 1 ;;
  4)  echo "policy denied — this is a decision, not an obstacle"; exit 1 ;;
  5)  echo "secret not found in that scope"; exit 1 ;;
  7)  echo "backend unavailable — retry with backoff"; exit 1 ;;
  9)  echo "the child command failed"; exit 1 ;;
  10) echo "internal error — report it"; exit 1 ;;
esac
```

JSON, when you want the detail:

```bash
out=$(agent-secrets run --json --project ezjob --env development -- pnpm test)
code=$?
[ "$code" -eq 9 ] && echo "child exited $(printf '%s' "$out" | jq -r '.data.childExitCode')"
```

The envelope's `data.code` always agrees with the process exit code. If they ever
disagree, that is a bug worth reporting.

## Rules for anyone changing this file

- Codes are stable. Adding a new one is a minor change; changing or reusing an
  existing one is major.
- Every new domain error subclass maps to an existing code unless there is a genuinely
  new category, and a new category needs a human decision.
- Exit 1 stays unused, so that "crashed before our handler ran" remains
  distinguishable from "failed in a way we understand".
- Update `EXIT_CODES` in the core, this file, and [`DOC.md`](../DOC.md) in the same
  commit. A divergence between them is a defect in the public contract.
