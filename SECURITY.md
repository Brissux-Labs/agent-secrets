# Security policy

Agent Secrets exists to keep credentials out of places they should never reach. A
vulnerability here is not a broken build — it is somebody's production key in a
transcript. We take reports seriously and we would rather hear about a false alarm
than not hear about a real one.

---

## Reporting a vulnerability

**Email `security@bxlabs.ai`.**

> **Maintainer note — action required before this repository goes public.**
> Confirm that `security@bxlabs.ai` is a real, monitored mailbox and that someone
> reads it. A published disclosure address that bounces is worse than publishing no
> address at all, because a reporter who bounces usually goes public instead. This
> note stays in the file until the mailbox is verified.

**Do not open a public GitHub issue, discussion, or pull request for a security
issue.** Do not post it in a public chat. If a fix is obvious to you, it is obvious to
whoever reads the issue before we do.

If you cannot email, open a **GitHub private security advisory** on the repository
(Security → Advisories → Report a vulnerability). That channel is private to the
maintainers.

### Never send a real credential

**Do not include a real API key, token, password, or any other live credential in a
report** — not in the body, not in a screenshot, not in an attached log, not in a
reproduction repository, not "redacted" by hand.

If your finding requires a credential to demonstrate, generate a fake one. Our own
tests use values of the form `ASECRET_CANARY_<random>` for exactly this purpose;
please do the same. If you have already sent us a real credential, tell us in your
next message so we can treat it as an incident on our side, and **rotate it
immediately** on yours.

### What to include

- Which component: CLI, Bitwarden adapter, one-time form API, Telegram adapter, MCP
  server, or the domain core.
- Version or commit hash.
- Reproduction steps, ideally with a fake canary value in place of a real secret.
- The impact you believe it has, in plain terms — what an attacker gets.
- Whether you have disclosed it anywhere else, and any deadline you intend to apply.

### What we will do

| Stage                       | Target                                                  |
| --------------------------- | ------------------------------------------------------- |
| Acknowledgement             | 2 business days                                          |
| Initial assessment and severity | 5 business days                                      |
| Fix or documented mitigation for a critical issue | 14 days               |
| Fix for high severity       | 30 days                                                  |
| Fix for medium or low       | Next release, or documented as accepted risk             |
| Public advisory             | After a fix is available, coordinated with you           |

We will keep you updated even when the answer is "still working on it". We will credit
you in the advisory unless you ask us not to. We do not currently run a bug bounty and
we will not pretend otherwise.

If we conclude a report is not a vulnerability, we will say so and explain why. If you
disagree, say so — we have been wrong before.

---

## Supported versions

| Version | Status                                                                    |
| ------- | ------------------------------------------------------------------------- |
| `0.1.x` | **Pre-release, in development. Not published, not supported, not for production use.** |

Once V1 ships, security fixes land on the latest minor release. Older minors get
fixes only for critical issues, and only until the next minor is out. This table is
updated at every release; if it still says "pre-release", nothing has shipped.

---

## Scope

**In scope**

- Any path by which a raw secret value reaches a log, a terminal, an error message, a
  tool result, a model context, a database row, a process argument, a git object, or a
  test artifact.
- Anything that lets a caller retrieve a value they are not entitled to: a policy
  bypass, a missing check, a reference that escapes its scope.
- One-time request weaknesses: token predictability, a replayable or non-atomic claim,
  TTL bypass, binding confusion between users or references.
- Telegram adapter weaknesses: allowlist bypass, command injection, a link issued to
  the wrong chat.
- MCP weaknesses: a default tool that can return a value, a policy check that can be
  bypassed by argument shaping, an execution path that escapes the executable lists.
- Subprocess handling: anything that reintroduces a shell, argument injection into
  `bws`, or an error path that echoes stderr containing a value.
- Insecure file permissions on config, audit or database files.
- Supply-chain issues in our published packages: a dependency that can observe a
  value, a compromised release artefact.

**Out of scope**

- Vulnerabilities in Bitwarden Secrets Manager, the `bws` CLI, Telegram, Node.js, or
  npm. Report those upstream; tell us if we need to react.
- An attacker who already has code execution as your OS user. See the limitations
  below — we do not claim to defend against that and never will.
- Missing hardening that has no demonstrated impact ("you should use header X").
  Welcome as a normal issue, not as a vulnerability report.
- Social engineering of maintainers.
- Automated scanner output with no analysis attached.

---

## Honest limitations

These are not bugs. They are the shape of the problem, and we would rather write them
down than let a reader assume otherwise. [`docs/threat-model.md`](docs/threat-model.md)
covers the full analysis.

**1. An unrestricted agent running as your OS user can invoke permitted
secret-consuming commands.** Agent Secrets stops an agent from *reading* a value. It
does not stop an agent that is allowed to run `agent-secrets run -- deploy.sh` from
running it. If the agent can execute the command, it gets the command's effects. The
defences that matter here are the executable allow-list, the environment policy, and
not giving an agent unattended shell access in `production`.

**2. Environment injection exposes the value to the child and everything it spawns.**
`agent-secrets run` puts the value in a child process environment. That child, and
every descendant it creates, can read it, print it, upload it, or write it to disk.
Our redaction filter catches the naive cases — a child that echoes its environment —
and catches nothing from a child that encodes the value first. Injecting a secret into
a program is trusting that program. There is no version of this tool where that stops
being true.

**3. Memory wiping is best effort.** `SecretValue.dispose()` drops our reference to
the string. JavaScript strings are immutable and garbage-collected, so we cannot
guarantee the bytes leave process memory, and we cannot prevent them reaching swap or
a core dump. Anyone who tells you they can zero a secret in a managed runtime is
describing an intention, not a guarantee.

**4. A denylist of executables is porous.** `sh`, `bash` and `env` are denied by
default because they are the common accident, not because denying them is sufficient.
A determined caller reaches a shell through a hundred other binaries. Use
`allowExecutables` when you actually need a boundary.

**5. Telegram sees command metadata.** The value never travels through Telegram, but
the reference does, and so does the one-time URL. See
[`docs/telegram-security.md`](docs/telegram-security.md), including what happens when
a human pastes a value by mistake — deleting the message does not undo it.

**6. The one-time link is a bearer token for two minutes.** Anyone holding the URL
within its TTL can submit the form once. It is bound to a user, a reference and an
action, and it is claimed atomically, so it cannot be replayed — but it is not bound
to a device. Treat a leaked link as a leaked write capability and see
[`docs/recovery.md`](docs/recovery.md).

**7. We depend on Bitwarden.** If your Bitwarden organisation is compromised, Agent
Secrets does not help you. We are the interaction layer; the vault's security is the
vault's.

**8. Nothing here is audited yet.** No third party has reviewed this code. The threat
model has not been reviewed by anyone who did not write it. That review is a blocking
item for the public release; until it happens, calibrate your trust accordingly.

---

## Our own commitments

- No telemetry, no analytics, no phone-home — not opt-in, not anonymised.
- No cryptography of our own invention. `node:crypto` primitives for randomness,
  hashing and constant-time comparison, and nothing more.
- No dependency that can observe a value is added without human review; the version
  catalog in `pnpm-workspace.yaml` exists so that review is a one-file exercise.
- Every child process is spawned with an argument array and no shell.
- Values, and everything derived from them — length, hash, prefix, entropy estimate —
  stay out of every log sink. See [`docs/logging.md`](docs/logging.md).
- Releases are published with provenance and signed tags once V1 ships.
