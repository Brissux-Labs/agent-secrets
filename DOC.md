# DOC — durable behaviour reference

This is the reference for how Agent Secrets *behaves*: the reference grammar, the
command surface, the machine-readable output envelope, the exit-code contract, where
files live and with which permissions, and which environment variables are read.

> **Implementation status.** Everything in this document marked **planned** is
> specified but not built. Today only `@bx-labs/agent-secrets-core` exists, so the
> reference grammar, the error/exit-code mapping, the metadata and audit shapes, the
> policy semantics and the value rules are real; **every command described below is
> planned.** See [`ROADMAP.md`](ROADMAP.md) and [`CONTEXT.md`](CONTEXT.md).

Update this file whenever durable behaviour changes. If a behaviour is not written
here, it is not specified.

---

## 1. Canonical references

### 1.1 Grammar

```
reference  := [ backend "/" ] project "/" environment "/" name
scope      := [ backend "/" ] project "/" environment

backend      := "bitwarden"
project      := /^[a-z0-9][a-z0-9-]{0,62}$/
environment  := "development" | "preview" | "production"
name         := /^[A-Z][A-Z0-9_]{0,127}$/
```

Full form: `bitwarden/ezjob/development/OPENAI_API_KEY`
Shorthand: `ezjob/development/OPENAI_API_KEY` (backend defaults to `bitwarden`)

### 1.2 Rules

- **The backend may be omitted. The environment may not.** There is no default
  environment and no environment variable that supplies one. A missing environment is
  `INVALID_INPUT` / exit 2, never an inferred `production`.
- The grammar is narrow deliberately. It is the first defence against newline
  injection into `bws` arguments, path traversal in Keychain account identifiers, and
  HTML injection into the secure form. It is validated once, in
  `@bx-labs/agent-secrets-core`, and never re-parsed ad hoc.
- `name` is a valid POSIX environment variable name, because that is what it becomes
  inside `agent-secrets run`.
- Validation errors name the rejected **field**, never the rejected **content**. An
  error message never echoes what you submitted.

### 1.3 Storage encoding

One Bitwarden project holds every record for a given deployment. The canonical scope
is encoded into the Bitwarden secret **key**, so `project`, `environment` and `name`
survive a round-trip through the backend without a side table. The Bitwarden record
id is metadata (`backendId`) — it addresses a record, it says nothing about a value.

---

## 2. Command surface

All commands are **planned**.

### 2.1 Global flags

| Flag                  | Meaning                                                                 |
| --------------------- | ----------------------------------------------------------------------- |
| `--json`              | Emit the JSON envelope on stdout instead of human-readable output.       |
| `--project <slug>`    | Project slug. Defaults to `AGENT_SECRETS_PROJECT`, then to the manifest. |
| `--env <environment>` | `development` \| `preview` \| `production`. Required; never defaulted.   |
| `--backend <id>`      | Backend id. Defaults to `bitwarden`.                                     |
| `--config <dir>`      | Override the config directory.                                           |
| `--policy <path>`     | Override policy file discovery.                                          |
| `--no-audit`          | Discard audit events for this invocation instead of appending them.      |
| `--quiet`             | Suppress progress output. Errors still go to stderr.                     |
| `--version`, `--help` | Standard.                                                                |

There is deliberately **no** `--yes-to-everything`, **no** `--force` on a production
mutation, and **no** flag that prints a value.

### 2.2 `agent-secrets init`

Enrol this machine.

```bash
agent-secrets init [--device-name <label>] [--project-id <uuid>] \
  [--server-url <url>] [--executable-path <path>] [--force]
```

- Prompts for a Bitwarden Secrets Manager access token on a **hidden TTY**. The token
  is never accepted as an argument, from stdin in a pipe, or from an environment
  variable — all three are visible somewhere. Anything not supplied as a flag is asked
  for interactively; `init` therefore refuses to run under `--json`.
- `--server-url` is the Bitwarden base URL. It is required for any deployment that is
  not the US cloud, **including the EU cloud**: `--server-url https://vault.bitwarden.eu`.
  `bws` derives `<base>/identity` and `<base>/api` from it.
- `--executable-path` is the absolute path to `bws`. See "Locating `bws`" below —
  this is the flag that matters when the binary is not in a system directory.
- Generates a device id and writes the Keychain entry (see
  [`docs/device-enrollment.md`](docs/device-enrollment.md)).
- Creates the config directory at `0700` and `config.json` at `0600`.
- `--force` replaces an existing enrolment.
- The backend is probed **before** anything is written, so a failed enrolment leaves no
  config file and no credential behind.
- Audit: `init`.

**Exit:** 0 on success; 2 on malformed input or a non-interactive session; 3 if the
backend refused the access token or the machine account lacks permission; 5 if the
backend has no such project, or the token cannot see the project it was given; 6 if
this device is already enrolled and `--force` was not given; 7 if `bws` could not be
found, the backend was unreachable, or it answered in a shape this version does not
understand.

Each of those exits carries its own message. They used to be one sentence — "the
backend rejected this token, or is unreachable" — which named the one input the
operator cannot check without pasting a credential somewhere it must never go.

#### Locating `bws`

A bare `bws` is resolved against a **fixed list of directories**, not against your
`PATH`:

```
/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin
```

This is deliberate — a poisoned `PATH` entry is a cheap way to substitute a program
that captures the access token — and it has a consequence worth stating plainly: an
install in `~/.local/bin`, `~/bin`, or a release tarball unpacked anywhere else is
invisible to this tool even though `which bws` reports success. Point at it explicitly:

```bash
export AGENT_SECRETS_BWS_PATH=/absolute/path/to/bws   # persistent
agent-secrets init --executable-path /absolute/path/to/bws   # this enrolment only
```

Resolution order:

1. `--executable-path`, at `init` only;
2. the path recorded at enrolment in `config.json`;
3. `AGENT_SECRETS_BWS_PATH`;
4. a bare `bws` against the fixed list above.

Note that 2 beats 3, not the other way round. A path pinned at enrolment is a
reviewed decision in a `0600` file; an environment variable is ambient and inherited
by every process, and letting it redirect the binary that receives the access token
would reopen the substitution the fixed list exists to prevent. If a pinned path
stops being correct — the binary moved — re-run `init --force`, which is a
deliberate act that leaves an audit record.

The path chosen at `init` is persisted, so later commands spawn that exact binary
instead of repeating a search. `node scripts/preflight.mjs` and `agent-secrets doctor`
both report this case specifically.

### 2.3 `agent-secrets doctor` — planned

Diagnose the installation. Reads nothing sensitive, writes nothing.

```bash
agent-secrets doctor [--project <slug>] [--json]
```

Checks, in order:

1. Node version against `>= 22.11`.
2. `bws` binary present, executable, and its version.
3. Keychain entry present for this device and project.
4. Backend reachability and whether the credential can read and write
   (`SecretBackend.health()`). When the probe fails, the report carries both the
   stable `errorCode` and a `reason` from a closed vocabulary —
   `executable-not-found`, `unauthenticated`, `permission-denied`, `not-found`,
   `unreachable`, `timeout`, `rate-limited`, `incompatible-response`, `unknown` —
   so that a caller can tell "the binary is missing" from "the token was refused".
   Like `errorCode`, `reason` is chosen from the *shape* of the failure; no backend
   text ever reaches it.
5. Config directory and file permissions (`0700` / `0600`); a group- or
   world-readable config is reported as a failure, not a warning.
6. Policy file parses, or the built-in default is in force.
7. Audit file writable and append-only.

**Exit:** 0 when every check passes, 3 when enrolment is missing, 7 when the backend
is unreachable, 2 when the policy file is malformed.

### 2.4 `agent-secrets logout` — planned

```bash
agent-secrets logout [--project <slug>] [--all]
```

Deletes the Keychain entry for this device (and project, unless `--all`). Leaves the
audit log in place — removing your credential is not a reason to erase the record
that you had one. Audit: `logout`.

**Exit:** 0 on success, 0 if there was nothing to remove (idempotent), 5 only when an
explicitly named project has no entry.

### 2.5 `agent-secrets add` — planned

Create a secret that does not exist yet.

```bash
agent-secrets add --project <slug> --env <environment> --name <NAME> \
  [--description <text>] [--provider <id>] [--tag <tag>]... \
  [--allow-empty] [--allow-whitespace] [--max-bytes <n>] \
  [--via telegram]
```

- The value is typed at a **hidden prompt**, then typed a second time; the two are
  compared with a constant-time comparison. There is no `--value` flag and there
  never will be one — a value in `argv` is a value in `ps` and in your shell history.
- Value rules: non-empty, at most 64 KiB, no leading or trailing whitespace. Each can
  be relaxed by the corresponding flag. Rejections say *what rule* failed and nothing
  about the value.
- `--via telegram` skips the local prompt entirely and issues a one-time link to the
  enrolled Telegram account instead. Useful when the human is not at this terminal.
- Audit: `create` (or `request-create` for `--via telegram`).

**Exit:** 0; 2 on a value-rule or input failure; 4 if policy forbids `create` in that
environment; 6 if the secret already exists (use `rotate`); 7 if the backend is
unreachable.

### 2.6 `agent-secrets list` — planned

```bash
agent-secrets list --project <slug> --env <environment> \
  [--tag <tag>] [--provider <id>] [--json]
```

Metadata only: reference, name, provider, tags, description, timestamps, backend
record id, version marker. **No value, no length, no hash, no preview.** The result
schema is `.strict()`, so a future field named `preview` fails to parse rather than
shipping.

**Exit:** 0 (an empty list is success, not `NOT_FOUND`); 4 if policy forbids `list`;
7 if the backend is unreachable.

### 2.7 `agent-secrets describe` — planned

```bash
agent-secrets describe --project <slug> --env <environment> --name <NAME> [--json]
```

Same fields as `list`, for one record.

**Exit:** 0; 5 if the record does not exist; 4 if policy forbids `describe`.

### 2.8 `agent-secrets rotate` — planned

```bash
agent-secrets rotate --project <slug> --env <environment> --name <NAME> \
  [--allow-empty] [--allow-whitespace] [--max-bytes <n>] [--via telegram]
```

Identical ingestion path to `add`, except the record must already exist. Rotation
never reads the old value — it is not needed to replace it, so it is not read.

**Exit:** 0; 5 if the record does not exist; 4 if policy forbids `rotate` (which is
the default in `production`); 2 on a value-rule failure.

### 2.9 `agent-secrets delete` — planned

```bash
agent-secrets delete --project <slug> --env <environment> --name <NAME> --yes
```

- `--yes` is mandatory in a non-interactive context. Interactively, the operator
  retypes the secret's **name** (not its value) to confirm.
- Deletion in `production` is denied by the default policy and stays denied until a
  policy file says otherwise.

**Exit:** 0; 5 if the record does not exist; 4 if policy forbids `delete`.

### 2.10 `agent-secrets run` — planned

The only command that reads values, and the only place a value leaves the process.

```bash
agent-secrets run --project <slug> --env <environment> \
  [--secret <NAME>]... [--manifest <path>] [--all] [--timeout <ms>] \
  -- <command> [args...]
```

Behaviour, in order:

1. Resolve the secret set: `--secret` flags, else the manifest's entry for that
   environment, else `--all` for every secret in scope. An empty set is an error —
   `run` with nothing to inject is almost always a mistake.
2. Assert policy for `run`, including the executable deny/allow lists. The default
   deny list contains `env`, `printenv`, `sh`, `bash`, `zsh`, `dash`, `fish` and
   `ksh`: not because a denylist is sufficient (it is not; see
   [`docs/threat-model.md`](docs/threat-model.md)) but because it stops the common
   accident of piping an environment straight into a transcript.
3. Resolve the values in **one** batch call to the backend.
4. Build the child environment block: the parent environment plus one variable per
   secret. This is the single `expose()` call site in the command.
5. Spawn with an argument array. No shell, no string interpolation, ever.
6. Dispose of every `SecretValue` as soon as the child is spawned.
7. Stream the child's stdout and stderr through a redaction transform seeded with the
   resolved values, so a child that prints its own environment prints `[secret]`.
   Best effort: a child that base64-encodes the value defeats it, by design of
   reality rather than of this tool.
8. Write one audit event recording the executable **basename** and the secret
   **names** — never the argument vector, which routinely carries tokens.

**Exit semantics.** `run` exits **9** whenever the child exits non-zero or dies on a
signal; the child's own status is reported in the JSON envelope as
`data.childExitCode` and `data.signal`. It does *not* forward the child's exit code,
because exit codes 2–10 belong to this tool: a caller must be able to tell "policy
denied" from "the child happened to return 4", and the caller most likely to get
that wrong is an agent making a security decision.

`--propagate-exit-code` restores forwarding, so `agent-secrets run -- pytest`
exits exactly as `pytest` would. Use it in a shell or a CI step where you read the
result yourself; do not use it where an agent branches on the code.

Other exits: 2 on invalid input or an empty secret set; 4 on policy denial or a
denied executable; 5 if a named secret does not exist; 7 if the backend is
unreachable.

**Output.** The child's stdout and stderr are piped through a redaction transform
seeded with the values that were injected, so a child that prints its own
environment prints `[REDACTED]`. The transform keeps an overlap buffer, so a value
split across two writes is still caught.

The cost is that a piped child has no TTY: it may disable colour, and it cannot
drive an interactive prompt on stdout. `--pass-through-output` hands the child
this terminal directly for the cases that need it — and turns the filter off for
that run. The CLI warns every time it is used.

---

## 3. JSON output envelope

Every `--json` invocation writes exactly one JSON object to stdout, and nothing else.
Human-readable progress goes to stderr so that `--json` output is always parseable.

```jsonc
{
  "schemaVersion": 1,
  "status": "ok",
  "data": { /* command-specific */ }
}
```

On failure:

```jsonc
{
  "schemaVersion": 1,
  "status": "error",
  "data": {
    "code": "POLICY_DENIED",
    "message": "Action \"rotate\" is not allowed in ezjob/production.",
    "reference": "ezjob/production",
    "hint": "Adjust agent-secrets.policy.yaml if this action should be permitted."
  }
}
```

Guarantees:

- `schemaVersion` is `1`. It increments only on a breaking change to the envelope.
- The envelope object is `.strict()`: no extra top-level keys.
- `data` passes `assertNoValueFields` before it is written. A payload carrying a key
  named `value`, `secret`, `plaintext`, `preview`, `prefix`, `suffix`, `length`,
  `size`, `hash`, `digest`, `checksum`, `entropy` or `fingerprint` — at any depth —
  throws instead of serializing.
- Error `data` is the sanitized error shape: a stable `code`, a message assembled
  from constants and validated identifiers, and optionally `field`, `reference` and
  `hint`. The original throwable is kept on `cause` for local debugging and is never
  rendered by any sink.

### 3.1 Error codes

| `code`                | Exit | Meaning                                              |
| --------------------- | ---- | ---------------------------------------------------- |
| `INVALID_INPUT`       | 2    | Malformed reference, failed value rule, bad flag.     |
| `AUTH_REQUIRED`       | 3    | Not enrolled, or the device credential was rejected.  |
| `POLICY_DENIED`       | 4    | Policy, or a required human approval, said no.        |
| `NOT_FOUND`           | 5    | No such secret, project, or device entry.             |
| `CONFLICT`            | 6    | The record already exists, or enrolment collides.     |
| `BACKEND_UNAVAILABLE` | 7    | `bws` missing, unreachable, or answering unusably.    |
| `EXPIRED_OR_CONSUMED` | 8    | A one-time request is past TTL or already claimed.    |
| `CHILD_FAILED`        | 9    | The `run` child exited non-zero or died on a signal.  |
| `INTERNAL`            | 10   | Sanitized catch-all. Details withheld on purpose.     |

Full table with remediation guidance: [`docs/exit-codes.md`](docs/exit-codes.md).

---

## 4. Metadata shape

Returned by `list` and `describe`. `.strict()`, so nothing rides along.

| Field         | Type                                            | Notes                                    |
| ------------- | ----------------------------------------------- | ---------------------------------------- |
| `backend`     | `"bitwarden"`                                   |                                          |
| `project`     | slug                                            |                                          |
| `environment` | `development` \| `preview` \| `production`      |                                          |
| `name`        | `NAME`                                          |                                          |
| `reference`   | string                                          | Canonical `backend/project/environment/name`. |
| `backendId`   | string, optional                                | Addresses a record, not a value.         |
| `version`     | string, optional                                | Backend revision marker. Never derived from the value. |
| `description` | string ≤ 512, optional                          | Escaped at every render site.            |
| `provider`    | `/^[a-z0-9][a-z0-9.-]{0,63}$/`, optional        |                                          |
| `tags`        | array of `/^[a-z0-9][a-z0-9-]{0,31}$/`, optional| At most 16 on input.                     |
| `createdAt`   | ISO 8601, optional                              |                                          |
| `updatedAt`   | ISO 8601, optional                              |                                          |

There is no field describing the value. That is not an omission to be corrected.

---

## 5. Audit events

One JSON object per line, append-only. Fields are fixed by a `.strict()` schema and
checked by `assertNoValueFields` before any sink writes.

| Field               | Notes                                                              |
| ------------------- | ------------------------------------------------------------------ |
| `id`                | `evt_<uuid without dashes>`                                        |
| `timestamp`         | ISO 8601                                                           |
| `actorType`         | `human` \| `agent` \| `device` \| `telegram`                       |
| `actorId`           | Opaque: device id, Telegram numeric user id, MCP client name       |
| `deviceId`          | Optional                                                           |
| `operation`         | `init`, `logout`, `doctor`, `create`, `rotate`, `delete`, `list`, `describe`, `run`, `request-create`, `request-rotate`, `request-consume` |
| `reference`         | Canonical reference or scope; empty string for device operations   |
| `secretNames`       | Optional array of names — names only                               |
| `commandExecutable` | Optional. **Basename only, never the argument vector**             |
| `outcome`           | `success` \| `denied` \| `failure`                                 |
| `errorCode`         | Optional stable code                                               |
| `durationMs`        | Optional non-negative integer                                      |

Sinks: the CLI writes JSONL to `audit.jsonl` at `0600`; the API writes rows to
SQLite. Both go through the same `AuditSink` interface so the no-value assertion
happens exactly once.

---

## 6. Policy

### 6.1 Defaults

With no policy file present:

| Environment   | `allow`                                                                   | `humanApproval`                    |
| ------------- | ------------------------------------------------------------------------- | ---------------------------------- |
| `development` | `list`, `describe`, `request-create`, `request-rotate`, `create`, `rotate`, `delete`, `run` | —                 |
| `preview`     | `list`, `describe`, `request-create`, `request-rotate`, `run`             | `request-create`, `request-rotate` |
| `production`  | `list`, `describe`                                                        | —                                  |

Default command lists: `denyExecutables` is `env`, `printenv`, `sh`, `bash`, `zsh`,
`dash`, `fish`, `ksh`; `allowExecutables` is empty (meaning "no allow-list
restriction"). When `allowExecutables` is non-empty, it becomes exclusive.

### 6.2 Semantics

- **Deny by default.** An action absent from the applicable `allow` list is denied. A
  project or environment with no rule is denied.
- **A malformed policy file is a hard failure**, never a silent fall back to
  permissive defaults.
- **`humanApproval` is orthogonal to `allow`.** An action can be permitted *and*
  require a gate outside the model. The engine reports the requirement; the caller
  must obtain approval through a channel the agent does not control.
- **Enforced in code.** An agent that has been talked into requesting a production
  rotation still receives `POLICY_DENIED`, because the decision is made by the policy
  engine and not by a system prompt.
- Executable matching is on the **basename**, so `/bin/sh` and `sh` are one rule.

### 6.3 File format — planned loader

`agent-secrets.policy.yaml`, discovered in the project directory, overridable with
`--policy`:

```yaml
version: 1
projects:
  ezjob:
    environments:
      production:
        allow: [list, describe, rotate]
        humanApproval: [rotate]
commands:
  denyExecutables: [env, printenv, sh, bash, zsh, dash, fish, ksh]
  allowExecutables: []
```

The schema is `.strict()` at every level: an unknown key is an error, not a warning.
That YAML above is how you turn production rotation on. It is deliberately something
you have to write down, review and commit.

---

## 7. Files and permissions

### 7.1 CLI, per user — planned

Directory resolution: `$AGENT_SECRETS_CONFIG_DIR`, else `$XDG_CONFIG_HOME/agent-secrets`,
else `~/.config/agent-secrets`.

| Path                                    | Mode   | Contents                                                  |
| --------------------------------------- | ------ | --------------------------------------------------------- |
| `<config-dir>/`                         | `0700` | —                                                          |
| `<config-dir>/config.json`              | `0600` | Device id, device label, default project, backend id, API base URL, `bws` path. **No credential.** |
| `<config-dir>/audit.jsonl`              | `0600` | Append-only audit events, one JSON object per line.        |
| `<config-dir>/policy.yaml`              | `0600` | Optional user-level policy, overridden by a project file.  |

The Bitwarden access token is **not** in any of these. It lives in the macOS Keychain
under service `Agent Secrets Bitwarden Access Token`, account `<device-id>:<project-id>`.
See [`docs/device-enrollment.md`](docs/device-enrollment.md).

`doctor` treats a group- or world-readable config file as a failed check.

### 7.2 Project files — planned

| Path                          | Committed? | Contents                                        |
| ----------------------------- | ---------- | ----------------------------------------------- |
| `agent-secrets.yaml`          | **yes**    | Manifest: references only, never values. See [`docs/manifests.md`](docs/manifests.md). |
| `agent-secrets.policy.yaml`   | **yes**    | Policy document. Reviewable by design.          |

### 7.3 API server — planned

| Path                             | Mode   | Contents                                              |
| -------------------------------- | ------ | ----------------------------------------------------- |
| `<data-dir>/`                    | `0700` | —                                                     |
| `<data-dir>/agent-secrets.sqlite`| `0600` | One-time request rows and server-side audit events. **No value column exists in any migration.** |

`data/` is in `.gitignore`, as are `*.sqlite`, `*.sqlite-journal`, `*.sqlite-wal` and
`*.sqlite-shm`.

---

## 8. Environment variables

### 8.1 CLI — planned

| Variable                    | Effect                                                              |
| --------------------------- | ------------------------------------------------------------------- |
| `AGENT_SECRETS_CONFIG_DIR`  | Overrides the config directory.                                     |
| `AGENT_SECRETS_PROJECT`     | Default for `--project`.                                            |
| `AGENT_SECRETS_BACKEND`     | Default for `--backend`. Only `bitwarden` is valid in V1.           |
| `AGENT_SECRETS_BWS_PATH`    | Absolute path to the `bws` binary. Needed whenever it is not in one of the directories listed in §2.2, which includes every `~/.local/bin`-style install. Overridden by `--executable-path`; overrides the path recorded at enrolment. |
| `AGENT_SECRETS_API_URL`     | Base URL of your one-time form API, e.g. `https://secrets.example.invalid`. |
| `NO_COLOR`                  | Standard. Disables styling.                                         |

**There is deliberately no variable that supplies a default environment.** Adding
`AGENT_SECRETS_ENV` would recreate exactly the accident the reference grammar exists
to prevent: a command that silently targets production because a shell profile said
so three months ago.

**There is deliberately no variable that supplies the Bitwarden access token.** An
environment variable is inherited by every child process, which is the opposite of
what a device credential should be.

`AGENT_SECRETS_TELEMETRY` is reserved and pinned to `0` in the test environment as a
belt-and-braces assertion. There is no telemetry code path to enable; the variable
exists so that a future reviewer grepping for it finds this paragraph.

### 8.2 API server — planned

| Variable                      | Effect                                                          |
| ----------------------------- | ---------------------------------------------------------------- |
| `AGENT_SECRETS_API_PORT`      | Listen port.                                                     |
| `AGENT_SECRETS_API_BASE_URL`  | Public HTTPS origin used to build one-time links.                |
| `AGENT_SECRETS_DB_PATH`       | SQLite file path.                                                |
| `AGENT_SECRETS_API_TOKEN`     | Shared token authenticating the Telegram adapter to the API.     |
| `AGENT_SECRETS_REQUEST_TTL_MS`| One-time request TTL. Defaults to `120000`. Values above 300000 are refused. |

### 8.3 Telegram adapter — planned

| Variable                          | Effect                                                      |
| --------------------------------- | ------------------------------------------------------------ |
| `TELEGRAM_BOT_TOKEN`              | Bot token from BotFather.                                    |
| `AGENT_SECRETS_TELEGRAM_ALLOWLIST`| Comma-separated numeric Telegram user ids. Empty means the bot answers nobody. |
| `AGENT_SECRETS_API_URL`           | Where to create one-time requests.                           |
| `AGENT_SECRETS_API_TOKEN`         | Must match the API's value.                                  |

Server-side tokens live in your process manager's secret store, not in a `.env` file
in the repository. `.env` and `.env.*` are gitignored precisely because someone will
try.

---

## 9. What never appears anywhere

Restating the contract in the terms this document uses, because it is the reason for
every design above:

A raw value must never reach a log, a terminal, an error message, a tool result, a
model context, a database row, a process argument, a git object, or a test artifact.
It has exactly three legitimate destinations: the backend vault via the backend
adapter, the environment block of a child spawned by `agent-secrets run`, and the
request body of the secure input form in transit between browser and adapter.

Anything else is a defect, whether or not a test catches it. See
[`docs/logging.md`](docs/logging.md) for the field-level rules, including why a value's
**length** and its **hash** are treated as disclosure.
