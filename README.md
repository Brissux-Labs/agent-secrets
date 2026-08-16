# Agent Secrets

**An open-source secret broker for AI agents.**

Agent Secrets lets a human make a credential available to an agent-driven workflow
**without ever pasting it into a conversation, a source file, a shell argument, a git
commit, a model context, or a log**.

That is the whole product in one sentence. Everything below exists to make that
sentence true rather than aspirational.

---

## The problem

You are working with a coding agent. It needs `OPENAI_API_KEY` to run the test suite.
Today your options are all bad:

- paste the key into the chat — it is now in the model context, the provider's logs,
  and your terminal scrollback;
- put it in `.env` — it is one `cat` away from the model context, and one `git add -A`
  away from your history;
- export it in your shell — it is in `ps`, in your shell history, and inherited by
  every process the agent spawns.

Agent Secrets gives the agent a fourth option: it can *ask* for a secret, *use* a
secret, and *reason about* a secret's existence, without ever being able to read one.

## What it is

A broker, not a vault. Storage is [Bitwarden Secrets Manager](https://bitwarden.com/products/secrets-manager/);
Agent Secrets adds the interaction layer that is missing around it:

- a **CLI** (`agent-secrets`) that reads values into a child process environment and
  nowhere else;
- a **Telegram flow** where the bot never receives the value — it hands back a
  one-time HTTPS link to a minimal form, and the value travels from the browser to
  the vault;
- an **MCP server** exposing metadata and controlled execution to agents, with **no
  raw-value tool in the default toolset**;
- **multi-device support**, where each machine holds its own revocable backend token
  in the macOS Keychain.

## What it is **not**

- **Not a vault.** It stores nothing itself. Bitwarden holds the ciphertext.
- **Not a password manager.** No browser autofill, no shared logins, no TOTP.
- **Not an enterprise policy engine.** The policy model is a small, readable,
  deny-by-default YAML file — not RBAC, not SCIM, not an approval workflow product.
- **Not a way to hide a secret from a program you deliberately run.** Once a value is
  injected into a child process environment, that child and its descendants can read
  it. See [`docs/threat-model.md`](docs/threat-model.md), which says so bluntly.

## Current status

> **Pre-release. V1 in development. Nothing is published to npm yet.**
>
> What exists today is the monorepo skeleton and the domain core
> (`@bx-labs/agent-secrets-core`): canonical references, sanitized errors, metadata
> and audit schemas, the policy engine, value rules, and the `SecretValue` wrapper.
> The CLI, the Bitwarden adapter, the Telegram bot, the API and the MCP server are
> **designed and specified but not implemented**.
>
> [`ROADMAP.md`](ROADMAP.md) tracks it item by item and
> [`CONTEXT.md`](CONTEXT.md) records what is deliberately unfinished. Do not deploy
> this yet.

---

## 60 seconds, once V1 ships

Everything in this section is the **planned** V1 path. It does not work yet.

```bash
# 1. Install the CLI. The unscoped name was taken on npm, so the package is scoped;
#    the binary it installs is still called `agent-secrets`.
npm install -g @bx-labs/agent-secrets

# 2. Enrol this machine. Prompts for a Bitwarden Secrets Manager access token on a
#    hidden TTY and stores it in the macOS Keychain. The token never touches a file.
agent-secrets init

# 3. Check the plumbing: Keychain entry, bws binary, backend reachability, policy.
agent-secrets doctor

# 4. Add a secret. The value is typed on a hidden prompt, never as an argument.
agent-secrets add --project demo-app --env development --name EXAMPLE_API_KEY

# 5. Run something with it. The value exists only in the child's environment block.
agent-secrets run --project demo-app --env development -- pnpm test
```

From Telegram, the same `add` never puts the value in the chat:

```
you → /add demo-app development EXAMPLE_API_KEY
bot ← Open this once, within 2 minutes:
      https://secrets.example.invalid/f/PLACEHOLDER-ONE-TIME-TOKEN
```

You type the value into that page. The bot never sees it. Telegram never sees it.

> Every credential-looking string in this repository — docs, examples, tests — is a
> placeholder. `EXAMPLE_API_KEY`, `secrets.example.invalid` and
> `PLACEHOLDER-ONE-TIME-TOKEN` are not real and are not meant to look real.

## Canonical references

Every secret has exactly one address:

```
backend/project/environment/name
bitwarden/ezjob/development/OPENAI_API_KEY
```

- `backend` — `bitwarden` in V1; may be omitted, in which case it defaults.
- `project` — `^[a-z0-9][a-z0-9-]{0,62}$`
- `environment` — `development` | `preview` | `production`. **Never inferred.** An
  omitted environment is an error, because the one thing worse than a failed command
  is a command that silently guessed `production`.
- `name` — `^[A-Z][A-Z0-9_]{0,127}$`, i.e. a valid environment variable name.

## Default policy

Restrictive on purpose, and enforced in code rather than in a prompt:

| Environment   | Allowed by default                                            |
| ------------- | ------------------------------------------------------------- |
| `development` | full lifecycle — list, describe, request, create, rotate, delete, run |
| `preview`     | list, describe, run, and requests that need human approval     |
| `production`  | **list and describe only** — mutation is off until you enable it explicitly in a policy file |

## Architecture

```
        ┌────────────┐        ┌──────────────┐        ┌─────────────────┐
        │   Human    │        │  AI agent    │        │  Any MCP client │
        │ (terminal) │        │ (Claude Code,│        │                 │
        └─────┬──────┘        │   Codex, …)  │        └────────┬────────┘
              │               └──────┬───────┘                 │
              │ hidden TTY prompt    │  metadata + run only    │
              ▼                      ▼                         ▼
        ┌──────────────────────────────────────────────────────────────┐
        │  agent-secrets CLI            @bx-labs/agent-secrets         │
        │  ┌────────────────────────────────────────────────────────┐  │
        │  │ policy engine · redaction · JSONL audit (0600)         │  │
        │  └────────────────────────────────────────────────────────┘  │
        └───────────┬───────────────────────────────────┬──────────────┘
                    │                                   │
                    │ argument array, no shell          │ env block only
                    ▼                                   ▼
        ┌───────────────────────────┐          ┌──────────────────────┐
        │  bws  (Bitwarden CLI)     │          │  child process       │
        │  ▲ macOS Keychain token   │          │  (pnpm test, …)      │
        └───────────┬───────────────┘          └──────────────────────┘
                    │ HTTPS
                    ▼
        ┌───────────────────────────┐
        │ Bitwarden Secrets Manager │   ← the only place a value rests
        └───────────────────────────┘
                    ▲
                    │ HTTPS form POST — the value's other legitimate path
        ┌───────────┴───────────────┐        ┌────────────────────────┐
        │  one-time form API        │◀───────│  Telegram bot          │
        │  (Fastify + SQLite)       │  link  │  metadata only, ever   │
        └───────────────────────────┘        └────────────────────────┘
                    ▲
                    │ HTTPS, 2-minute single-use link
              ┌─────┴──────┐
              │  browser   │  ← the human types the value here
              └────────────┘
```

The value crosses exactly three boundaries: into the vault, into a child process
environment, and between the secure form and the backend adapter. Every other arrow
in that diagram carries metadata only.

## Packages

| Package                                   | Directory                    | Published | What it does                                                        | Status  |
| ----------------------------------------- | ---------------------------- | --------- | ------------------------------------------------------------------- | ------- |
| `@bx-labs/agent-secrets-core`             | `packages/core`              | yes       | References, sanitized errors, metadata/audit schemas, policy engine, `SecretValue` | **implemented** |
| `@bx-labs/agent-secrets-redaction`        | `packages/redaction`         | yes       | Redaction transforms and canary leak detection                       | planned |
| `@bx-labs/agent-secrets-test-helpers`     | `packages/test-helpers`      | no        | Fake `bws`, fake Keychain, canary utilities                          | planned |
| `@bx-labs/agent-secrets-backend-bitwarden`| `packages/backend-bitwarden` | yes       | `SecretBackend` over the `bws` CLI in a hardened subprocess          | planned |
| `@bx-labs/agent-secrets`                  | `packages/cli`               | yes       | The `agent-secrets` binary                                           | planned |
| `@bx-labs/agent-secrets-mcp`              | `packages/mcp-server`        | yes       | MCP server: metadata and scoped execution, never values              | planned |
| `@bx-labs/agent-secrets-api`              | `apps/api`                   | no        | One-time secure input form, SQLite request store                     | planned |
| `@bx-labs/agent-secrets-telegram`         | `apps/telegram`              | no        | Telegram adapter, allowlisted, metadata only                         | planned |

## Documentation

| Document                                            | What you will find                                            |
| --------------------------------------------------- | ------------------------------------------------------------- |
| [`DOC.md`](DOC.md)                                   | Command surface, JSON envelope, config paths, environment vars |
| [`docs/architecture.md`](docs/architecture.md)       | Components, data flows, backend contract, data model           |
| [`docs/threat-model.md`](docs/threat-model.md)       | Assets, adversaries, mitigations, and what we do **not** stop  |
| [`docs/logging.md`](docs/logging.md)                 | Allowed and forbidden log fields, and why length is disclosure |
| [`docs/exit-codes.md`](docs/exit-codes.md)           | The exit code contract and how to branch on it                 |
| [`docs/device-enrollment.md`](docs/device-enrollment.md) | Enrolling a second Mac, Keychain naming, revocation        |
| [`docs/telegram-security.md`](docs/telegram-security.md) | What Telegram sees, allowlists, rate limits                |
| [`docs/recovery.md`](docs/recovery.md)               | Runbooks for lost devices, leaked links, outages               |
| [`docs/mcp.md`](docs/mcp.md)                         | Tool inventory, client wiring, prompt-injection stance         |
| [`docs/manifests.md`](docs/manifests.md)             | `agent-secrets.yaml`, and why it is safe to commit             |
| [`SECURITY.md`](SECURITY.md)                         | Private disclosure path and honest limitations                 |
| [`CONTRIBUTING.md`](CONTRIBUTING.md)                 | Setup, quality gates, and the hard boundaries                  |
| [`ROADMAP.md`](ROADMAP.md)                           | What is done, what is next                                     |
| [`CONTEXT.md`](CONTEXT.md)                           | Living project state for whoever picks this up next            |

## Telemetry

None. Not opt-in, not anonymous, not "just crash reports". V1 makes no network call
except to your Bitwarden instance, your own API host, and the Telegram API when you
run the bot. See [`CONTRIBUTING.md`](CONTRIBUTING.md) — adding telemetry is one of the
changes we will not accept.

## Requirements

- Node.js **>= 22.11**
- pnpm (workspace, `pnpm@11.5.0`)
- macOS for Keychain-backed device enrolment in V1
- A Bitwarden Secrets Manager organisation and the official `bws` CLI

## Contributing

Read [`CONTRIBUTING.md`](CONTRIBUTING.md) and `CLAUDE.md` first. This is a security
product: a sloppy change here leaks a production credential, not a build. Report
vulnerabilities privately — see [`SECURITY.md`](SECURITY.md), never a public issue.

## License

Apache-2.0. Built by [Bx Labs](https://github.com/Brissux-Labs).
