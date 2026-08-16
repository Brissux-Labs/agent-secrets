# Agent Secrets

**An open-source secret broker for AI agents.** Make a credential available to an
agent-driven workflow without ever pasting it into a conversation, a source file,
a shell argument, a git commit, a model context, or a log.

Storage is [Bitwarden Secrets Manager](https://bitwarden.com/products/secrets-manager/).
This package is the CLI that brokers access to it: values go to your vault and to
the processes that need them, and nowhere else.

> **Pre-release.** V1 is in development. See the [root README](../../README.md)
> and [`ROADMAP.md`](../../ROADMAP.md) before deploying anything.

## Install

The unscoped name was taken on npm, so the package is scoped. The binary it
installs is still called `agent-secrets`.

```bash
npm install -g @bx-labs/agent-secrets
```

Requirements: Node.js >= 22.11, the official `bws` CLI, a Bitwarden Secrets
Manager machine account, and macOS for Keychain-backed enrolment (elsewhere the
CLI falls back to a 0600 file and says so).

## 60 seconds

```bash
# Enrol this machine. The access token is typed at a hidden prompt and handed
# straight to the macOS Keychain — it never touches a file this tool writes.
agent-secrets init
agent-secrets doctor   # enrolment, backend reachability, file permissions

# Add a secret. The value is typed twice at a hidden prompt, never as an argument.
agent-secrets add EXAMPLE_API_KEY --project demo-app --env development

# Names and metadata only — there is no way to print a value.
agent-secrets list --project demo-app --env development

# Run something with it. The value exists only in the child's environment block.
agent-secrets run --project demo-app --env development --keys EXAMPLE_API_KEY -- pnpm test
```

## The command surface

| Command | What it does |
| ------- | ------------ |
| `init` | Enrol this device; store its backend token in the OS credential store |
| `doctor` | Check enrolment, backend reachability, and file permissions |
| `logout` | Remove this device's local token — vault secrets are untouched |
| `add <NAME>` | Create a secret from a hidden prompt or `--stdin` |
| `rotate <NAME>` | Replace an existing secret's value |
| `list` | List names and non-secret metadata in a scope |
| `describe <NAME>` | One secret's metadata — no value, length, or fingerprint |
| `delete <NAME>` | Delete, after typing the full canonical reference |
| `run -- <cmd>` | Run a command with named secrets in its environment |

`--project` and `--env` are required wherever a scope is needed. **An omitted
environment is an error, never a default** — the one thing worse than a failed
command is one that silently guessed `production`. `--json` puts every command in
a stable `{ schemaVersion, status, data }` envelope, and exit codes are a public
contract (`2` invalid input, `3` not enrolled, `4` policy denied, `9` the child
failed, and the rest in [`docs/exit-codes.md`](../../docs/exit-codes.md)).

### Manifests: the shape meant for agents

Commit an `agent-secrets.yaml` and the repository states which secrets a command
needs, reviewed in a pull request like any other code, instead of the agent
deciding:

```yaml
version: 1
project: demo-app
commands:
  test:
    environment: development
    secrets: [EXAMPLE_API_KEY]
    command: [pnpm, test]
```

```bash
agent-secrets run --manifest test
```

A manifest arrives with a repository, so it is untrusted input: the first run —
and every run after the file changes — shows you the exact argument array and
asks. The approval is keyed to a hash of the file, and cannot be waived
non-interactively; the point is a human looking at it outside the model's
control.

## What this tool is responsible for

That a value reaches exactly two places: the vault, and the environment block of
a child process you named. No command accepts a value as an argument or a flag —
there is no `--value` and there never will be, because a flag is shell history,
`ps` output, and a CI log. `run` injects only the names you listed; there is no
"inject everything" mode. Everything printed passes through one writer that walks
the payload for value-derived fields and sweeps the final string through
redaction. Policy is evaluated in code before the backend is contacted, so an
agent talked into asking for a production rotation gets `POLICY_DENIED` rather
than an argument.

What it does **not** do: bound the child. Once a value is in a process
environment, that process and its descendants can print it, POST it, or write it
to a file. `--isolated-env` narrows what else the child inherits; it does not
contain the child. Real isolation needs a container or a narrowly scoped
credential. [`docs/threat-model.md`](../../docs/threat-model.md) says so bluntly.

## Configuration

State lives in `~/.config/agent-secrets/` (0700): `config.json` (0600, no
secrets — backend, device id, Bitwarden project id), `audit.jsonl` (0600,
metadata-only JSONL), `policy.yaml`, and `manifest-approvals.json`. Set
`AGENT_SECRETS_HOME` to move all of it. The access token lives only in the OS
credential store; `AGENT_SECRETS_CREDENTIAL_STORE=file` forces the weaker
file-backed store, documented rather than hidden. There is deliberately no
default-environment setting, and no telemetry of any kind.

## More

- [Root README](../../README.md) — the architecture and what this is not
- [`DOC.md`](../../DOC.md) — full command surface, JSON envelope, config paths
- [`docs/manifests.md`](../../docs/manifests.md) — `agent-secrets.yaml` in detail
- [`docs/exit-codes.md`](../../docs/exit-codes.md) — how to branch on the result
- [`SECURITY.md`](../../SECURITY.md) — private disclosure path and honest limits

Apache-2.0. Built by [Bx Labs](https://github.com/Brissux-Labs).
