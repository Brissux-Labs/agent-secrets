# Setting up Agent Secrets — instructions for an AI agent

You are reading this because someone gave you a link to this repository and asked
you to set it up for them. This page is written for you rather than for them.

It works for any agent that can run shell commands: Claude Code, Codex, Hermes,
or anything else with a terminal. A section at the end covers wiring the MCP
server into an MCP-capable client.

---

## Read this first: one step is not yours to do

Agent Secrets exists to keep credentials out of model context. That includes
yours.

**Two things must be done by the human, and you must not do them for them:**

1. Creating the Bitwarden account, project, and machine account (web UI).
2. Pasting the machine account access token into `agent-secrets init`.

That token opens the whole vault. There is no `--token` flag and there never will
be, because a flag lands in shell history, in `ps` output, and in your
transcript. `init` reads it from a hidden prompt on a real terminal.

So do not:

- ask the human to paste the token into this conversation;
- offer to run `init` with the token supplied some other way;
- suggest putting it in an environment variable or a file "just for setup";
- read it back to confirm it.

Do: prepare everything else, then hand them one command to run themselves. The
whole human part takes about two minutes. If you finish the automated steps and
say "now run `agent-secrets init` and paste your token when prompted", you have
done this correctly.

---

## Step 0 — Find out where you are

```bash
node scripts/preflight.mjs --json
```

Run this from the repository root, after cloning. It reports what is present,
what is missing, and the single next action:

```jsonc
{
  "ready": false,
  "checks": [ { "id": "node", "ok": true, "found": "22.22.2" }, /* ... */ ],
  "nextAction": {
    "id": "install-bws",
    "actor": "agent",          // "human" means stop and ask
    "summary": "Install the Bitwarden Secrets Manager CLI.",
    "command": "brew install bitwarden/tap/bws",
    "url": "https://github.com/bitwarden/sdk-sm/releases?q=bws"
  }
}
```

Loop: run it, do `nextAction`, run it again. Stop the moment `actor` is
`"human"`.

---

## Step 1 — Clone and build

```bash
git clone https://github.com/Brissux-Labs/agent-secrets.git
cd agent-secrets
pnpm install
pnpm build
```

Requires Node >= 22.11 and pnpm. If pnpm is missing:
`corepack enable && corepack prepare pnpm@latest --activate`.

---

## Step 2 — Prove it works, before touching a real vault

```bash
pnpm demo
```

This runs the real CLI against a **fake** Bitwarden binary in a throwaway
directory. It needs no account, no token, and no network. It touches no Keychain
and leaves nothing behind.

If the demo passes, the build is good. Show the human the output — particularly
the step where a child process prints the secret and the terminal shows
`[REDACTED]` — because that is the product's central claim, demonstrated rather
than asserted.

**If the human only wants to evaluate the tool, you can stop here.** Everything
past this point requires a real Bitwarden account.

---

## Step 3 — Install the backend CLI

Agent Secrets stores nothing itself. It drives Bitwarden Secrets Manager through
the official `bws` binary.

```bash
# macOS
brew install bitwarden/tap/bws

# elsewhere: download the release for your platform and put it on PATH
# https://github.com/bitwarden/sdk-sm/releases?q=bws
```

Verify: `bws --version`. Tested against `bws` 1.x and 2.1.0.

**`which bws` is not enough.** Agent Secrets resolves a bare `bws` against a fixed
list of directories — `/usr/local/bin`, `/opt/homebrew/bin`, `/usr/bin`, `/bin`,
`/usr/sbin`, `/sbin` — and never against your `PATH`, so that a poisoned `PATH`
entry cannot substitute a program that captures the access token. A binary
installed anywhere else (a `~/.local/bin` install, an unpacked release tarball)
is invisible to the tool while every shell check says it is fine.

Re-run `node scripts/preflight.mjs --json`: the `bws-reachable` check covers
exactly this, and its `nextAction` gives the export to run. Otherwise:

```bash
export AGENT_SECRETS_BWS_PATH=/absolute/path/to/bws
```

Put that in the human's shell profile, or hand them `--executable-path` in
step 4 — a value on the command line is fine here, it is a path, not a secret.

---

## Step 4 — Hand over to the human

Tell them, in your own words, that they need to do this part themselves and why.
Give them these two things:

**A. In the Bitwarden web vault** (free tier includes Secrets Manager):

1. Enable Secrets Manager for their organisation.
2. Create a **project** — one per machine group, not one per environment. All
   environments live under it. Name it something like `agent-secrets`.
3. Create a **machine account**, give it read/write on that project, and
   generate an **access token**.
4. Copy the project's UUID from its URL, and keep the access token on screen.

One machine account per computer, not one shared. That is what makes a lost
laptop revocable without rotating every secret.

**B. On their machine:**

```bash
agent-secrets init
```

It asks for a device name, the project UUID, and then the access token on a
hidden prompt. The token goes into the macOS Keychain and never into a file.

Two flags to add for them when they apply — you can supply both, neither is a
secret:

```bash
# Bitwarden EU cloud (or any self-hosted deployment). Without it, bws talks to
# the US cloud and a perfectly valid EU token is refused.
--server-url https://vault.bitwarden.eu

# Only when bws is not in one of the directories listed in step 3.
--executable-path /absolute/path/to/bws
```

Then wait for them to tell you it is done.

---

## Step 5 — Verify, and confirm the boundary

```bash
agent-secrets doctor --json
```

Exit 0 with `"reachable": true` means the device is enrolled and the backend
answers. Exit 3 means enrolment did not complete.

Then verify the thing that matters:

```bash
agent-secrets list --project <their-project> --env development --json
```

You get names and metadata. **You cannot get a value, from any command, in any
mode.** If a task seems to need one, it does not — use `agent-secrets run` to
execute the command that needs it.

---

## Step 6 — Everyday use

```bash
# Add a secret. The human types the value at a hidden prompt.
agent-secrets add OPENAI_API_KEY --project myapp --env development

# See what exists.
agent-secrets list --project myapp --env development

# Run something with it. The value reaches the child process and nothing else.
agent-secrets run --project myapp --env development \
  --keys OPENAI_API_KEY -- npm run dev
```

Exit codes are a contract — `3` enrolment required, `4` policy denied, `5` not
found, `7` backend unreachable, `9` the child command failed. Branch on them
rather than on message text. Full table in
[`exit-codes.md`](exit-codes.md).

`--json` gives every command a stable `{ schemaVersion, status, data }` envelope.

Two behaviours that surprise people, both deliberate:

- **`--env` is mandatory and never defaults.** An omitted environment is an
  error, because the alternative is eventually writing to production while
  believing you are in development.
- **Production is denied by default.** Not a warning — a refusal, with exit 4.
  Enabling it means writing it down in a policy file, which leaves a trace.

---

## Step 7 — Wire up the MCP server, if the client supports it

This gives an MCP-capable client seven tools: `secret_list`, `secret_describe`,
`secret_add_request`, `secret_rotate_request`, `secret_delete_request`,
`run_with_secrets`, `secret_health`. None of them returns a value.

The server reuses the enrolment from Step 4 — same config, same Keychain entry,
same policy file. There is no second credential to hand it.

**Claude Code** — `.mcp.json` in the project, or the user-level equivalent:

```jsonc
{
  "mcpServers": {
    "agent-secrets": {
      "command": "agent-secrets-mcp",
      "args": [],
      "env": {}
    }
  }
}
```

**Codex and other clients using the same shape** — usually `~/.codex/config.toml`
or a `mcpServers` block; the command and args are identical.

**Any MCP client**: the server speaks stdio. Launch `agent-secrets-mcp` with no
arguments. Remote HTTP transport is deliberately not implemented yet.

**Hermes** already loads Bitwarden Secrets Manager at startup through
`hermes secrets bitwarden setup`. Agent Secrets complements that rather than
replacing it: let Hermes keep loading what it needs at boot, and use Agent
Secrets for creating, rotating, and scoped execution. Do not point both at the
same responsibility.

Two optional environment variables:

```bash
# Restrict the server to reads: no deletion, no execution, no link minting.
AGENT_SECRETS_MCP_READ_ONLY=1

# Enable the secure-input request tools by pointing at a running API.
AGENT_SECRETS_API_URL=https://secrets.example.com
AGENT_SECRETS_ADAPTER_TOKEN=<the API's adapter credential>
```

Without the API variables, `secret_add_request` reports that secure links are not
configured and tells the human to use `agent-secrets add` instead. That is a
working setup, not a broken one — the API is only needed for the Telegram flow.

---

## What to tell the human when you are done

Be accurate about what they now have, including the limits:

- Secrets live in their Bitwarden vault; this tool never stores a value.
- You can see names and metadata, and run commands that use secrets. You cannot
  read a value, and neither can any other agent pointed at this server.
- Each machine has its own revocable token. Losing a laptop means revoking one
  machine account, not rotating everything.
- **Bitwarden grants permissions per project.** All environments sit under one
  project, so `development` / `production` separation is enforced by this tool's
  policy engine, not by the vault. Anyone holding a device token can read
  production values directly through `bws`. For real production, use a separate
  Bitwarden project. This is [§5.12 of the threat
  model](threat-model.md).
- This is pre-release software with no external security review.

---

## If something fails

| Symptom | Cause | Fix |
|---|---|---|
| exit 3 on every command | not enrolled, or the Keychain entry was removed | `agent-secrets init` |
| exit 7 | `bws` missing, or the token was revoked | `agent-secrets doctor`, check the machine account |
| `init` says "The bws executable was not found" | `bws` is installed outside the directories in step 3 — the usual case is `~/.local/bin` | `export AGENT_SECRETS_BWS_PATH=$(which bws)`, then re-run `init` |
| `init` says "The backend rejected this access token" | the token was truncated when pasted, or has been revoked | copy it again from the machine account; do **not** paste it into a chat to check it |
| `init` says "The backend could not be reached" | wrong region — an EU account probed against the US cloud | re-run with `--server-url https://vault.bitwarden.eu` |
| `init` says "that project is not visible to it" | wrong project UUID, or the machine account has no grant on it | check the UUID in the project's URL, and the machine account's project access |
| exit 4 on a write | production, or an action absent from the policy | intended — ask the human before changing policy |
| exit 5 on `run` | a named secret does not exist in that scope | `agent-secrets list` to see what does |
| `init` cannot read the token | not a real terminal | run it in a terminal; this cannot be worked around |
| Keychain prompts repeatedly | login keychain locked | unlock it; `doctor` reports the store in use |

When you are stuck, `agent-secrets doctor --json` and
`node scripts/preflight.mjs --json` are the two commands that describe the state
without revealing anything sensitive. Paste those, not a token.
