# Device enrollment

Every machine that uses Agent Secrets holds **its own** Bitwarden Secrets Manager
access token, in that machine's macOS Keychain. Nothing is shared between machines,
nothing is synced, and revoking one device leaves the others working.

That is the entire design goal: losing a laptop should cost you one token, not your
whole vault.

> **Status.** Enrolment is **planned**. `agent-secrets init`, `doctor` and `logout`
> are specified below and not yet implemented. V1 targets macOS; a Linux
> secret-service adapter is post-V1.

---

## 1. Why per-device tokens

A single shared token is the arrangement most teams end up with by accident, and it
has three properties you do not want:

- **Revocation is all-or-nothing.** One lost laptop means everyone re-enrols.
- **The audit trail is useless.** Every action is attributed to "the token", so you
  cannot tell which machine did what.
- **The token has to travel.** It gets pasted into a chat, a password manager note, a
  CI variable, and eventually a repository.

Per-device tokens invert all three. Each machine's token is minted once, in Bitwarden,
and typed once, into a hidden prompt on that machine. It never travels again.

---

## 2. Enrolling your first machine

```bash
# 1. In the Bitwarden web vault: create a machine account for this device,
#    grant it access to the Agent Secrets project, and generate an access token.
#    Name it after the machine — "work-macbook", not "agent-secrets".

# 2. Install the CLI.
npm install -g @bx-labs/agent-secrets

# 3. Enrol. This prompts for the access token on a hidden TTY.
agent-secrets init --project ezjob --device-name work-macbook

# 4. Verify.
agent-secrets doctor --project ezjob
```

`init` does exactly four things:

1. Prompts for the access token on a **hidden TTY read**. The token is never accepted
   as a command-line argument (visible in `ps` and in shell history), never read from
   a pipe, and never read from an environment variable (inherited by every child
   process). If you find yourself wanting to automate this, that is the design
   working.
2. Validates the token by performing a metadata-only health probe against the backend.
   A bad token fails here, with `AUTH_REQUIRED` / exit 3, before anything is stored.
3. Generates a device id — a random opaque identifier, not a hostname, not a MAC
   address, not a serial number. It appears in audit records, so it must not itself be
   sensitive.
4. Writes the Keychain entry, creates the config directory at `0700`, and writes
   `config.json` at `0600`.

---

## 3. Enrolling a second Mac

The important part: **you do not copy anything from the first machine.**

```bash
# On the SECOND Mac.

# 1. In Bitwarden, create a SECOND machine account with its OWN access token.
#    Do not reuse the first machine's token. Name it "home-macbook".

# 2. Install and enrol.
npm install -g @bx-labs/agent-secrets
agent-secrets init --project ezjob --device-name home-macbook

# 3. Verify.
agent-secrets doctor --project ezjob
```

That is all. There is no pairing step, no device registry to update, no token to
transfer. The two machines now share exactly one thing: a Bitwarden project.

Both machines see the same secrets and produce distinct audit records, so
`deviceId` tells you which machine ran what.

### Do not do these

| Don't | Why |
| ----- | --- |
| Copy the Keychain entry to the second Mac | You now have one token in two places, and revocation is back to all-or-nothing. |
| Sync `~/.config/agent-secrets` via iCloud, Dropbox or a dotfiles repo | The device id would collide, audit attribution would become meaningless, and you would be syncing a security-relevant directory through a third party. |
| Reuse one access token across machines | Same problem as copying the Keychain entry, with the added risk that the token was pasted somewhere to get it there. |
| Enrol a shared or CI machine with your personal token | CI gets its own machine account, with a scope that matches what CI actually needs. |

---

## 4. Keychain naming

One entry per device-and-project pair.

| Field | Value |
| ----- | ----- |
| Service | `Agent Secrets Bitwarden Access Token` |
| Account | `<device-id>:<project-id>` |
| Kind | Generic password |
| Payload | The Bitwarden Secrets Manager access token |

`<device-id>` is the opaque identifier generated at `init`. `<project-id>` is the
Bitwarden project identifier. Both are constrained by the reference grammar's slug
rules before they are used, which is why a project slug cannot contain a `/`, a
newline, or anything else that could confuse the `security` command's argument
handling.

Inspect an entry manually (this prints metadata; it does **not** print the token):

```bash
security find-generic-password \
  -s "Agent Secrets Bitwarden Access Token" \
  -a "<device-id>:<project-id>"
```

Do not add `-w`. That flag prints the secret to your terminal, which puts it in your
scrollback, your terminal's session restore, and — if an agent is watching your
terminal — its context.

Every `security` invocation from our code uses an argument array through `execFile`,
never a shell, never string interpolation.

---

## 5. What is safe to sync, and what never is

### Safe to commit to git

| File | Contents |
| ---- | -------- |
| `agent-secrets.yaml` | The manifest: which references a project needs, per environment. References only. See [`manifests.md`](manifests.md). |
| `agent-secrets.policy.yaml` | The policy document: which actions are permitted where. Rules only. |

Both are *supposed* to be committed. They describe what a project needs and what is
allowed; being reviewable in a pull request is the point.

### Safe to keep locally, not worth syncing

| Path | Why not sync it |
| ---- | --------------- |
| `~/.config/agent-secrets/config.json` | Holds this device's identity. Syncing it duplicates device ids and corrupts audit attribution. |
| `~/.config/agent-secrets/audit.jsonl` | Per-machine record. Archive it if you like; merging two machines' logs into one file loses the distinction that makes it useful. |

### Never, under any circumstances

| Thing | Why |
| ----- | --- |
| The Bitwarden access token | It is the device credential. It belongs in one Keychain and nowhere else — not in a file, not in a dotfiles repo, not in a password manager note shared with the team, not in a CI variable you also use locally. |
| The Keychain entry itself | Same thing, exported. |
| Any secret value | There is no file in this system that holds one. If you have one in a file, it did not come from here. |
| `.env` files | Gitignored for a reason. Adopting Agent Secrets is a good moment to delete them and rotate what was in them. |

---

## 6. Revoking a lost machine

Order matters. Revoke first, tidy up afterwards.

```bash
# 1. FIRST, in the Bitwarden web vault: revoke that machine account's access token.
#    This is the only step that actually stops the lost machine. Everything else
#    is housekeeping.

# 2. From a machine you still have, confirm what that device did.
grep '"deviceId":"<lost-device-id>"' ~/.config/agent-secrets/audit.jsonl

# 3. Rotate anything that device could read. Assume it read everything in its scope.
agent-secrets rotate --project ezjob --env development --name EXAMPLE_API_KEY

# 4. If the machine ever comes back, or before you sell or wipe it:
agent-secrets logout --project ezjob     # removes the Keychain entry
```

Timing note: revocation is Bitwarden's operation and is not instantaneous. Until it
propagates, the token works. This is why step 3 exists — treat everything in that
device's scope as disclosed, not merely as at risk.

The other machines are unaffected throughout. They hold different tokens, and nothing
about revoking one touches another. Verify with `agent-secrets doctor` on a machine
you kept; if it reports healthy, the blast radius was contained.

The full incident runbook, including what to do when you are not sure whether the
machine was unlocked, is in [`recovery.md`](recovery.md).

---

## 7. Troubleshooting

| Symptom | Likely cause | Fix |
| ------- | ------------ | --- |
| `AUTH_REQUIRED` / exit 3 right after `init` | Token typed incorrectly, or it lacks access to the project | Re-run `init --force` with a freshly copied token; check the machine account's project grant in Bitwarden |
| `AUTH_REQUIRED` on a machine that worked yesterday | Token revoked or expired | Mint a new token for that machine account and `init --force` |
| macOS keeps prompting to allow Keychain access | The binary changed (an upgrade re-signs it) | Allow once and choose "Always Allow" for the new binary |
| `doctor` reports the config file as world-readable | A `umask` or a copied directory | `chmod 600 ~/.config/agent-secrets/config.json && chmod 700 ~/.config/agent-secrets` |
| `CONFLICT` / exit 6 from `init` | Already enrolled for that project | `agent-secrets logout --project <slug>` then re-enrol, or `init --force` |
| Two machines showing the same `deviceId` in audit records | Someone synced the config directory | Stop syncing it, `logout` and re-enrol the second machine |
| `BACKEND_UNAVAILABLE` / exit 7 during `init` | `bws` missing or not on `PATH` | Install the Bitwarden `bws` CLI, or set `AGENT_SECRETS_BWS_PATH` |
