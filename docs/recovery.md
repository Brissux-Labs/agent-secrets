# Recovery runbooks

What to do when something has gone wrong. Each runbook assumes you are stressed and
reading quickly, so the first step is always the one that stops the bleeding.

> **Status.** The commands referenced here are **planned**; only the domain core is
> implemented today. The procedures themselves — revoke first, rotate second, tidy up
> third — are correct regardless.

**Two rules that apply to every runbook below.**

1. **Rotate at the provider, not just in the vault.** Replacing a value in Bitwarden
   does nothing to a key that is still valid at OpenAI, Stripe, or AWS. Kill the old
   credential where it is honoured, then store the new one.
2. **Do not paste a credential into a chat, an issue, or a support ticket** while
   handling an incident. Incidents are exactly when people do this.

---

## Index

| # | Situation | First move |
| - | --------- | ---------- |
| 1 | [Lost or stolen Mac](#1-lost-or-stolen-mac) | Revoke that machine's token in Bitwarden |
| 2 | [Lost Bitwarden access token](#2-lost-or-suspected-compromised-bitwarden-access-token) | Revoke it, then re-enrol |
| 3 | [Compromised Telegram bot token](#3-compromised-telegram-bot-token) | Revoke via BotFather |
| 4 | [Compromised one-time link](#4-compromised-one-time-link) | Check whether it was claimed |
| 5 | [API server loss](#5-api-server-loss) | Nothing is lost; rebuild |
| 6 | [SQLite corruption](#6-sqlite-corruption) | Stop the server, then decide |
| 7 | [Accidental secret deletion](#7-accidental-secret-deletion) | Check the Bitwarden trash |
| 8 | [Bitwarden outage](#8-bitwarden-outage) | Wait. Do not degrade |
| 9 | [Compromised production credential](#9-compromised-production-credential) | Rotate at the provider now |
| 10 | [Maintainer signing key loss](#10-maintainer-signing-key-loss) | Stop publishing |

---

## 1. Lost or stolen Mac

**Assume the worst case that is consistent with what you know.** If the machine was
unlocked, or you cannot be sure it was locked, treat everything in that device's scope
as read.

**Stop the bleeding**

1. In the Bitwarden web vault, **revoke that machine account's access token**. This is
   the only step that actually stops the device; everything else is housekeeping.
   Revocation is not instantaneous — until it propagates, the token works.
2. If the machine had Bitwarden's own client signed in, revoke that session too.

**Assess**

3. From a machine you still have, read the audit trail for that device:

   ```bash
   grep '"deviceId":"<lost-device-id>"' ~/.config/agent-secrets/audit.jsonl
   ```

   Remember this is the *local* record of what that machine did. The server-side audit
   in the API database covers Telegram-initiated operations. Neither is a substitute
   for assuming the whole scope was read.

**Rotate**

4. Rotate every secret that device's token could read. Order by blast radius:
   production first, then preview, then development.

   ```bash
   agent-secrets list --project ezjob --env production
   agent-secrets rotate --project ezjob --env production --name EXAMPLE_API_KEY
   ```

   And rotate at each provider — see the rule at the top of this file.

**Verify and tidy**

5. `agent-secrets doctor` on a machine you kept. It should report healthy: the other
   devices hold different tokens and are unaffected. If it does not, you revoked the
   wrong machine account.
6. Delete the machine account in Bitwarden once you are finished with its audit trail.
7. If the machine is recovered or before you wipe it: `agent-secrets logout --all`.

**Afterwards:** confirm FileVault was on. A locked Mac with FileVault is a
substantially better position than a locked Mac without it, and it is worth knowing
which one you were in.

---

## 2. Lost or suspected-compromised Bitwarden access token

Covers: a token pasted into a chat, committed to a repository, echoed into a CI log,
or simply mislaid.

**Stop the bleeding**

1. Revoke the token in the Bitwarden web vault. Immediately. Before investigating,
   before telling anyone, before checking whether it was really exposed. A revoked
   token you did not need to revoke costs you one `init`.

**Assess**

2. Which project scope did it have? That is your blast radius.
3. Check the Bitwarden access log for use you do not recognise.
4. If it was committed to git: the credential is compromised from the moment it was
   pushed, and stays compromised. History rewriting does not recall forks, clones,
   caches, or anyone's local copy. Rewrite history if you like for tidiness; rotate
   regardless.

**Recover**

5. Mint a new access token for that machine account.
6. Re-enrol: `agent-secrets init --project ezjob --force`.
7. `agent-secrets doctor` to confirm.
8. Rotate the secrets the old token could read, at their providers.

**Afterwards:** if the token reached a place it should never have been, work out how.
It cannot have come from the Keychain by accident — it was typed into something. The
answer is usually a screen share, a copied dotfile, or a well-meaning "here, use
mine".

---

## 3. Compromised Telegram bot token

With this token an attacker impersonates your bot to your users and reads every
message sent to it.

**Stop the bleeding**

1. In BotFather: `/revoke` for the bot. The old token dies instantly.
2. Stop your bot process. It is now authenticating with a dead token and will fail
   noisily.

**Assess**

3. What did the attacker see while they held it? Every message to the bot: commands,
   references, project names, environment names, secret names, **and any one-time
   links that were issued during that window**.
4. Check the API audit for one-time requests created during the window. Any request
   that was *consumed* and that you cannot account for means an attacker wrote a value
   of their choosing to that reference — see runbook 4.
5. Values themselves were never in the chat, so no value was disclosed by this alone.

**Recover**

6. Set the new token in your process manager's secret store — not in a `.env` file.
7. Restart the bot and confirm the allowlist is intact and still numeric ids.
8. Rotate any reference whose one-time link was minted during the window, whether or
   not it was consumed.

**Afterwards:** the token got out somehow. Check the server's environment handling,
your deploy pipeline's log output, and whether it was ever pasted anywhere.

---

## 4. Compromised one-time link

Covers: a link screenshotted, forwarded, shared on a call, captured by a synced
clipboard, or visible in a proxy log.

**First, establish whether it was claimed**

The link is bound, single-use and short-lived, so there are only three states:

| State | Meaning | Action |
| ----- | ------- | ------ |
| Expired unclaimed | More than 2 minutes passed, nobody submitted | **Nothing was written.** No action needed beyond noting it. |
| Claimed by you | You used it yourself | Normal operation. |
| Claimed, and not by you | Somebody else submitted the form | Treat as an incident, below. |

Check the API audit for a `request-consume` event with that `oneTimeRequestId`, and
compare its timestamp to when you used it.

**If someone else claimed it**

1. The attacker could **write** a value to that one reference. They could not read the
   existing value — the form has no read path at all.
2. So the current stored value is attacker-controlled. Anything that resolved that
   reference since then received an attacker-chosen credential. Work out what ran.
3. Rotate that reference properly: mint a fresh credential at the provider, and store
   it through a flow you trust — the local CLI prompt, not another link.
4. Investigate anything that consumed the poisoned value. A service configured with an
   attacker's API key may have been sending your data to them.

**If it merely leaked and expired unclaimed:** genuinely nothing happened. The atomic
claim means an unclaimed request wrote nothing. Note it and move on.

**Afterwards:** links leak through screenshots and screen shares more than anything
else. If it keeps happening, use the local CLI prompt for sensitive references.

---

## 5. API server loss

The host died, the disk failed, the container was deleted.

**Assess what you actually lost**

- **No secret values.** They were never on that server at rest. Values pass through
  the process in transit and are stored in Bitwarden.
- **Pending one-time requests.** They were short-lived by definition; any that
  mattered have expired.
- **Server-side audit history.** This is the real loss. It is a record, not a
  capability.

**Recover**

1. Rebuild the host and redeploy the API.
2. Provide the configuration: `AGENT_SECRETS_API_BASE_URL`, `AGENT_SECRETS_DB_PATH`,
   `AGENT_SECRETS_API_TOKEN`, and the server's Bitwarden credential.
3. The API recreates its SQLite schema on first start. An empty database is a valid
   state — there is nothing to migrate in.
4. Restart the bot pointing at the new host.
5. `agent-secrets doctor` and one end-to-end `add` in `development` to confirm.

**Afterwards:** back up the SQLite file if the audit history matters to you, treating
the backup as sensitive-but-not-secret (it holds references and token *hashes*, no
values). Do not put it anywhere a value would be forbidden from going, out of habit.

---

## 6. SQLite corruption

Symptoms: `SQLITE_CORRUPT`, `database disk image is malformed`, the API refusing to
start.

**Stop**

1. Stop the API server. Do not let it keep writing to a damaged file.
2. Copy the file — and its `-wal` and `-shm` siblings — somewhere safe before touching
   anything.

**Diagnose**

```bash
sqlite3 /path/to/agent-secrets.sqlite "PRAGMA integrity_check;"
```

**Decide**

- **If only `one_time_requests` is damaged:** it is ephemeral. Drop and recreate it.
  Nothing of value is lost; every live request is seconds from expiring anyway.
- **If `audit_events` is damaged:** try recovery.

  ```bash
  sqlite3 corrupt.sqlite ".recover" | sqlite3 recovered.sqlite
  ```

  If it works, verify the recovered rows parse against the audit schema before
  trusting them.
- **If recovery fails:** start a fresh database. Record the gap — an audit trail with
  an acknowledged hole is honest; one with a silent hole is not. Note the date range
  in [`CONTEXT.md`](../CONTEXT.md).

**Restart**

3. Start the API. Confirm with a `development` round trip.

**Afterwards:** corruption usually means the process was killed mid-write, the
filesystem lied about durability, or the file lives on a network mount. Check which,
and do not host the database on a network filesystem.

---

## 7. Accidental secret deletion

You ran `agent-secrets delete` on the wrong reference.

**First, do not panic-recreate.** Creating a *different* value under the same name is
worse than a missing secret: things will silently authenticate as the wrong thing, or
fail in ways you will misdiagnose.

**Recover**

1. **Check Bitwarden's trash.** Bitwarden retains deleted items for a period; if the
   record is there, restore it from the web vault. This is the only path that recovers
   the *original value*, because Agent Secrets keeps no copy — that is the design.
2. If it is not recoverable: the value is gone. Mint a fresh credential at the
   provider and store it with `agent-secrets add`.
3. Update anything that was using the old credential, then revoke the old one at the
   provider so a stale copy somewhere cannot keep working.

**Assess the damage**

4. Anything that resolves that reference is now failing. In `development` that is an
   inconvenience; in `production` it is an outage, which is a large part of why the
   default policy denies `delete` in `production`.
5. The audit trail shows who deleted it and when:

   ```bash
   grep '"operation":"delete"' ~/.config/agent-secrets/audit.jsonl
   ```

**Afterwards:** if an agent did this, tighten the policy. Deletion in any environment
you care about should require human approval, and `production` deletion should stay
denied.

---

## 8. Bitwarden outage

`BACKEND_UNAVAILABLE` / exit 7 everywhere.

**Confirm it is them**

1. `agent-secrets doctor` — distinguishes "`bws` missing" from "backend unreachable".
2. Check Bitwarden's status page and your own network.

**While it is down**

- `run` fails closed. Your workflows stop. **That is correct behaviour**, and it is
  the behaviour we chose deliberately: a secret broker that degrades to "carry on
  without the secret" is not a secret broker.
- Retry with exponential backoff, a small number of attempts, then escalate.
- **Do not** work around it by exporting the value into your shell, writing a `.env`,
  or pasting it into CI variables. That is precisely the state Agent Secrets exists to
  get you out of, and the workaround always outlives the outage.
- If a build genuinely must proceed, use a credential the incident cannot touch and
  scope it to the emergency — then revoke it when the outage ends. Write down that you
  did this.

**When it comes back**

3. `agent-secrets doctor` to confirm.
4. Revoke any emergency credential you minted.
5. Check for partial writes: a `create` interrupted mid-flight may have left a record
   without the value you expected. `describe` the references you were working on.

---

## 9. Compromised production credential

The serious one. A production key is known to someone it should not be.

**Immediately, in this order**

1. **Revoke it at the provider.** Not in Bitwarden — at OpenAI, Stripe, AWS, wherever
   it is honoured. Until you do this, everything else is theatre.
2. **Mint a replacement** at the provider.
3. **Store the replacement**, using a flow you trust. Under the default policy,
   production mutation is denied, so this needs either a policy file that explicitly
   permits it or a temporary, deliberate, documented change:

   ```bash
   agent-secrets rotate --project ezjob --env production --name EXAMPLE_API_KEY
   ```

   The friction here is intentional. It is also why you should decide *now*, not
   during an incident, whether your policy file permits production rotation.
4. **Redeploy** anything holding the old value in a long-lived process. A rotated
   secret does not reach a process that already started.

**Then assess**

5. What could the credential do, and what does the provider's audit log say was done
   with it?
6. How did it get out? The audit trail narrows it:

   ```bash
   grep '"environment":"production"' ~/.config/agent-secrets/audit.jsonl
   ```

   Look for `run` events that injected it, `resolveMany` calls, and which device and
   actor performed them. Remember what §4.9 of the [threat model](threat-model.md)
   says: a child process that received the value could have done anything with it.
7. If a specific device is implicated, follow runbook 1 for that machine.

**Afterwards**

8. Tighten `allowExecutables` for production, so `run` cannot launch arbitrary
   binaries with a production credential.
9. Confirm production mutation is denied again if you enabled it for the rotation.
10. Write the incident up in [`CONTEXT.md`](../CONTEXT.md) — what leaked, how, and what
    changed as a result.

---

## 10. Maintainer signing key loss

Covers a lost or compromised release-signing key or npm publishing credential.

**If it is compromised**

1. **Revoke immediately**: the npm token, the GPG/SSH signing key, and any CI
   credential with publish rights.
2. **Check npm for releases you did not make.** Any unexpected version is a
   supply-chain incident affecting everyone who installed it.
3. If a malicious version was published: deprecate it on npm with a message pointing
   at the advisory, publish a clean version, and issue a security advisory on the
   repository. Do not rely on unpublishing — mirrors and lockfiles have long memories.
4. Notify users through the repository advisory and the README. Say plainly which
   versions are affected and what to do.

**If it is merely lost**

5. Generate a new key, publish the new fingerprint in the repository, and sign a
   commit and a tag announcing the rotation with both the old key (if you still can)
   and the new one.
6. Update whatever documents the current signing key.

**Either way**

7. Re-enable publishing only with provenance and two-factor authentication.
8. Prefer short-lived, CI-scoped publishing credentials over a long-lived personal
   token.
9. Record the rotation in [`CONTEXT.md`](../CONTEXT.md) with the date and both
   fingerprints, so someone verifying an old release can tell which key was current
   when.

---

## After any incident

- Append a dated entry to [`CONTEXT.md`](../CONTEXT.md): what happened, what you did,
  what changed.
- If it revealed a gap in the design rather than in the operation, update
  [`threat-model.md`](threat-model.md). A newly discovered residual risk that goes
  unwritten will be rediscovered the same way.
- If it was a vulnerability in Agent Secrets itself, follow
  [`SECURITY.md`](../SECURITY.md) — privately, and **without attaching a real
  credential**.
