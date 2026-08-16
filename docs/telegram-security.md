# Telegram security

The Telegram flow exists so a human can supply a credential from their phone, away
from the terminal where the agent is working. It is designed around one assumption:

> **Telegram sees everything that passes through Telegram.**

So the value never passes through Telegram.

> **Status.** The Telegram adapter and the one-time form API are **planned**.
> `apps/telegram/src/` and `apps/api/src/` are empty. Everything below is the
> specification, not a description of running code.

---

## 1. Why the value never travels through Telegram

Not because Telegram is untrustworthy in some special way, but because it is a
messaging platform, and messaging platforms have properties that are wrong for
credentials:

- **Messages are stored on servers you do not control.** Standard Telegram chats,
  including all bot chats, are stored server-side so they can sync across devices.
  Bot conversations cannot be secret chats; end-to-end encryption is not available for
  them.
- **Messages are replicated to every device on the account.** Your phone, your iPad,
  your desktop client, and any device someone else has added to your account.
- **Messages are backed up and cached.** By the platform, by the OS, and by whatever
  notification system surfaced a preview on a lock screen.
- **Deletion is a request, not an erasure.** More on this in §5.

A credential in a chat is a credential in all of those places, permanently. So the bot
has no command that accepts a value, and no code path that reads a message body as
one. This is structural: it is not a filter that could be misconfigured.

### What actually happens instead

```
you  → /add ezjob development EXAMPLE_API_KEY        (metadata only)
bot  ← https://secrets.example.invalid/f/PLACEHOLDER (a one-time link)
you  → [open the link in a browser, type the value there]
bot  ← stored: bitwarden/ezjob/development/EXAMPLE_API_KEY
```

The value's path is **browser → HTTPS body → `SecretValue` → backend adapter →
Bitwarden**. Telegram is not on it. Neither is the bot process: it never receives the
value, at any stage, in any form.

---

## 2. What Telegram does see

Be clear-eyed about this. Telegram's servers observe:

| Visible to Telegram | Example |
| ------------------- | ------- |
| Your commands, verbatim | `/add ezjob development EXAMPLE_API_KEY` |
| Which projects and environments you use | `ezjob`, `production` |
| Which secret **names** exist | `EXAMPLE_API_KEY`, `DATABASE_URL` |
| **The one-time URL**, in full | `https://secrets.example.invalid/f/<token>` |
| Your hostname / domain | `secrets.example.invalid` |
| Timing and frequency | "rotated production credentials at 03:14, six times this week" |
| Your Telegram account identity | Numeric id, and whatever else your account carries |
| Bot replies | Confirmations, references, error messages |

**Never visible to Telegram:** the value, its length, its hash, or any function of it.

### The one-time URL is the interesting one

It transits Telegram's infrastructure, so treat it as known to Telegram for its
lifetime. That is why it is built the way it is:

- **≥256 bits of CSPRNG randomness.** Not guessable, not enumerable.
- **Stored only as a SHA-256 hash.** Reading the API's database yields no usable link.
- **Bound** to actor, backend, project, environment, name and action. A link for
  `development/EXAMPLE_API_KEY` cannot be pointed at `production/DATABASE_URL`.
- **2-minute TTL**, enforced in the claim predicate rather than by a background sweep.
- **Single use**, claimed atomically. Two submissions cannot both win.

So the exposure is: for up to two minutes, anyone who obtains the URL could submit the
form **once**, writing a value of their choosing to that one reference. They cannot
read the existing value — there is no read path in the form at all. The realistic harm
is credential replacement: a denial of service, or poisoning. See
[`recovery.md`](recovery.md) for what to do about a leaked link.

**If your threat model includes Telegram itself**, do not use the Telegram flow. Use
the local CLI prompt (`agent-secrets add`), which never involves Telegram, the API, or
a browser.

---

## 3. The allowlist model

**Deny by default, with no way to turn it off.**

- The bot answers **only** numeric Telegram user ids present in
  `AGENT_SECRETS_TELEGRAM_ALLOWLIST`.
- **An empty allowlist means the bot answers nobody.** There is no "allow all", no
  wildcard, and no "first user to message becomes the admin" bootstrap — that last
  pattern is a race an attacker wins by being faster than you.
- The allowlist holds **numeric user ids**, not `@usernames`. Usernames can be
  changed and re-registered; numeric ids cannot.
- The check runs **before command parsing**, so an unauthorized sender cannot probe
  which projects or secrets exist through differences in error messages.
- Refusals are generic and identical whether or not the reference exists.
- Group chats are refused outright. The bot operates in one-to-one chats only, because
  a group's membership can change without the bot noticing.
- Every attempt — allowed, refused, or malformed — produces an audit event with the
  opaque actor id.

Adding yourself is a deliberate, server-side act: you edit the environment
configuration of your own API host and restart the bot. There is no in-chat
enrolment command, because an in-chat enrolment command is an in-chat privilege
escalation command.

### Layered with policy

The allowlist answers *who may talk to the bot*. The policy engine answers *what that
person may do*. They are independent, and both must pass. An allowlisted user asking
for a production rotation still receives `POLICY_DENIED` under the default policy —
because the policy engine is code, and it does not care who is asking.

---

## 4. Rate limits

Applied per Telegram user id, per chat, and per source IP on the API. Concrete
defaults, adjustable in configuration:

| Limit | Default | Why |
| ----- | ------- | --- |
| Bot commands | 20 per minute per user | Ordinary use is a handful of commands; 20 is generous and still throttles a script. |
| One-time request creation | 5 per minute, 30 per hour per user | Each request creates a live capability. Minting them in bulk is not a normal workflow. |
| Form GET per token | 5 attempts | A legitimate human opens the link once, twice if the network hiccups. |
| Form POST per token | 1 successful, 3 attempted | The claim is single-use anyway; the attempt cap stops brute-forcing the anti-CSRF token. |
| Form endpoints per IP | 60 per minute | Blunt instrument against enumeration of the token space. |
| Failed allowlist checks per IP | 10 per minute, then quiet | Refuse and stop replying, rather than confirming the bot is alive. |

Exceeding a limit produces a generic refusal, an audit event, and no information about
which limit was hit. When the bot goes quiet on an unauthorized sender, that is the
intended behaviour, not an outage.

---

## 5. When a user pastes a value by mistake

It will happen. Someone will type `/add ezjob development EXAMPLE_API_KEY
<the actual key>`, or paste the key as a follow-up message.

### What the bot does

1. **It never treats the text as a value.** There is no code path that reads a message
   body as a secret. The extra argument is a parse error, not an ingestion.
2. **It detects the likely mistake** — a fourth positional argument on `/add`, or a
   free-text message that matches credential-shaped heuristics — and responds with a
   warning rather than a generic syntax error.
3. **The warning says what actually happened**, in these terms: *the value is now
   stored on Telegram's servers and replicated to your devices; deleting the message
   does not undo that; rotate this credential at its provider before doing anything
   else.*
4. **It records an audit event with `outcome: "denied"` and no reference** to what was
   pasted. The audit trail notes that a paste occurred; it does not preserve it. The
   whole point is not to create a second copy.
5. **It logs nothing about the pasted text.** Not its length, not a hash, not a
   prefix — see [`logging.md`](logging.md) for why each of those would itself be a
   disclosure.
6. **It offers to delete the message**, and is explicit that deletion is cosmetic.

### What you should do

**Assume the credential is compromised. Rotate it at the provider.**

Not "consider rotating". Rotate. The value has been transmitted to a third-party
service, stored server-side, replicated to every device on your account, possibly
displayed in a lock-screen notification, possibly captured by a client-side backup,
and possibly indexed by a desktop client's local search database. None of that is
recoverable by deleting a message.

Then, once the old credential is dead at the provider, use the normal flow to store
the new one.

### Deleting the message does not undo the exposure

Worth stating on its own line, because it is the single most common misconception:

> Deleting a Telegram message removes it from the chat view. It does not remove it
> from server-side storage guarantees you do not control, from backups, from other
> devices that already synced it, from notification history, from a client's local
> cache, or from anyone who already read it.

`/delete` is housekeeping. Rotation is the remedy. Do the rotation first.

---

## 6. Operating the bot securely

- **The bot token is a credential.** With it, an attacker impersonates your bot to
  your allowlisted users and reads every message sent to it. Keep it in your process
  manager's secret store, never in a `.env` file in the repository (`.env` and
  `.env.*` are gitignored precisely because someone will try).
- **Use webhooks with a secret token, or long polling.** Both are fine; a webhook
  endpoint must verify Telegram's secret token header and be served over HTTPS.
- **Run the bot and the API as separate processes** with the smallest sensible
  privileges. The bot never needs backend write access — it asks the API to mint a
  request, and the API talks to Bitwarden.
- **Authenticate bot → API** with `AGENT_SECRETS_API_TOKEN`. That token can mint
  one-time links for arbitrary references; treat it accordingly.
- **Validate every update with Zod** before touching any field. Telegram updates are
  external input, and a bot is an unauthenticated internet-facing endpoint.
- **Never echo user input into a reply** without escaping. The reference grammar
  rejects anything that could become markup, which is one of the reasons it is as
  narrow as it is.
- **Review the audit trail periodically.** A one-time request minted at an hour you
  were asleep is worth a question.

---

## 7. If you would rather not use Telegram at all

You do not have to. The Telegram adapter is optional and independent:

- `agent-secrets add` and `agent-secrets rotate` prompt on a hidden TTY locally.
  Nothing leaves the machine except the value's journey to Bitwarden.
- The one-time form API can be run without the bot, with links delivered by whatever
  channel you prefer.
- The MCP server never depends on Telegram; its request tools return a request id and
  an expiry, and the delivery channel is a deployment decision.

The Telegram flow solves one specific problem: *the human is not at the terminal where
the agent is working*. If that is not your problem, skip it.
