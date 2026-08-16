# Logging rules

What may be written to a log, an audit record, a tool result, an error message, a
terminal, or a database row — and what may not, ever.

These rules apply to every sink in the project without exception: the CLI's JSONL
audit file, server logs, MCP tool results, HTTP responses, test output, and anything
a developer adds temporarily while debugging. "I removed it before committing" is not
a policy.

---

## 1. The rule

> A raw secret value must never reach a log, a terminal, an error message, a tool
> result, a model context, a database row, a process argument, a git object, or a test
> artifact — **and neither must anything derived from it.**

The second half is the part people get wrong. Length, hashes and prefixes feel like
metadata. They are not. Section 4 explains why.

## 2. Allowed fields

Safe to log, at any verbosity.

### Identity and addressing

| Field | Example | Note |
| ----- | ------- | ---- |
| `backend` | `bitwarden` | |
| `project` | `ezjob` | |
| `environment` | `development` | |
| `name` | `EXAMPLE_API_KEY` | The **name**, never the value it addresses. |
| `reference` | `bitwarden/ezjob/development/EXAMPLE_API_KEY` | |
| `backendId` | backend record id | Addresses a record. Says nothing about a value. |
| `version` | backend revision marker | Must come from the backend, never be derived from the value. |

### Actor and device

| Field | Note |
| ----- | ---- |
| `actorType` | `human` \| `agent` \| `device` \| `telegram` |
| `actorId` | Opaque: device id, Telegram numeric user id, MCP client name |
| `deviceId` | |
| `deviceLabel` | The human-chosen label, e.g. `work-laptop` |

### Operation and outcome

| Field | Note |
| ----- | ---- |
| `operation` | From the fixed audit operation list |
| `action` | From the fixed policy action list |
| `outcome` | `success` \| `denied` \| `failure` |
| `errorCode` | Stable code only: `POLICY_DENIED`, `NOT_FOUND`, … |
| `exitCode` | |
| `policyReason` | The engine's own sentence, assembled from constants and validated identifiers |
| `requiresHumanApproval` | boolean |
| `durationMs`, `latencyMs` | |
| `timestamp`, `id`, `schemaVersion` | |

### Execution

| Field | Note |
| ----- | ---- |
| `commandExecutable` | **Basename only.** `pnpm`, not `/usr/local/bin/pnpm --token=…` |
| `secretNames` | Array of names, e.g. `["EXAMPLE_API_KEY"]` |
| `secretCount` | The number of secrets injected — a count of *records*, never of bytes |
| `childExitCode`, `signal` | |
| `cwd` | Working directory of the child |

### HTTP and requests

| Field | Note |
| ----- | ---- |
| `requestId` | Server-generated correlation id |
| `method`, `statusCode` | |
| `route` | The **template**, `/f/:token`, never the concrete path |
| `oneTimeRequestId` | `req_<uuid>` — the row id, not the token |
| `expiresAt`, `consumedAt`, `attempts` | |

### Diagnostics

| Field | Note |
| ----- | ---- |
| `nodeVersion`, `platform`, `bwsVersion`, `packageVersion` | |
| `configDirMode`, `auditFileMode` | Permission bits, for `doctor` |
| `reachable`, `canRead`, `canWrite` | Backend health booleans |

---

## 3. Forbidden fields

Never logged. Never stored. Never returned. Not at debug level, not behind a flag, not
in a test snapshot.

### The value, in any form

- The value itself, in whole or in part.
- **The value's length**, byte size, or character count.
- **Any hash, HMAC, digest, checksum or fingerprint of the value** — salted or not,
  truncated or not.
- A prefix, a suffix, or the first/last *n* characters.
- A "masked" rendering that preserves real characters (`sk-ab…yz89`). A constant
  `[secret]` is the only acceptable placeholder.
- An entropy estimate, a character-class summary ("32 hex chars"), or a charset
  description.
- A detected provider *inferred from the value's shape*. A `provider` field the human
  typed is metadata; a `provider` field a regex derived from the value is disclosure.
- Whether two values are equal, beyond the single boolean the `add`/`rotate`
  confirmation prompt needs locally.

### Credentials and capabilities

- The Bitwarden device access token, in whole or in part — including a prefix, a
  suffix, or "the first 4 characters, just to identify which token".
- The Telegram bot token or the API shared token, same rules.
- **One-time URLs and one-time tokens.** Log the `oneTimeRequestId` instead.
- The stored token **hash**. It is a verifier for a live capability; treat it as the
  capability.
- Anti-CSRF tokens and session identifiers.
- `Authorization`, `Cookie`, `Proxy-Authorization` and `Set-Cookie` headers, in
  requests or responses.

### Bulk captures

- **Raw HTTP request or response bodies** from any form endpoint. The submission body
  *is* the value.
- **Full environment dumps** — `process.env`, the child environment block, or a diff
  of them.
- **The child's argument vector.** Tokens live in argv constantly. Log the basename.
- **Raw `bws` stdout or stderr from a value-bearing operation** (`resolveMany`,
  `create`, `update`). Metadata-only invocations may be logged after schema parsing;
  value-bearing ones may not, at any verbosity.
- Raw `spawn` / `execFile` error objects. Their `message` can embed both the command
  line and the value; that is why `toSafeError` keeps the original on `cause` and
  takes nothing from it.
- Stack traces that include an argument vector or a captured value in a frame.
- Core dumps, heap snapshots, and `--inspect` sessions of a process that has held a
  value.

### Practical consequences

- No `console.log(secret)` — and no `console.log({ secret })`, no
  `` console.log(`${secret}`) ``, no `util.inspect(objectContainingSecret, { depth:
  null })`. `SecretValue` renders as `[secret]` in all of those, which is a safety net
  and not a licence.
- No `JSON.stringify` of any object that may contain a `SecretValue`. `toJSON()`
  **throws** on purpose: a serializer reaching a value is a defect to surface, not to
  mask with a placeholder.
- Biome forbids `console.*` other than `console.error` outside `test/`, the CLI and
  the MCP server. That is a lint rule, not the reason; the reason is this document.

---

## 4. Why length and hash count as disclosure

Both look harmless. Both are routinely added "just for debugging". Both meaningfully
help an attacker.

### 4.1 Length

**It identifies the credential type.** Real-world API keys have characteristic lengths
and formats. A logged length of 51, 64 or 40 characters, combined with the `name`
field you *are* allowed to log, tells an attacker exactly which provider's key they
are hunting and therefore which format to brute-force, which rate limits apply, and
which endpoint to test a guess against. You have converted "some secret" into "a
specific vendor's key, of known shape".

**It collapses the search space.** Entropy estimates assume an unknown length. Fixing
the length removes that uncertainty entirely. For a human-chosen password — and
people do put passwords in secret stores — knowing it is 9 characters rather than
"8 to 64" is the difference between a feasible offline attack and an infeasible one.

**It leaks change information.** Log the length at each rotation and you have a
timeline: same length every time means a machine-generated key of fixed format;
varying lengths mean a human is typing them. Both are useful to an attacker deciding
where to spend effort.

**It leaks through comparison.** Two references with the same length at the same
timestamp are probably the same credential stored twice — which tells an attacker that
compromising the *development* copy gets them the *production* one.

### 4.2 Hashes

**A hash is a complete commitment to the value.** It does not obscure the secret; it
lets anyone holding the log *verify a guess offline*, at whatever rate their hardware
allows, with no interaction with your systems and no rate limit and no audit trail.
For any value drawn from a guessable space — and secrets are drawn from guessable
spaces far more often than people believe: default passwords, sequential test keys,
values copied from a tutorial — an unsalted hash is equivalent to publishing the
value.

**Precomputation makes it worse.** Unsalted hashes of common values are already
tabulated. If a credential ever appeared in a breach corpus, its hash is a lookup, not
a crack.

**A hash is a stable cross-system correlator.** The same value hashed in your logs,
your vendor's logs, and a breach dump links all three. An attacker who sees the same
digest in a public dataset and in your audit file now knows exactly which of your
references that leaked credential corresponds to — without ever breaking the hash.

**Truncation does not fix it.** A truncated hash still confirms guesses, just with a
false-positive rate; an attacker filters the survivors by trying them.

**Salting does not fix it either**, for our purposes: a per-record salt stops
cross-system correlation and precomputation, but anyone who can read the log can
usually read the salt, and offline verification returns.

### 4.3 The general principle

**Any function of the value is a channel.** Length, hash, entropy, character classes,
equality with a previous value, even "did validation pass" if the rule is narrow
enough. The only field about a value that is safe to emit is the constant `[secret]`,
because it is a function of nothing.

When you find yourself wanting to log something about a value in order to debug, log
something about the *operation* instead: the reference, the outcome, the error code,
the duration. If that genuinely is not enough, the missing information is a design
problem, not a logging problem.

---

## 5. How the rules are enforced

Layered, because a rule that depends on a person remembering it is not enforced.

1. **`SecretValue` is structurally non-serializable.** Private field, so it survives
   neither spread, nor `Object.keys`, nor `structuredClone`, nor `JSON.stringify`.
   `toString`, `Symbol.toPrimitive` and `util.inspect.custom` return `[secret]`.
   `toJSON()` throws.
2. **`.strict()` schemas.** `secretMetadataSchema`, `auditEventSchema` and the JSON
   envelope reject unknown keys. A `preview` field does not ship; it fails to parse.
3. **`FORBIDDEN_METADATA_FIELDS` + `assertNoValueFields`.** A recursive guard that
   throws on `value`, `secret`, `secretValue`, `plaintext`, `preview`, `prefix`,
   `suffix`, `length`, `size`, `hash`, `digest`, `checksum`, `entropy` or
   `fingerprint` at any depth, case-insensitively. It runs before every sink write and
   before every tool result. It throws rather than stripping: a payload that got this
   far with a forbidden field is a defect to fix at the source.
4. **Sanitized errors.** Every domain error's message is built from constants and
   validated identifiers. `toSafeError` wraps unknown throwables and contributes
   nothing from their message.
5. **Redaction transforms** on child stdout/stderr, seeded with the resolved values.
   Best effort against a cooperative child; useless against an adversarial one.
6. **Canary tests.** Generate `ASECRET_CANARY_<random>` at runtime, run the flow, and
   assert the canary appears in none of stdout, stderr, the audit file, the SQLite
   database, generated config, or the git working tree. **Planned** — this harness
   does not exist yet, which means layers 1–5 are currently unverified by test.
7. **Lint.** Biome's `noConsole` (allowing `console.error`) outside `test/`, the CLI
   and the MCP server, plus the `noSecrets` rule.

If you are adding a sink, you are adding it behind `assertNoValueFields`. If you think
your case is special, it is not.

---

## 6. Quick reference

```
LOG THIS                          NEVER LOG THIS
─────────────────────────────     ─────────────────────────────────────────
reference, project, env, name     the value
backendId, version                its length, size, or byte count
actorType, actorId, deviceId      its hash, HMAC, digest, checksum
operation, action, outcome        its prefix, suffix, or masked form
errorCode, exitCode               its entropy or character classes
policyReason                      access tokens, bot tokens, API tokens
durationMs, latencyMs             one-time URLs, one-time tokens, token hashes
commandExecutable (basename)      the child's argument vector
secretNames, secretCount          full environment dumps
requestId, route template         raw request/response bodies
oneTimeRequestId                  Authorization / Cookie headers
nodeVersion, bwsVersion           raw bws output from value-bearing calls
reachable / canRead / canWrite    raw spawn errors and their stack traces
```
