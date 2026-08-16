# @bx-labs/agent-secrets-redaction

Redaction transforms and the canary harness for
[Agent Secrets](../../README.md).

Nothing here is the primary control. The primary control is that a raw value only
ever travels between the three destinations named in the root README. This
package is what catches the day that invariant is broken by a refactor, a
dependency, or a child process nobody controls.

**Who imports it:** the CLI (in front of stdout, stderr and captured child
output), the Bitwarden adapter (in front of `bws` stderr), and the MCP server (in
front of anything returned to a model). Test suites across the monorepo import
the canary helpers.

```bash
npm install @bx-labs/agent-secrets-redaction
```

## The three things worth knowing

**1. Two passes, in this order.** `RedactionScope` scrubs the exact strings this
process currently holds — including their percent-encoded, base64, base64url and
JSON-escaped forms, because a value is rarely logged verbatim. `redactPatterns`
then runs over the result as a net for credential *shapes* nobody told us about.
Scopes are per-operation and short-lived on purpose: a process-wide registry of
every value ever resolved would itself be a target.

```ts
import { RedactionScope, redactText } from '@bx-labs/agent-secrets-redaction';

const scope = new RedactionScope();
scope.track(secretValue);
redactText('POST /v1?key=<the tracked value>', scope); // "POST /v1?key=[REDACTED]"
scope.dispose();
```

**2. Streams need an overlap buffer, not just a transform.** A pipe splits
wherever the kernel buffer happened to fill, so a 40-character token can arrive
as 12 characters then 28 — and neither half matches. `createRedactingStream`
holds back the tail of each chunk and re-prepends it, and uses `StringDecoder` so
a multi-byte character is never cut in half.

```ts
import { createRedactingStream } from '@bx-labs/agent-secrets-redaction';

child.stdout.pipe(createRedactingStream(process.stdout, scope));
```

**3. Canaries prove the rules rather than asserting them.** A test generates a
128-bit synthetic value, pushes it through a real flow, and asserts it is absent
everywhere. The helpers refuse any needle that is not a canary, so they can never
be pointed at a real credential, and a failing assertion names the haystacks that
matched and prints no excerpt — the bytes next to a leaked canary are exactly
what the test exists to protect.

```ts
import { assertNoCanary, newCanary, scanPathsForCanary } from '@bx-labs/agent-secrets-redaction';

const canary = newCanary(); // ASECRET_CANARY_<32 hex chars>
assertNoCanary(canary, { stdout, stderr, auditLog });
await scanPathsForCanary(canary, [workingTree]);
```

## What this package is responsible for

Defence in depth in front of every sink, with bounded cost. Exact-match
redaction is a linear substring search per tracked form, so it has no
backtracking and no ReDoS surface. Every pattern keys off a vendor-assigned
prefix or an unmistakable structure — there is deliberately no "long
high-entropy string" rule, because entropy heuristics mangle commit hashes,
UUIDs and minified code, and redaction that ruins ordinary output gets turned
off.

The honest limits, stated plainly: pattern redaction only catches shapes it
knows; values shorter than `MIN_TRACKED_LENGTH` (4) are never tracked, because
rewriting "the" and "id" into `[REDACTED]` would be a self-inflicted outage; and
base64 derivation catches a value encoded on its own, not one embedded inside a
larger base64 blob where its bytes depend on 3-byte alignment.

## More

- [Root README](../../README.md) — what Agent Secrets is and is not
- [`docs/logging.md`](../../docs/logging.md) — the allowed and forbidden log
  fields these transforms enforce, and why length is disclosure

Apache-2.0.
