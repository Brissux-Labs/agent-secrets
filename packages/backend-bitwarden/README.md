# @bx-labs/agent-secrets-backend-bitwarden

The [Bitwarden Secrets Manager](https://bitwarden.com/products/secrets-manager/)
storage adapter for [Agent Secrets](../../README.md).

It implements the `SecretBackend` contract from
`@bx-labs/agent-secrets-core` on top of the official `bws` CLI, run in a
hardened subprocess. Agent Secrets stores nothing itself; this is the package
that talks to the only place a value rests.

**Who imports it:** the `agent-secrets` CLI and the MCP server. Import it
directly only if you are embedding the broker in your own tool — end users
install [`@bx-labs/agent-secrets`](../cli/README.md) instead.

```bash
npm install @bx-labs/agent-secrets-backend-bitwarden
```

Requires the official `bws` binary on `PATH` (or an absolute path) and a
Bitwarden Secrets Manager machine account token.

## The three things worth knowing

**1. One Bitwarden project, scope encoded in the key.** Every record for an
installation lives in a single Bitwarden project, keyed
`<project>/<environment>/<name>`. That is what lets two machines share one
project with independent, separately revocable tokens. The cost is that
Bitwarden-side permissions are per-project, so environment isolation is enforced
by the Agent Secrets policy engine rather than by the vault.

```ts
import { BitwardenBackend } from '@bx-labs/agent-secrets-backend-bitwarden';

const backend = new BitwardenBackend({
  accessToken: tokenFromTheOsCredentialStore,
  projectId: '00000000-0000-0000-0000-000000000000',
});

await backend.list({ backend: 'bitwarden', project: 'demo-app', environment: 'development' });
```

**2. There is no `resolveOne`.** The only read path for values is
`resolveMany(refs)`, which returns `SecretValue` instances for the CLI's `run` to
place in a child environment block. A batch-only API makes "resolve one and
print it" an awkward thing to write, which is the point. `list` and `describe`
return metadata only, and `describe` on a missing secret is `null`, not an error.

**3. Every subprocess goes through one hardened `run`.** `execFile` with
`shell: false` and an argument array, an explicit minimal environment (nothing is
inherited), a fixed `SAFE_PATH` so a poisoned `PATH` entry cannot substitute a
token-capturing binary, a timeout with kill escalation, and an output cap.
`bws` stdout is parsed with a Zod schema — that is a security control, not a
nicety — and stderr is redacted and truncated before it can reach an error.

## What this package is responsible for

Making a value's round trip to the vault the only thing that happens, and making
every failure sanitized. A non-zero `bws` exit is classified into an
`AgentSecretsError` subclass by reading the already-redacted stderr for known
phrases; the stderr text itself is never embedded in the resulting message,
because Bitwarden's error output has been observed to echo request payloads. A
response that is not valid JSON, or that does not match the schema, becomes
`BACKEND_UNAVAILABLE` with no output attached.

The one exposure this package does not hide: `bws secret create` takes the value
as a command-line argument, and on macOS and Linux `ps` shows argv to any process
of the same user. The client probes `bws` for a stdin transport at runtime and
prefers it when available, reporting which was used via `valueTransport`. When
only argv is available the window applies to `create` and `update` alone, and the
adversary it helps is one already running as your user — who could read the
access token from the credential store and query the vault directly. It is a real
narrowing we would rather not ship, not a hole we discovered late.

## More

- [Root README](../../README.md) — what Agent Secrets is and is not
- [`docs/architecture.md`](../../docs/architecture.md) — the backend contract and
  the storage layout
- [`docs/threat-model.md`](../../docs/threat-model.md) — the argv window and what
  else we do not stop

Apache-2.0.
