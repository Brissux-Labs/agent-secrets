# @bx-labs/agent-secrets-core

The domain core of [Agent Secrets](../../README.md), an open-source secret broker
for AI agents.

This package holds no I/O, no subprocess, and no network call. It is the shared
vocabulary every other package is written against: canonical references,
sanitized errors, metadata and audit schemas, the policy engine, and the
`SecretValue` wrapper.

**Who imports it:** every other package in the monorepo — the CLI, the Bitwarden
adapter, the MCP server, the API, the Telegram bot. Import it directly if you are
writing a backend adapter or a tool that speaks the same reference grammar.

```bash
npm install @bx-labs/agent-secrets-core
```

## The three things worth knowing

**1. `SecretValue` is the only type allowed to carry a value.** It keeps the
string in a `#private` field, so it survives neither spread, `Object.keys`,
`structuredClone`, nor `JSON.stringify`. `toString` and `util.inspect` return
`[secret]`; `toJSON` throws, because a serializer reaching a value is a defect
worth surfacing. Reading it means calling the greppable `expose()`.

```ts
import { SecretValue } from '@bx-labs/agent-secrets-core';

const value = SecretValue.from(rawFromHiddenPrompt);
console.log(`${value}`); // "[secret]"
JSON.stringify({ value }); // throws SecretDisclosureError

// expose: handing the value to the child process environment block
childEnv['EXAMPLE_API_KEY'] = value.expose();
value.dispose(); // best effort — see the note below
```

**2. Every secret has one address, and the environment is never inferred.**
References are `backend/project/environment/name`, validated by a narrow grammar
so the same string cannot mean two things downstream.

```ts
import { makeRef, parseRef } from '@bx-labs/agent-secrets-core';

parseRef('bitwarden/demo-app/development/EXAMPLE_API_KEY');
parseRef('demo-app/development/EXAMPLE_API_KEY'); // backend defaults
makeRef({ project: 'demo-app', name: 'EXAMPLE_API_KEY' }); // type error: environment is required
```

**3. Policy is a decision made in code, not in a prompt.** `PolicyEngine` is
deny-by-default: an action absent from a project's allow list is denied, an
unknown project is denied, and a policy file that fails to parse is a hard
failure rather than a fallback to permissive defaults. The built-in rules give
`development` the full lifecycle, `preview` read plus `run`, and `production`
`list` and `describe` only.

```ts
import { PolicyEngine } from '@bx-labs/agent-secrets-core';

new PolicyEngine().assert({ action: 'rotate', target: ref }); // PolicyDeniedError in production
```

## What this package is responsible for

Making disclosure a loud failure rather than a silent one, at the type level and
at the serialization boundary. Concretely: `SecretValue` has no path to a string
that is not an `expose()` call; `AgentSecretsError` messages are built from
constants and validated identifiers, never from a raw `bws` or `spawn` message,
and the original throwable on `cause` is non-enumerable so `console.error(err)`
cannot print it; metadata and audit schemas are `.strict()`, and
`assertNoValueFields` walks any payload for a `value`, `length`, `hash` or
`preview` field before it is serialized.

What it does **not** claim: `dispose()` cannot scrub the bytes from process
memory — JavaScript strings are immutable and garbage-collected, so it drops our
own reference and nothing more. Nor does this package stop a program you
deliberately hand a value to from doing whatever it likes with it.

## More

- [Root README](../../README.md) — what Agent Secrets is and is not
- [`docs/architecture.md`](../../docs/architecture.md) — the backend contract and
  data model this package defines
- [`docs/exit-codes.md`](../../docs/exit-codes.md) — the `EXIT_CODES` / error-code
  mapping, which is a public contract

Apache-2.0.
