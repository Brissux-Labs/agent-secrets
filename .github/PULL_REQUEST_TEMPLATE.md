# Summary

<!-- What changes, and why. Link the ROADMAP item or issue. -->

## Leak surface

Every box is a claim about this diff. Leave one unchecked and say why rather than
checking it optimistically — an unchecked box starts a conversation, a wrong tick
ends one.

- [ ] **No raw value reaches a log, an error message, a tool result, a JSON
      envelope, a result schema, a database row, or a process argument.** Value
      length, hash, prefix, suffix and entropy count as the value.
- [ ] **No new `expose()` call site**, or every new one carries a
      `// expose: <reason>` comment and is one of the three destinations in
      CLAUDE.md §1.
- [ ] **Canary test added** for any leak-relevant behaviour this PR touches: run
      the flow with a generated canary and assert its absence from stdout,
      stderr, log sinks, the SQLite file, generated config, and the working tree.
- [ ] **No new dependency that can observe a value.** If a dependency was added,
      name it here with what it can see and why nothing already present will do.
- [ ] **Errors are sanitized at the boundary** — no backend or subprocess message
      is re-thrown or rendered.
- [ ] **Fails closed**: unknown input, unreachable backend, ambiguous policy and
      missing environment all refuse and exit non-zero.

## Quality gates (run locally, not just in CI)

- [ ] `pnpm lint`
- [ ] `pnpm typecheck`
- [ ] `pnpm test`
- [ ] `pnpm test:integration`
- [ ] `node scripts/scan-secrets.mjs`
- [ ] `node scripts/check-no-raw-getter.mjs`

## Does this change authentication, token handling, redaction, or production policy?

<!--
Answer yes or no explicitly. "Yes" is not a problem; an unanswered question is.

If yes, this PR needs human review before merge regardless of who wrote it and
regardless of whether CI is green — CLAUDE.md §8. That covers: auth or
authorization logic, one-time token generation/binding/consumption, redaction
rules or logging sinks, production policy gates, and anything that changes what
`agent-secrets run` puts into a child environment.

Request a review from a maintainer and say which of those areas is affected.
-->

**Answer:**

## Documentation

- [ ] `DOC.md` updated if durable behaviour changed.
- [ ] `CONTEXT.md` has a dated entry for this intervention.
- [ ] Exit codes unchanged, or the change is called out as breaking.
