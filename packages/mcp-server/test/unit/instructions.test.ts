import { describe, expect, it } from 'vitest';
import { SERVER_INSTRUCTIONS } from '../../src/index.js';

/**
 * The one piece of guidance that reaches every client.
 *
 * Tool descriptions are read when a model is already considering a tool.
 * `instructions` is sent once, at initialize, before the model has decided
 * anything — so it is where the process belongs: *when* to involve this server
 * at all, and what never to do with a credential regardless of which tool is in
 * front of it. Claude Code, Codex, Hermes and OpenClaw all receive the same
 * string; none of them is special-cased, and none of them should be.
 *
 * It is guidance, not enforcement. What the code guarantees is that no tool can
 * return a value; what this string does is stop a model from going looking
 * elsewhere — a `.env`, its own memory, a shell history — when a task needs one.
 * Both tests below matter: the rules must be present, and the string must stay
 * short enough that a client actually shows it.
 */

describe('SERVER_INSTRUCTIONS', () => {
  const rules: Array<[string, RegExp]> = [
    ['no tool returns a value', /no tool[\s\S]{0,40}returns? a value/i],
    ['never ask for a paste', /never[\s\S]{0,80}paste/i],
    ['never write a value to a file or a log', /\.env/],
    ['never fall back to another store', /fallback|fall back/i],
    ['report the blockage instead of routing around it', /unavailable[\s\S]{0,120}stop/i],
    ['an exposed value is compromised', /compromised/i],
    ['and must be revoked at the provider', /revoked[\s\S]{0,60}provider/i],
    ['metadata tools are for checking, not reading', /secret_describe/],
    ['execution goes through run_with_secrets', /run_with_secrets/],
    ['creation goes through the request tools', /secret_add_request/],
    ['rotation goes through the request tools', /secret_rotate_request/],
    ['deletion needs the canonical confirmation', /secret_delete_request/],
    ['the CLI fallback is a hidden prompt', /agent-secrets add[\s\S]{0,400}hidden prompt/i],
    ['names reach the application unchanged', /OPENAI_API_KEY/],
    ['derived data is disclosure too', /length[\s\S]{0,60}hash/i],
  ];

  for (const [label, pattern] of rules) {
    it(`states that ${label}`, () => {
      expect(SERVER_INSTRUCTIONS).toMatch(pattern);
    });
  }

  it('never suggests that a value could be obtained', () => {
    expect(SERVER_INSTRUCTIONS).not.toMatch(/retrieve|read the value|get the value|reveal/i);
  });

  it('stays short enough to survive a client that truncates', () => {
    // A rule nobody reads is a rule that does not exist. If this needs raising,
    // cut something first.
    expect(SERVER_INSTRUCTIONS.length).toBeLessThan(3000);
  });

  it('carries no example that looks like a credential', () => {
    expect(SERVER_INSTRUCTIONS).not.toMatch(/sk-[A-Za-z0-9]{8}|ghp_[A-Za-z0-9]{8}/);
  });
});
