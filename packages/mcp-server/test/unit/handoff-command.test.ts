import { makeRef } from '@bx-labs/agent-secrets-core';
import { describe, expect, it } from 'vitest';
import { handoffCommand } from '../../src/index.js';

/**
 * The command an agent hands to a human.
 *
 * Why this is a function in the tool and not a sentence in the model's reply:
 * the human is about to paste it into a shell. A command line composed by a
 * language model is a command line an injected instruction can shape — into the
 * wrong environment, into a different binary, or into `bws secret create KEY
 * <value>`, which would put the value in argv and in shell history. Composed
 * here, every component comes from `makeRef`, so the reference grammar has
 * already rejected anything that could become a second command.
 */

describe('handoffCommand', () => {
  const ref = makeRef({ project: 'bx-labs', environment: 'development', name: 'OPENAI_API_KEY' });

  it('maps a create request to `add`', () => {
    expect(handoffCommand('create', ref)).toBe(
      'agent-secrets add OPENAI_API_KEY --project bx-labs --env development',
    );
  });

  it('maps a rotate request to `rotate`, not `add`', () => {
    expect(handoffCommand('rotate', ref)).toBe(
      'agent-secrets rotate OPENAI_API_KEY --project bx-labs --env development',
    );
  });

  it('names the environment explicitly, because nothing ever defaults it', () => {
    const preview = makeRef({ project: 'bx-labs', environment: 'preview', name: 'OPENAI_API_KEY' });
    expect(handoffCommand('create', preview)).toContain('--env preview');
  });

  /**
   * The property that makes this safe to paste. Not "we escape it" — we do not
   * escape anything; the grammar cannot produce a character that would need it.
   */
  it('cannot contain a shell metacharacter, whatever the reference', () => {
    const awkward = makeRef({
      project: 'a0-very-long-project-slug-with-many-hyphens-in-it-0123456789',
      environment: 'production',
      name: 'A_VERY_LONG_NAME_WITH_DIGITS_0123456789_AND_UNDERSCORES',
    });

    expect(handoffCommand('create', awkward)).toMatch(/^[A-Za-z0-9 _-]+$/);
  });

  it('never offers a way to pass the value, because there is none', () => {
    expect(handoffCommand('create', ref)).not.toMatch(/--value|--secret|--token/);
  });
});
