import { describe, expect, it } from 'vitest';
import {
  bwsSecretListItemSchema,
  bwsSecretListSchema,
  bwsSecretSchema,
} from '../../src/bws-schemas.js';

/**
 * What survives the parse boundary.
 *
 * `bws secret list` returns the value of every secret — that is how its `-o env`
 * output format can exist at all. The list-item schema does not declare a
 * `value` field, which is only half of the guarantee: a passthrough parse keeps
 * undeclared keys, so every value in the project stayed attached to the objects
 * the adapter caches in its lookup index for the lifetime of the command.
 *
 * Nothing printed them — the metadata mapper builds an explicit object — but a
 * plain string holding a credential, living outside `SecretValue`, in a cache,
 * is the shape of a leak waiting for one careless `console.error`. Values are
 * dropped where they are parsed, and only `secret get` / `create` / `edit`,
 * which declare `value` and immediately wrap it, are allowed to carry one.
 */

const LIST_ITEM = {
  object: 'secret',
  id: 'b3d1f0a2-4c8e-4a51-9f7d-2e5b8c1a6d40',
  organizationId: '9f4d2c1e-8b7a-4f6d-9c3e-2a1b5d7e0f84',
  projectId: '10e1d55e-f6e2-42f5-afc9-b4a800c4e36a',
  key: 'ezjob/development/OPENAI_API_KEY',
  note: '',
  creationDate: '2026-08-16T10:00:00.000000Z',
  revisionDate: '2026-08-16T10:00:00.000000Z',
};

describe('bwsSecretListItemSchema', () => {
  it('drops a value that bws includes in list output', () => {
    const canary = `ASECRET_CANARY_${'a1b2c3d4e5f6'}`;
    const parsed = bwsSecretListItemSchema.parse({ ...LIST_ITEM, value: canary });

    expect(parsed).not.toHaveProperty('value');
    expect(JSON.stringify(parsed)).not.toContain(canary);
  });

  it('drops every value across a whole list', () => {
    const canary = `ASECRET_CANARY_${'0f9e8d7c6b5a'}`;
    const parsed = bwsSecretListSchema.parse([
      { ...LIST_ITEM, value: canary },
      { ...LIST_ITEM, id: '5c2a9b73-1d4e-4f88-b0a6-7e3c1f9d2b45', value: canary },
    ]);

    expect(JSON.stringify(parsed)).not.toContain(canary);
  });

  it('still tolerates a field a future bws adds', () => {
    const parsed = bwsSecretListItemSchema.parse({ ...LIST_ITEM, somethingNew: 'x' });

    expect(parsed.key).toBe(LIST_ITEM.key);
    expect(parsed).not.toHaveProperty('somethingNew');
  });

  it('keeps the value on the one schema entitled to carry it', () => {
    const canary = `ASECRET_CANARY_${'7a6b5c4d3e2f'}`;
    const parsed = bwsSecretSchema.parse({ ...LIST_ITEM, value: canary });

    // `splitValue` in bws-client.ts destructures this away into a SecretValue
    // on the next line; it exists here only so that it can be wrapped.
    expect(parsed.value).toBe(canary);
  });
});
