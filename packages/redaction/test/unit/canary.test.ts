import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  assertNoCanary,
  CANARY_PREFIX,
  isCanary,
  MAX_SCANNED_FILE_BYTES,
  newCanary,
  scanPathsForCanary,
} from '../../src/index.js';

describe('newCanary', () => {
  it('produces a recognisable, obviously synthetic value', () => {
    const canary = newCanary();

    expect(canary.startsWith(CANARY_PREFIX)).toBe(true);
    expect(canary).toMatch(/^ASECRET_CANARY_[0-9a-f]{32}$/);
    expect(isCanary(canary)).toBe(true);
  });

  it('never repeats', () => {
    const canaries = new Set(Array.from({ length: 500 }, () => newCanary()));

    expect(canaries.size).toBe(500);
  });
});

describe('assertNoCanary', () => {
  it('passes when nothing leaked', () => {
    const canary = newCanary();

    expect(() =>
      assertNoCanary(canary, {
        stdout: 'export TOKEN=[REDACTED]\n',
        stderr: '',
        auditLog: Buffer.from('{"operation":"run","outcome":"success"}\n', 'utf8'),
        missingSink: undefined,
      }),
    ).not.toThrow();
  });

  it('names the haystacks that leaked', () => {
    const canary = newCanary();

    expect(() =>
      assertNoCanary(canary, {
        stdout: 'clean',
        stderr: `spawn failed: ${canary}`,
        auditLog: Buffer.from(`value=${canary}`, 'utf8'),
      }),
    ).toThrow(/stderr, auditLog/);
  });

  it('never prints the leaked content or its surroundings', () => {
    const canary = newCanary();
    const neighbour = 'AN-ADJACENT-VALUE-THAT-MUST-NOT-BE-PRINTED';

    try {
      assertNoCanary(canary, { stdout: `${neighbour} ${canary} ${neighbour}` });
      expect.unreachable('assertNoCanary should have thrown');
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      // The bytes next to a leaked canary are whatever the flow was handling at
      // the time. A failure message that dumps them leaks into CI logs, which
      // are usually more widely readable than the process that leaked.
      expect(message).not.toContain(canary);
      expect(message).not.toContain(neighbour);
      expect(message).toContain('stdout');
    }
  });

  it('detects a canary written as UTF-16', () => {
    const canary = newCanary();

    expect(() => assertNoCanary(canary, { plist: Buffer.from(canary, 'utf16le') })).toThrow(
      /plist/,
    );
  });

  it('detects a canary that leaked base64-encoded', () => {
    // A value base64'd into a header has leaked exactly as much as one printed
    // verbatim, so the harness must not be fooled by the encoding.
    const canary = newCanary();
    const encoded = Buffer.from(canary, 'utf8').toString('base64');

    expect(() => assertNoCanary(canary, { header: `Basic ${encoded}` })).toThrow(/header/);
  });

  it('refuses a needle that is not a canary', () => {
    expect(() => assertNoCanary('some-real-looking-token', { stdout: '' })).toThrow(TypeError);
  });
});

describe('scanPathsForCanary', () => {
  let root = '';

  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), 'agent-secrets-canary-'));
  });

  afterEach(async () => {
    await rm(root, { recursive: true, force: true });
  });

  it('finds the canary in nested files and reports nothing else', async () => {
    const canary = newCanary();
    await mkdir(join(root, 'nested', 'deeper'), { recursive: true });
    await writeFile(join(root, 'clean.txt'), 'nothing to see');
    await writeFile(join(root, 'nested', 'leak.log'), `resolved ${canary}\n`);
    await writeFile(join(root, 'nested', 'deeper', 'also.json'), JSON.stringify({ canary }));

    const hits = await scanPathsForCanary(canary, [root]);

    expect(hits).toHaveLength(2);
    expect(hits).toContain(join(root, 'nested', 'leak.log'));
    expect(hits).toContain(join(root, 'nested', 'deeper', 'also.json'));
  });

  it('returns an empty list for a clean tree', async () => {
    const canary = newCanary();
    await writeFile(join(root, 'clean.txt'), 'redacted output only');

    expect(await scanPathsForCanary(canary, [root])).toEqual([]);
  });

  it('finds a canary that was written out base64-encoded', async () => {
    const canary = newCanary();
    await writeFile(
      join(root, 'config.json'),
      JSON.stringify({ auth: Buffer.from(canary, 'utf8').toString('base64') }),
    );

    expect(await scanPathsForCanary(canary, [root])).toEqual([join(root, 'config.json')]);
  });

  it('reads binary files without throwing and still finds the bytes', async () => {
    const canary = newCanary();
    const binary = Buffer.concat([
      Buffer.from([0x00, 0xff, 0xfe, 0x80, 0x01]),
      Buffer.from(canary, 'utf8'),
      Buffer.from([0x00, 0xc0, 0x80]),
    ]);
    await writeFile(join(root, 'core.dump'), binary);
    await writeFile(join(root, 'image.bin'), Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x00, 0xff]));

    const hits = await scanPathsForCanary(canary, [root]);

    expect(hits).toEqual([join(root, 'core.dump')]);
  });

  it('skips node_modules, .git and dist', async () => {
    const canary = newCanary();
    for (const directory of ['node_modules', '.git', 'dist']) {
      await mkdir(join(root, directory), { recursive: true });
      await writeFile(join(root, directory, 'noise.txt'), canary);
    }

    expect(await scanPathsForCanary(canary, [root])).toEqual([]);
  });

  it('does not read a file above the size cap', async () => {
    const canary = newCanary();
    const oversized = Buffer.alloc(MAX_SCANNED_FILE_BYTES + 1, 0x61);
    oversized.write(canary, 0, 'utf8');
    await writeFile(join(root, 'huge.log'), oversized);

    // The cap is a deliberate blind spot: reading arbitrary-sized artefacts into
    // memory would turn the safety net into an out-of-memory failure.
    expect(await scanPathsForCanary(canary, [root])).toEqual([]);
  });

  it('ignores paths that do not exist', async () => {
    const canary = newCanary();

    expect(await scanPathsForCanary(canary, [join(root, 'nope')])).toEqual([]);
  });

  it('refuses a needle that is not a canary', async () => {
    await expect(scanPathsForCanary('not-a-canary', [root])).rejects.toBeInstanceOf(TypeError);
  });
});
