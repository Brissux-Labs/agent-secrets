import { Writable } from 'node:stream';
import { describe, expect, it } from 'vitest';
import {
  createRedactingStream,
  newCanary,
  REDACTION_TOKEN,
  RedactionScope,
} from '../../src/index.js';

function collector(): { target: Writable; text: () => string } {
  const chunks: Buffer[] = [];
  const target = new Writable({
    write(chunk: Buffer, _encoding, callback): void {
      chunks.push(Buffer.from(chunk));
      callback();
    },
  });
  return { target, text: () => Buffer.concat(chunks).toString('utf8') };
}

async function pipeThrough(
  scope: RedactionScope,
  writes: readonly (string | Buffer)[],
): Promise<string> {
  const sink = collector();
  const stream = createRedactingStream(sink.target, scope);
  for (const write of writes) {
    stream.write(write);
  }
  await new Promise<void>((resolve) => stream.end(resolve));
  return sink.text();
}

describe('createRedactingStream', () => {
  it('forwards ordinary output untouched', async () => {
    const scope = new RedactionScope();

    expect(await pipeThrough(scope, ['hello ', 'world\n'])).toBe('hello world\n');
  });

  it('redacts a tracked value inside a single chunk', async () => {
    const canary = newCanary();
    const scope = new RedactionScope();
    scope.trackString(canary);

    const out = await pipeThrough(scope, [`export TOKEN=${canary}\n`]);

    expect(out).not.toContain(canary);
    expect(out).toBe(`export TOKEN=${REDACTION_TOKEN}\n`);
  });

  it('redacts a value split across two chunk boundaries', async () => {
    // The case that makes naive per-chunk redaction worthless: a pipe splits
    // wherever the kernel buffer filled, not where a token ends.
    const canary = newCanary();
    const scope = new RedactionScope();
    scope.trackString(canary);

    // The prefix is longer than the overlap window on purpose, so the first
    // chunk is genuinely forwarded and only its tail is withheld. A shorter
    // prefix would let the whole thing sit in the buffer until `_final` and
    // prove nothing.
    const prefix = `${'x'.repeat(200)} `;
    const head = canary.slice(0, 11);
    const tail = canary.slice(11);

    const out = await pipeThrough(scope, [`${prefix}${head}`, `${tail} suffix\n`]);

    expect(out).not.toContain(canary);
    expect(out).not.toContain(head);
    expect(out).toBe(`${prefix}${REDACTION_TOKEN} suffix\n`);
  });

  it('redacts a value split one character at a time', async () => {
    const canary = newCanary();
    const scope = new RedactionScope();
    scope.trackString(canary);

    const out = await pipeThrough(scope, [...`log ${canary} end\n`]);

    expect(out).not.toContain(canary);
    expect(out).toBe(`log ${REDACTION_TOKEN} end\n`);
  });

  it('redacts a value that straddles three chunks', async () => {
    const canary = newCanary();
    const scope = new RedactionScope();
    scope.trackString(canary);

    const out = await pipeThrough(scope, [
      canary.slice(0, 5),
      canary.slice(5, 30),
      `${canary.slice(30)}\n`,
    ]);

    expect(out).not.toContain(canary);
    expect(out).toBe(`${REDACTION_TOKEN}\n`);
  });

  it('does not corrupt a multi-byte character split across chunks', async () => {
    const scope = new RedactionScope();
    const bytes = Buffer.from('héllo wörld 😀', 'utf8');

    const out = await pipeThrough(scope, [bytes.subarray(0, 2), bytes.subarray(2)]);

    expect(out).toBe('héllo wörld 😀');
    expect(out).not.toContain('�');
  });

  it('does not cut an astral character in half at the overlap boundary', async () => {
    const scope = new RedactionScope();
    const text = '😀'.repeat(10);

    // The overlap window lands between the two UTF-16 units of an emoji unless
    // the writer steps back a unit.
    expect(await pipeThrough(scope, [text])).toBe(text);
  });

  it('flushes the withheld overlap when the stream ends', async () => {
    const canary = newCanary();
    const scope = new RedactionScope();
    scope.trackString(canary);

    // The final chunk ends mid-word: the overlap buffer holds it back, and only
    // `_final` may release it.
    const out = await pipeThrough(scope, ['tail-without-newline']);

    expect(out).toBe('tail-without-newline');
  });

  it('picks up values tracked after the stream was created', async () => {
    const canary = newCanary();
    const scope = new RedactionScope();
    const sink = collector();
    const stream = createRedactingStream(sink.target, scope);

    stream.write('starting\n');
    scope.trackString(canary);
    stream.write(`resolved ${canary}\n`);
    await new Promise<void>((resolve) => stream.end(resolve));

    expect(sink.text()).not.toContain(canary);
    expect(sink.text()).toBe(`starting\nresolved ${REDACTION_TOKEN}\n`);
  });

  it('applies pattern redaction to a child process that printed a foreign token', async () => {
    const scope = new RedactionScope();
    const sample = `ghp_${'examplenotarealtoken'.padEnd(36, '0')}`;

    const out = await pipeThrough(scope, [`gh auth status -> ${sample}\n`]);

    expect(out).toBe(`gh auth status -> ${REDACTION_TOKEN}\n`);
  });

  it('leaves the target open so a shared stdout stays usable', async () => {
    const scope = new RedactionScope();
    const sink = collector();
    const stream = createRedactingStream(sink.target, scope);

    await new Promise<void>((resolve) => stream.end('done', resolve));

    expect(sink.target.writableEnded).toBe(false);
    expect(sink.text()).toBe('done');
  });
});
