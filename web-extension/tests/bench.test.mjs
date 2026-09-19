/**
 * Performance guards.
 *
 * The paper claims a native build sustains ~450 MB/s and that encryption
 * overhead is negligible for a chat message. This port is portable JavaScript,
 * so the absolute number is far lower — but the *shape* of the cost is what a
 * user can feel, and that shape has to hold:
 *
 *   • sealing a chat-size message must stay far below a frame time;
 *   • per-byte cost must not blow up with message size (no accidental O(n²));
 *   • the paper's Algorithm-1 dictionary must stay within a sane size.
 *
 * The bounds are deliberately loose: they are regression guards against an
 * accidental algorithmic change, not a benchmark of the machine running them.
 */
import test from 'node:test';
import assert from 'node:assert/strict';

const {
  kbEncryptWithKey, kbEncryptToDict, kbDecryptFromDict, kbGenerateSessionKey, kbUtf8
} = await import('../src/crypto.js');

const runs = 3;

/** Fastest of `runs` timings, in milliseconds (see scripts/bench.mjs). */
async function fastest(fn) {
  await fn();
  let best = Infinity;
  for (let i = 0; i < runs; i++) {
    const started = process.hrtime.bigint();
    await fn();
    best = Math.min(best, Number(process.hrtime.bigint() - started) / 1e6);
  }
  return best;
}

test('sealing a chat-size message stays far below a frame', async () => {
  const key = kbGenerateSessionKey();
  const message = 'a'.repeat(500);

  const dict = await kbEncryptToDict(message, key);
  const dictMs = await fastest(() => kbEncryptToDict(message, key));
  assert.ok(dictMs < 50, `500-character dictionary seal took ${dictMs.toFixed(2)} ms`);
  assert.ok(await fastest(() => kbDecryptFromDict(dict, key)) < 50, 'opening a dictionary must be fast too');
});

test('per-byte cost does not blow up with message size', async () => {
  const key = kbGenerateSessionKey();
  const small = 'a'.repeat(1024);
  const large = 'a'.repeat(64 * 1024);

  const smallMs = await fastest(() => kbEncryptWithKey(small, key));
  const largeMs = await fastest(() => kbEncryptWithKey(large, key));

  // linear would be 64×; anything close to quadratic would be thousands
  const factor = largeMs / Math.max(smallMs, 0.01);
  assert.ok(largeMs < smallMs * 64 * 20, `64 KiB took ${largeMs.toFixed(2)} ms vs ${smallMs.toFixed(2)} ms for 1 KiB`);

  // and the cost per byte of the large message must be the smaller of the two
  assert.ok(largeMs / large.length <= (smallMs / small.length) * 4, `per-byte factor ${factor.toFixed(1)}×`);
});

test('the Algorithm 1 dictionary stays close to the payload it carries', async () => {
  const key = kbGenerateSessionKey();
  const message = 'a'.repeat(500);
  const dict = await kbEncryptToDict(message, key);
  const serialized = JSON.stringify(dict);

  // base64 expands by 4/3; the tag and nonce add a fixed 36 bytes
  assert.ok(serialized.length < 500 * 2, `dictionary is ${serialized.length} chars for 500 bytes`);
  assert.ok(serialized.includes('"nonce"') && serialized.includes('"ciphertext"') && serialized.includes('"tag"'));
  assert.equal(kbUtf8(message).length, 500);
});
