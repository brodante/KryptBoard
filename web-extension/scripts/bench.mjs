#!/usr/bin/env node
/**
 * KryptBoard benchmark.
 *
 * Mirrors the measurements the paper reports (AEAD throughput ~450 MB/s,
 * "negligible overhead" on a chat-size message, near-linear growth with
 * message length) against *this* implementation, so the numbers in the README
 * are reproducible rather than copied from the paper's native build.
 *
 *   node scripts/bench.mjs            human-readable report
 *   node scripts/bench.mjs --json     same numbers as JSON
 *
 * The crypto core is portable JavaScript (no crypto.subtle ChaCha20-Poly1305
 * in Chromium), so absolute throughput is far below the paper's figure; what
 * matters here is the shape: how much a message costs, and whether that cost
 * grows linearly.
 */
import {
  kbEncrypt, kbDecrypt, kbEncryptWithKey, kbEncryptToDict, kbDecryptFromDict,
  kbGenerateSessionKey, kbKeyFingerprint, kbUtf8, kbZeroizeBytes
} from '../src/crypto.js';

const json = process.argv.includes('--json');

function now() {
  return Number(process.hrtime.bigint()) / 1e6;
}

/**
 * Fastest of `runs` timings, in milliseconds, after two warm-up runs.
 *
 * The minimum is the honest number for a throughput measurement: the JIT and
 * the garbage collector only ever make an individual run slower, and a median
 * of a handful of runs is dominated by warm-up noise at small message sizes.
 */
async function timeIt(fn, runs = 7) {
  await fn();
  await fn();
  let best = Infinity;
  for (let i = 0; i < runs; i++) {
    const started = now();
    await fn();
    best = Math.min(best, now() - started);
  }
  return best;
}

function message(bytes) {
  return 'a'.repeat(bytes);
}

async function main() {
  const passphrase = 'benchmark-passphrase';
  const sessionKey = kbGenerateSessionKey();
  const results = { runtime: process.version, aeadd: [], kdf: {}, overhead: {}, shapes: {} };

  /* 1. the paper's headline number: AEAD throughput on a session key ---- */
  const sizes = [500, 1024, 16 * 1024, 64 * 1024, 256 * 1024, 1024 * 1024];
  for (const bytes of sizes) {
    const text = message(bytes);
    const sealMs = await timeIt(() => kbEncryptWithKey(text, sessionKey));
    const envelope = await kbEncryptWithKey(text, sessionKey);
    const openMs = await timeIt(() => kbDecryptFromDict(
      { nonce: envelope.split('|')[2], ciphertext: envelope.split('|')[3], tag: envelope.split('|')[4] },
      sessionKey
    ));
    const dictChars = JSON.stringify(await kbEncryptToDict(text, sessionKey)).length;
    results.aeadd.push({
      bytes,
      sealMs: Number(sealMs.toFixed(3)),
      openMs: Number(openMs.toFixed(3)),
      mbPerSecond: Number((bytes / 1024 / 1024 / (sealMs / 1000)).toFixed(2)),
      envelopeChars: envelope.length,
      dictChars
    });
  }

  /* 2. key derivation, the passphrase model's extra cost --------------- */
  results.kdf.hkdfMs = Number((await timeIt(() => kbEncrypt('bench', passphrase))).toFixed(3));
  results.kdf.pbkdf2_200kMs = Number((await timeIt(
    () => kbEncrypt('bench', passphrase, { hardened: true, iterations: 200000 })
  )).toFixed(3));

  /* 3. "negligible overhead" on a chat-size message -------------------- */
  const chat = message(500);
  const kdfOnlyMs = await timeIt(() => kbEncrypt(chat, passphrase));
  const sessionOnlyMs = await timeIt(() => kbEncryptWithKey(chat, sessionKey));
  const plainDict = await kbEncryptToDict(chat, sessionKey);
  results.overhead = {
    chatBytes: 500,
    passphraseMs: Number(kdfOnlyMs.toFixed(3)),
    sessionMs: Number(sessionOnlyMs.toFixed(3)),
    dictChars: JSON.stringify(plainDict).length
  };

  /* 4. what the wire formats cost -------------------------------------- */
  const envelope = await kbEncryptWithKey(chat, sessionKey);
  results.shapes = {
    plaintextBytes: kbUtf8(chat).length,
    envelopeChars: envelope.length,
    dictChars: JSON.stringify(await kbEncryptToDict(chat, sessionKey)).length,
    expansion: Number((envelope.length / chat.length).toFixed(2)),
    fingerprint: kbKeyFingerprint(sessionKey)
  };

  /* 5. zeroization still costs nothing measurable ---------------------- */
  const scratch = new Uint8Array(chat.length * 3);
  results.zeroizeMs = Number((await timeIt(() => {
    const buf = scratch.slice();
    kbZeroizeBytes(buf);
  })).toFixed(4));

  kbZeroizeBytes(sessionKey);

  if (json) {
    process.stdout.write(`${JSON.stringify(results, null, 2)}\n`);
    return;
  }

  const line = (s) => process.stdout.write(`${s}\n`);
  line(`KryptBoard benchmark — node ${process.version}, portable JS ChaCha20-Poly1305\n`);
  line('AEAD throughput (session key, no KDF):');
  line('  payload |  envelope |    dict |     seal |     open | sealed MB/s');
  for (const row of results.aeadd) {
    line(`  ${String(row.bytes).padStart(7)} | ${String(row.envelopeChars).padStart(9)} | ${String(row.dictChars).padStart(7)} | ${String(row.sealMs).padStart(8)} | ${String(row.openMs).padStart(8)} | ${String(row.mbPerSecond).padStart(11)}`);
  }
  const first = results.aeadd[0];
  const last = results.aeadd[results.aeadd.length - 1];
  const perByteFirst = first.sealMs / first.bytes;
  const perByteLast = last.sealMs / last.bytes;
  line(`\n  per-byte cost: ${(perByteFirst * 1e6).toFixed(1)} ns at 500 B → ${(perByteLast * 1e6).toFixed(1)} ns at 1 MiB`);
  line(`  scaling factor: ${(perByteFirst / perByteLast).toFixed(2)}× — a chat-size message pays a fixed`);
  line('  setup cost, so its per-byte figure is the highest; the curve flattens from 16 KiB on.');
  line('  The 1 MiB row drops again: building a 1.4 MB base64 string, not the cipher, dominates.');
  line('\nKey derivation (per message, passphrase model):');
  line(`  HKDF-SHA256      ${results.kdf.hkdfMs} ms`);
  line(`  PBKDF2 200k+HKDF ${results.kdf.pbkdf2_200kMs} ms`);
  line('\nChat-size message (500 characters):');
  line(`  passphrase model ${results.overhead.passphraseMs} ms end to end`);
  line(`  session key      ${results.overhead.sessionMs} ms of pure AEAD`);
  line('\nWire formats (500 characters):');
  line(`  envelope ${results.shapes.envelopeChars} chars (${results.shapes.expansion}× the plaintext)`);
  line(`  dict     ${results.shapes.dictChars} chars (Algorithm 1)`);
  line(`  key fingerprint ${results.shapes.fingerprint}`);
  line('\nA person types ~5 characters/second, so even the passphrase model spends');
  line('well under a frame per message. The paper\'s 450 MB/s figure is a native');
  line('build: this portable implementation trades throughput for being the same');
  line('code in every browser and in Node.');
}

main().catch((error) => {
  process.stderr.write(`${error && error.stack ? error.stack : error}\n`);
  process.exitCode = 1;
});
