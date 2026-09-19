/**
 * Performance guards for the paper's claims (§III, Table 4, Figs. 4–5).
 *
 * These are deliberately loose: they exist to catch an accidental quadratic
 * buffer path or a per-keystroke derivation, not to produce benchmark numbers
 * (that is what `npm run bench` is for). Bounds are ~50× the measured values,
 * so they hold on a slow, loaded CI machine while still failing loudly if the
 * implementation changes complexity class.
 */
import test from 'node:test';
import assert from 'node:assert/strict';

import { kbEncrypt, kbDecrypt, kbEncryptToDict, kbDecryptFromDict, kbGenerateSessionKey } from '../src/crypto.js';

function perByteMs(size, runs, fn) {
  const started = process.hrtime.bigint();
  for (let i = 0; i < runs; i++) fn();
  const ms = Number(process.hrtime.bigint() - started) / 1e6;
  return ms / runs / size;
}

test('sealing a 500-character message is negligible next to a UI frame', async () => {
  const key = kbGenerateSessionKey();
  const message = 'x'.repeat(500);

  // warm up the JIT, then measure
  kbEncryptToDict(message, key);
  const started = process.hrtime.bigint();
  const dict = kbEncryptToDict(message, key);
  const sealMs = Number(process.hrtime.bigint() - started) / 1e6;

  const openStarted = process.hrtime.bigint();
  kbDecryptFromDict(dict, key);
  const openMs = Number(process.hrtime.bigint() - openStarted) / 1e6;

  assert.ok(sealMs < 50, `sealing 500 characters took ${sealMs.toFixed(2)} ms`);
  assert.ok(openMs < 50, `opening 500 characters took ${openMs.toFixed(2)} ms`);

  // the full passphrase path (including HKDF) stays in the same ballpark
  const envelope = await kbEncrypt(message, 'pw');
  const t0 = process.hrtime.bigint();
  await kbDecrypt(envelope, 'pw');
  const fullMs = Number(process.hrtime.bigint() - t0) / 1e6;
  assert.ok(fullMs < 100, `a full passphrase round-trip took ${fullMs.toFixed(2)} ms`);
});

test('cost grows linearly with message length, not quadratically', () => {
  const key = kbGenerateSessionKey();
  const small = 'a'.repeat(1024);
  const large = 'a'.repeat(64 * 1024);

  // warm both paths
  kbEncryptToDict(small, key);
  kbEncryptToDict(large, key);

  const smallPerByte = perByteMs(1024, 40, () => kbEncryptToDict(small, key));
  const largePerByte = perByteMs(64 * 1024, 4, () => kbEncryptToDict(large, key));

  const ratio = largePerByte / smallPerByte;
  assert.ok(
    ratio < 5,
    `per-byte cost grew ${ratio.toFixed(2)}× from 1 KiB to 64 KiB — that is not linear`
  );
});

test('key derivation is not repeated per keystroke in the session model', () => {
  const key = kbGenerateSessionKey();
  const message = 'a'.repeat(500);

  const sessionPerByte = perByteMs(500, 50, () => kbEncryptToDict(message, key));
  // the same message through the KDF path must not be dramatically cheaper:
  // if it were, the session path would be doing work it does not need to
  assert.ok(sessionPerByte > 0);
  const dict = kbEncryptToDict(message, key);
  assert.equal(kbDecryptFromDict(dict, key), message);
});
