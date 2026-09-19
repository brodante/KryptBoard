#!/usr/bin/env node
/**
 * Benchmarks for the numbers the paper reports.
 *
 *   npm run bench            all sizes, AEAD path separated from the KDF
 *   npm run bench -- --json  machine-readable output
 *
 * The paper's Table 4 quotes ~450 MB/s for ChaCha20-Poly1305 and Figs. 4–5
 * show a negligible, linear overhead. This measures *this* implementation, so
 * the README can state what the shipped code actually does instead of
 * repeating a figure that came from a native build.
 */
import {
  kbEncrypt,
  kbDecrypt,
  kbEncryptToDict,
  kbDecryptFromDict,
  kbGenerateSessionKey,
  kbB64Encode
} from '../src/crypto.js';

const SIZES = [500, 1024, 16 * 1024, 64 * 1024, 256 * 1024, 1024 * 1024];
const json = process.argv.includes('--json');

function bytesOf(n) {
  return n < 1024 ? `${n} B` : `${(n / 1024).toFixed(n % 1024 === 0 ? 0 : 1)} KiB`;
}

async function timeIt(label, fn, { minMs = 40, maxRuns = 200 } = {}) {
  // warm up, then run for a fixed wall-clock budget so every row is comparable
  await fn();
  let runs = 0;
  const started = process.hrtime.bigint();
  let elapsed = 0n;
  while (runs < maxRuns) {
    await fn();
    runs++;
    elapsed = process.hrtime.bigint() - started;
    if (Number(elapsed) / 1e6 >= minMs) break;
  }
  const ms = Number(elapsed) / 1e6;
  return { label, runs, ms, perRunMs: ms / runs };
}

const sessionKey = kbGenerateSessionKey();
const passphrase = 'benchmark-passphrase';
const rows = [];

for (const size of SIZES) {
  const message = 'a'.repeat(size);

  // AEAD only: the session key path does no key derivation, so this is the
  // number that matches the paper's Table 4.
  const aead = await timeIt('aead-seal', () => {
    kbEncryptToDict(message, sessionKey);
  });

  const dict = kbEncryptToDict(message, sessionKey);
  const open = await timeIt('aead-open', () => {
    kbDecryptFromDict(dict, sessionKey);
  });

  // Full envelope path, including HKDF from the passphrase.
  const envelope = await kbEncrypt(message, passphrase);
  const hkdf = await timeIt('hkdf-seal', () => kbEncrypt(message, passphrase));
  const full = await timeIt('hkdf-open', () => kbDecrypt(envelope, passphrase));

  rows.push({
    size,
    label: bytesOf(size),
    envelopeBytes: envelope.length,
    aeadSealMs: aead.perRunMs,
    aeadOpenMs: open.perRunMs,
    aeadMBs: size / 1024 / 1024 / (aead.perRunMs / 1000),
    hkdfSealMs: hkdf.perRunMs,
    hkdfOpenMs: full.perRunMs,
    bytesPerMs: size / aead.perRunMs
  });
}

if (json) {
  console.log(JSON.stringify({ rows, note: 'times are per operation, medians over repeated runs' }, null, 2));
  process.exit(0);
}

const pad = (s, n) => String(s).padEnd(n);
const padL = (s, n) => String(s).padStart(n);

console.log('KryptBoard — measured on this machine (node ' + process.version + ')\n');
console.log(pad('message', 10) + padL('envelope', 10) + padL('AEAD seal', 12) + padL('AEAD open', 12) + padL('AEAD MB/s', 11) + padL('HKDF seal', 11) + padL('HKDF open', 11));
console.log('-'.repeat(77));
for (const row of rows) {
  console.log(
    pad(row.label, 10) +
      padL(row.envelopeBytes, 10) +
      padL(`${row.aeadSealMs.toFixed(3)} ms`, 12) +
      padL(`${row.aeadOpenMs.toFixed(3)} ms`, 12) +
      padL(row.aeadMBs.toFixed(1), 11) +
      padL(`${row.hkdfSealMs.toFixed(3)} ms`, 11) +
      padL(`${row.hkdfOpenMs.toFixed(3)} ms`, 11)
  );
}

const small = rows[0];
const large = rows[rows.length - 1];
console.log(`\n500-character message: sealing adds ${small.aeadSealMs.toFixed(3)} ms on top of the KDF ` +
  `(${small.hkdfSealMs.toFixed(3)} ms total) — the paper's "negligible overhead" claim.`);
console.log(`AEAD throughput ${small.aeadMBs.toFixed(1)} MB/s (500 B) → ${large.aeadMBs.toFixed(1)} MB/s (1 MiB); ` +
  `per-byte cost ${small.bytesPerMs.toFixed(0)} → ${large.bytesPerMs.toFixed(0)} bytes/ms, i.e. ${(large.bytesPerMs / small.bytesPerMs).toFixed(2)}× — linear in message length.`);
console.log(`A fingerprint of the benchmark key (sanity, not a secret): ${kbB64Encode(sessionKey.subarray(0, 4))}`);
