/**
 * Crypto core tests.
 *
 * The important part: every primitive is checked against the *published*
 * test vectors of its RFC, not only against itself. If these pass, the
 * browser build really is ChaCha20-Poly1305 as specified.
 *
 *   RFC 8439 §2.3.2  ChaCha20 block function
 *   RFC 8439 §2.4.2  ChaCha20 encryption
 *   RFC 8439 §2.5.2  Poly1305
 *   RFC 8439 §2.8.2  ChaCha20-Poly1305 AEAD (full message + tag)
 *   RFC 5869 A.1-A.3 HKDF-SHA256
 *   RFC 4231 §4.2-4.3 HMAC-SHA256
 *   FIPS 180-4       SHA-256
 *   RFC 7914 §11     PBKDF2-HMAC-SHA256
 */
import test from 'node:test';
import assert from 'node:assert/strict';

import {
  KBError,
  KB_ALGORITHM,
  KB_ALGORITHM_HARDENED,
  KB_PBKDF2_ITERATIONS,
  kbAeadOpen,
  kbAeadSeal,
  kbB64UrlDecode,
  kbB64UrlEncode,
  kbChaCha20Block,
  kbBytesToU32LE,
  kbChaCha20Xor,
  kbDecrypt,
  kbDeriveKey,
  kbDescribeEnvelope,
  kbEncrypt,
  kbFormatEnvelope,
  kbHkdf,
  kbHkdfExpand,
  kbHkdfExtract,
  kbHmacSha256,
  kbLooksLikeEnvelope,
  kbParseEnvelope,
  kbPbkdf2Sha256,
  kbPbkdf2Sha256Js,
  kbPoly1305,
  kbSha256,
  kbUtf8,
  kbFromUtf8
} from '../src/crypto.js';

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */

const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
const unhex = (s) => new Uint8Array(s.trim().replace(/\s+/g, '').match(/../g).map((h) => parseInt(h, 16)));

/* ------------------------------------------------------------------ */
/* SHA-256 / HMAC                                                      */
/* ------------------------------------------------------------------ */

test('SHA-256 matches FIPS 180-4 vectors', () => {
  assert.equal(hex(kbSha256(kbUtf8(''))), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  assert.equal(hex(kbSha256(kbUtf8('abc'))), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.equal(
    hex(kbSha256(kbUtf8('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'))),
    '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1'
  );
  // multi-block message (> 64 bytes, exercises the padding boundary)
  assert.equal(
    hex(kbSha256(kbUtf8('a'.repeat(1000)))),
    '41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3'
  );
  // 55 / 56 / 64 byte boundaries must not corrupt the length block
  assert.equal(hex(kbSha256(new Uint8Array(55))), '02779466cdec163811d078815c633f21901413081449002f24aa3e80f0b88ef7');
  assert.equal(hex(kbSha256(new Uint8Array(56))), 'd4817aa5497628e7c77e6b606107042bbba3130888c5f47a375e6179be789fbb');
  assert.equal(hex(kbSha256(new Uint8Array(64))), 'f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b');
});

test('HMAC-SHA256 matches RFC 4231 vectors', () => {
  assert.equal(
    hex(kbHmacSha256(unhex('0b'.repeat(20)), kbUtf8('Hi There'))),
    'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7'
  );
  assert.equal(
    hex(kbHmacSha256(kbUtf8('Jefe'), kbUtf8('what do ya want for nothing?'))),
    '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843'
  );
  // key longer than the 64-byte block
  assert.equal(
    hex(kbHmacSha256(unhex('aa'.repeat(131)), kbUtf8('Test Using Larger Than Block-Size Key - Hash Key First'))),
    '60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54'
  );
});

/* ------------------------------------------------------------------ */
/* HKDF                                                                */
/* ------------------------------------------------------------------ */

test('HKDF-SHA256 matches RFC 5869 A.1 (basic)', () => {
  const ikm = unhex('0b'.repeat(22));
  const salt = unhex('000102030405060708090a0b0c');
  const info = unhex('f0f1f2f3f4f5f6f7f8f9');
  const prk = kbHkdfExtract(salt, ikm);
  assert.equal(hex(prk), '077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5');
  const okm = kbHkdfExpand(prk, info, 42);
  assert.equal(hex(okm), '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865');
  assert.equal(hex(kbHkdf(ikm, salt, info, 42)), hex(okm));
});

test('HKDF-SHA256 matches RFC 5869 A.2 (long inputs) and A.3 (empty salt/info)', () => {
  const okmA2 = kbHkdf(
    unhex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f'),
    unhex('606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf'),
    unhex('b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'),
    82
  );
  assert.equal(
    hex(okmA2),
    'b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87'
  );
  const okmA3 = kbHkdf(unhex('0b'.repeat(22)), new Uint8Array(0), new Uint8Array(0), 42);
  assert.equal(hex(okmA3), '8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8');
});

/* ------------------------------------------------------------------ */
/* ChaCha20 / Poly1305                                                 */
/* ------------------------------------------------------------------ */

test('ChaCha20 block function matches RFC 8439 §2.3.2', () => {
  const key = unhex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
  const nonce = unhex('000000090000004a00000000');
  const block = kbChaCha20Block(kbBytesToU32LE(key, 0, 8), kbBytesToU32LE(nonce, 0, 3), 1);
  assert.equal(
    hex(block),
    '10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e' +
      'd2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e'
  );
});

test('ChaCha20 encryption matches RFC 8439 §2.4.2', () => {
  const key = unhex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
  const nonce = unhex('000000000000004a00000000');
  const plaintext = kbUtf8("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.");
  const ct = kbChaCha20Xor(key, nonce, 1, plaintext);
  assert.equal(
    hex(ct),
    '6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b' +
      'f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8' +
      '07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736' +
      '5af90bbf74a35be6b40b8eedf2785e42874d'
  );
  // XOR is an involution
  assert.equal(hex(kbChaCha20Xor(key, nonce, 1, ct)), hex(plaintext));
});

test('Poly1305 matches RFC 8439 §2.5.2', () => {
  const key = unhex('85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b');
  const tag = kbPoly1305(kbUtf8('Cryptographic Forum Research Group'), key);
  assert.equal(hex(tag), 'a8061dc1305136c6c22b8baf0c0127a9');
});

test('Poly1305 tag is sensitive to every bit of the message', () => {
  const key = unhex('85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b');
  const a = kbPoly1305(kbUtf8('Cryptographic Forum Research Group'), key);
  const b = kbPoly1305(kbUtf8('Cryptographic Forum Research Grouq'), key);
  assert.notEqual(hex(a), hex(b));
});

test('ChaCha20-Poly1305 AEAD matches the full RFC 8439 §2.8.2 vector', () => {
  const key = unhex('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f');
  const nonce = unhex('070000004041424344454647');
  const aad = unhex('50515253c0c1c2c3c4c5c6c7');
  const plaintext = kbUtf8(
    "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
  );

  const { ct, tag } = kbAeadSeal(key, nonce, plaintext, aad);
  assert.equal(
    hex(ct),
    'd31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6' +
      '3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36' +
      '92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc' +
      '3ff4def08e4b7a9de576d26586cec64b6116'
  );
  assert.equal(hex(tag), '1ae10b594f09e26a7e902ecbd0600691');

  const opened = kbAeadOpen(key, nonce, ct, tag, aad);
  assert.equal(kbFromUtf8(opened), kbFromUtf8(plaintext));
});

test('AEAD rejects tampered ciphertext, tag, nonce and AAD', () => {
  const key = kbDeriveKeySyncStub();
  const nonce = new Uint8Array(12).fill(7);
  const aad = kbUtf8('context');
  const { ct, tag } = kbAeadSeal(key, nonce, kbUtf8('attack at dawn'), aad);

  const flip = (u8, i) => {
    const copy = u8.slice();
    copy[i] ^= 0x01;
    return copy;
  };

  assert.throws(() => kbAeadOpen(key, nonce, flip(ct, 0), tag, aad), (e) => e instanceof KBError && e.code === 'AUTH_FAILED');
  assert.throws(() => kbAeadOpen(key, nonce, ct, flip(tag, 0), aad), (e) => e.code === 'AUTH_FAILED');
  assert.throws(() => kbAeadOpen(key, flip(nonce, 0), ct, tag, aad), (e) => e.code === 'AUTH_FAILED');
  assert.throws(() => kbAeadOpen(key, nonce, ct, tag, kbUtf8('other context')), (e) => e.code === 'AUTH_FAILED');
  assert.throws(() => kbAeadOpen(key, nonce, ct.slice(0, -1), tag, aad), (e) => e.code === 'AUTH_FAILED');
});

// local helper: a fixed 32-byte key without touching the KDF
function kbDeriveKeySyncStub() {
  return new Uint8Array(32).map((_, i) => (i * 7 + 3) & 0xff);
}

/* ------------------------------------------------------------------ */
/* PBKDF2                                                              */
/* ------------------------------------------------------------------ */

test('PBKDF2-HMAC-SHA256 matches RFC 7914 §11 vectors', async () => {
  const cases = [
    ['password', 'salt', 1, 32, '120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b'],
    ['password', 'salt', 2, 32, 'ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43'],
    ['password', 'salt', 4096, 32, 'c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a'],
    ['passwordPASSWORDpassword', 'saltSALTsaltSALTsaltSALTsaltSALTsalt', 4096, 40, '348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9']
  ];
  for (const [p, s, c, len, expected] of cases) {
    assert.equal(hex(kbPbkdf2Sha256Js(kbUtf8(p), kbUtf8(s), c, len)), expected, `js  ${p}/${c}`);
    assert.equal(hex(await kbPbkdf2Sha256(kbUtf8(p), kbUtf8(s), c, len)), expected, `webcrypto ${p}/${c}`);
  }
});

/* ------------------------------------------------------------------ */
/* base64url                                                           */
/* ------------------------------------------------------------------ */

test('base64url round-trips and matches the Android Base64Url contract', () => {
  for (let len = 0; len < 70; len++) {
    const bytes = new Uint8Array(len).map((_, i) => (i * 31 + len) & 0xff);
    const encoded = kbB64UrlEncode(bytes);
    assert.equal(encoded.includes('='), false, 'must be unpadded');
    assert.equal(encoded.includes('+'), false, 'must use the url alphabet');
    assert.equal(encoded.includes('/'), false, 'must use the url alphabet');
    assert.equal(hex(kbB64UrlDecode(encoded)), hex(bytes));
  }
  assert.equal(hex(kbB64UrlDecode('AQAB')), '010001');
  assert.throws(() => kbB64UrlDecode('not*valid'), (e) => e.code === 'BAD_ENVELOPE');
  // padded input from other tools is tolerated
  assert.equal(hex(kbB64UrlDecode('AQAB=')), '010001');
});

/* ------------------------------------------------------------------ */
/* envelope + end-to-end                                               */
/* ------------------------------------------------------------------ */

test('envelope keeps the Android v1|alg|nonce|ct|tag shape', async () => {
  const env = await kbEncrypt('hello board', 'correct horse battery staple');
  const parts = env.split('|');
  assert.equal(parts.length, 5);
  assert.equal(parts[0], 'v1');
  assert.equal(parts[1], 'CHACHA20-POLY1305');
  assert.equal(kbB64UrlDecode(parts[2]).length, 12, 'nonce is 12 bytes');
  assert.equal(kbB64UrlDecode(parts[4]).length, 16, 'tag is 16 bytes');
  assert.equal(kbB64UrlDecode(parts[3]).length, kbUtf8('hello board').length, 'ct length matches plaintext');
  assert.equal(/[\s]/.test(env), false, 'envelope is a single whitespace-free token');
  assert.ok(kbLooksLikeEnvelope(env));
});

test('round-trip: ASCII, unicode, emoji, empty-ish and 1 KiB payloads', async () => {
  const pass = 'päss-phrase-🔐-with-ünicode';
  const samples = [
    'hello world',
    'ünïcödé — em dash, “ smart quotes ”, ✓',
    'emoji 🔐🛡️👋🏽 family 👨‍👩‍👧‍👦 with ZWJ',
    'newlines\nand\ttabs and \\ backslash | pipe',
    'x'.repeat(1024),
    '  trailing space  '
  ];
  for (const s of samples) {
    const env = await kbEncrypt(s, pass);
    assert.equal(await kbDecrypt(env, pass), s);
  }
});

test('round-trip with the PBKDF2-hardened KDF, self-described by alg', async () => {
  const env = await kbEncrypt('hardened secret', 'pw', { hardened: true, iterations: 4096 });
  assert.match(env, /^v1\|CHACHA20-POLY1305\+PBKDF2-4096\|/);
  // the receiver learns the work factor from the envelope alone
  assert.equal(kbParseEnvelope(env).iterations, 4096);
  assert.equal(await kbDecrypt(env, 'pw'), 'hardened secret');

  // hardening must actually change the derived key
  const plain = kbParseEnvelope(await kbEncrypt('hardened secret', 'pw'));
  const keyA = await kbDeriveKey('pw', plain.nonce, '', { hardened: false });
  const keyB = await kbDeriveKey('pw', plain.nonce, '', { hardened: true, iterations: 4096 });
  assert.notEqual(hex(keyA), hex(keyB));
});

test('the work factor is bounded in both directions', async () => {
  // absurdly high iteration counts in an incoming envelope are refused
  assert.throws(
    () => kbParseEnvelope(`v1|CHACHA20-POLY1305+PBKDF2-999999999999|AQAB|AQAB|AQAB`),
    (e) => e.code === 'UNSUPPORTED_ALG'
  );
  // too-low counts are refused as well (they would silently weaken the KDF)
  assert.throws(
    () => kbParseEnvelope('v1|CHACHA20-POLY1305+PBKDF2-1|AQAB|AQAB|AQAB'),
    (e) => e.code === 'UNSUPPORTED_ALG'
  );
  // values requested above the ceiling are clamped on the way out
  const env = await kbEncrypt('x', 'pw', { hardened: true, iterations: 1e12 });
  assert.match(env, /PBKDF2-5000000\|/);
});

test('decryption fails loudly on wrong passphrase, wrong AAD and corruption', async () => {
  const env = await kbEncrypt('top secret', 'passphrase-A', { aad: 'channel-1' });
  await assert.rejects(() => kbDecrypt(env, 'passphrase-B', { aad: 'channel-1' }), (e) => e.code === 'AUTH_FAILED');
  await assert.rejects(() => kbDecrypt(env, 'passphrase-A', { aad: 'channel-2' }), (e) => e.code === 'AUTH_FAILED');

  const parts = env.split('|');
  const ct = kbB64UrlDecode(parts[3]);
  ct[0] ^= 0x80;
  parts[3] = kbB64UrlEncode(ct);
  await assert.rejects(() => kbDecrypt(parts.join('|'), 'passphrase-A', { aad: 'channel-1' }), (e) => e.code === 'AUTH_FAILED');

  await assert.rejects(() => kbEncrypt('x', ''), (e) => e.code === 'NO_PASSPHRASE');
});

test('malformed envelopes are rejected with typed errors', () => {
  const cases = [
    ['garbage', 'BAD_ENVELOPE'],
    ['v1|CHACHA20-POLY1305|only|four', 'BAD_ENVELOPE'],
    ['v9|CHACHA20-POLY1305|AAAA|AAAA|AAAA', 'UNSUPPORTED_VERSION'],
    ['v1|ROT13|AQAB|AQAB|AQAB', 'UNSUPPORTED_ALG'],
    ['v1|CHACHA20-POLY1305|AA|AQAB|AQAB', 'BAD_ENVELOPE'], // 1-byte nonce
    ['v1|CHACHA20-POLY1305|AQAB|AQAB|AA', 'BAD_ENVELOPE'], // 1-byte tag
    ['v1|CHACHA20-POLY1305|AQ*B|AQAB|AQAB', 'BAD_ENVELOPE']
  ];
  for (const [input, code] of cases) {
    assert.throws(() => kbParseEnvelope(input), (e) => e instanceof KBError && e.code === code, input);
    assert.equal(kbLooksLikeEnvelope(input), false, input);
  }
});

test('nonce is fresh for every message (no keystream reuse)', async () => {
  const seen = new Set();
  for (let i = 0; i < 200; i++) {
    const env = await kbEncrypt('same plaintext', 'same passphrase');
    const nonce = env.split('|')[2];
    assert.equal(seen.has(nonce), false, 'nonce repeated!');
    seen.add(nonce);
  }
  assert.equal(seen.size, 200);
  // identical plaintext must produce different ciphertext bodies
  const a = (await kbEncrypt('same plaintext', 'same passphrase')).split('|')[3];
  const b = (await kbEncrypt('same plaintext', 'same passphrase')).split('|')[3];
  assert.notEqual(a, b);
});

test('a caller-supplied nonce makes the envelope deterministic (for test vectors)', async () => {
  const nonce = unhex('000102030405060708090a0b');
  const a = await kbEncrypt('determinism', 'pw', { nonce });
  const b = await kbEncrypt('determinism', 'pw', { nonce });
  assert.equal(a, b);
  assert.equal(await kbDecrypt(a, 'pw'), 'determinism');
});

test('appending the AAD label is bound to the tag, not hidden in the envelope', async () => {
  const env = await kbEncrypt('msg', 'pw', { aad: 'room-42' });
  assert.equal(env.includes('room-42'), false, 'AAD must not leak into the ciphertext string');
  assert.equal(await kbDecrypt(env, 'pw', { aad: 'room-42' }), 'msg');
});

test('oversized payloads are refused before allocation', async () => {
  const big = 'A'.repeat((1 << 20) + 1);
  await assert.rejects(() => kbEncrypt(big, 'pw'), (e) => e.code === 'BAD_ENVELOPE');

  const fake = `v1|${KB_ALGORITHM}|AQAB|${'A'.repeat(Math.ceil((1 << 20) * 4 / 3) + 64)}|AQAB`;
  assert.throws(() => kbParseEnvelope(fake), (e) => e.code === 'BAD_ENVELOPE');
});

/**
 * Golden wire-format vectors.
 *
 * These pin the exact bytes on the wire, so any future refactor that silently
 * changed the envelope or the KDF would fail loudly. The derived keys in
 * `KDF_GOLDEN` below were recomputed independently with Python's hashlib/hmac
 * (HKDF-SHA256 with salt = nonce and info = "KryptBoard v1|CHACHA20-POLY1305|aad=…"),
 * which is the cross-check that the browser KDF agrees with a second
 * implementation — i.e. with whatever the Kotlin side implements.
 */
const KDF_GOLDEN = {
  nonce: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
  passphrase: 'shared-passphrase',
  aad: '',
  key: 'pjO1qRCwhiVIzvHCZIHK9XhUC5GzzfXgqb5C9RyqqYY',
  envelope: 'v1|CHACHA20-POLY1305|AAECAwQFBgcICQoL|v3zLgOoEJpt1WRBZHWUUNgTWJ0Lnp1V8|Y99GfDC7dpwhry83MrId2g'
};

test('KDF golden vectors (cross-checked against Python hashlib/hmac)', async () => {
  const nonce = new Uint8Array(KDF_GOLDEN.nonce);
  assert.equal(kbB64UrlEncode(await kbDeriveKey(KDF_GOLDEN.passphrase, nonce, '')), KDF_GOLDEN.key);
  assert.equal(
    kbB64UrlEncode(await kbDeriveKey(KDF_GOLDEN.passphrase, nonce, 'channel-7')),
    'DCW4x4tp-So5DKZeFCI89jb_Ix1AUvHs_FUaT7oc-0U'
  );
  assert.equal(
    kbB64UrlEncode(await kbDeriveKey(KDF_GOLDEN.passphrase, nonce, '', { hardened: true, iterations: 1000 })),
    'jqiapYBIRMAXYYpjyPWP8kYoUG1mldha0FMUbCw8UQ4'
  );
});

test('envelope golden vector is stable (Android crypto-lib interop)', async () => {
  const nonce = new Uint8Array(KDF_GOLDEN.nonce);
  const envelope = await kbEncrypt('KryptBoard interop check', KDF_GOLDEN.passphrase, { nonce });
  assert.equal(envelope, KDF_GOLDEN.envelope);
  assert.equal(await kbDecrypt(KDF_GOLDEN.envelope, KDF_GOLDEN.passphrase), 'KryptBoard interop check');
});

test('defaults are the documented ones', () => {
  assert.equal(KB_PBKDF2_ITERATIONS, 200000);
  assert.equal(KB_ALGORITHM_HARDENED.endsWith('+PBKDF2'), true);
  assert.equal(kbFormatEnvelope({
    alg: KB_ALGORITHM,
    nonce: new Uint8Array(12),
    ct: new Uint8Array(0),
    tag: new Uint8Array(16)
  }), `v1|${KB_ALGORITHM}|AAAAAAAAAAAAAAAA||AAAAAAAAAAAAAAAAAAAAAA`);
  assert.deepEqual(kbDescribeEnvelope(kbParseEnvelope(
    `v1|${KB_ALGORITHM}|AAAAAAAAAAAAAAAA|AQAB|AAAAAAAAAAAAAAAAAAAAAA`
  )), {
    algorithm: KB_ALGORITHM,
    hardened: false,
    iterations: 0,
    plaintextBytes: 3,
    envelopeBytes: `v1|${KB_ALGORITHM}|AAAAAAAAAAAAAAAA|AQAB|AAAAAAAAAAAAAAAAAAAAAA`.length
  });
});

/* ------------------------------------------------------------------ */
/* property / fuzz tests                                               */
/* ------------------------------------------------------------------ */

/**
 * Deterministic PRNG so a failing case can be reproduced from its seed,
 * and every reported iteration number maps to the same input forever.
 */
function mulberry32(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const CODE_POINTS = [
  ...Array.from({ length: 0x20 }, (_, i) => 0x20 + i), // printable ASCII
  0x00e9, 0x00fc, 0x0141, 0x03b1, 0x0416, 0x05d0, 0x0627, 0x3042, 0x4e2d, 0xac00,
  0x1f510, 0x1f6e1, 0x1f44b, 0x1f469, 0x200d, 0x0a, 0x09, 0x26a0
];

function randomString(rand, maxLength) {
  const length = Math.floor(rand() * (maxLength + 1));
  let out = '';
  for (let i = 0; i < length; i++) {
    const cp = CODE_POINTS[Math.floor(rand() * CODE_POINTS.length)];
    out += String.fromCodePoint(cp);
  }
  return out;
}

test('fuzz: 250 random round-trips, byte-for-byte identical', async () => {
  const rand = mulberry32(0xc0ffee);
  const aaDs = ['', '', 'room-42', 'channel:7', 'ünïcödé-aad'];

  for (let i = 0; i < 250; i++) {
    const plaintext = randomString(rand, 400);
    const passphrase = randomString(rand, 24) || 'p'; // empty passphrases are refused by design
    const aad = aaDs[Math.floor(rand() * aaDs.length)];
    const hardened = rand() < 0.1;
    const options = hardened ? { aad, hardened: true, iterations: 1000 } : { aad };

    const envelope = await kbEncrypt(plaintext, passphrase, options);
    const recovered = await kbDecrypt(envelope, passphrase, { aad });
    assert.equal(recovered, plaintext, `iteration ${i} did not round-trip`);
  }
});

test('fuzz: every single-bit corruption is detected, never silently accepted', async () => {
  const rand = mulberry32(0x5eed);
  const passphrase = 'fuzz-passphrase';
  let checks = 0;

  for (let i = 0; i < 120; i++) {
    const plaintext = randomString(rand, 80) || 'x';
    const envelope = await kbEncrypt(plaintext, passphrase);
    const parts = envelope.split('|');

    // corrupt one byte of the nonce, the ciphertext or the tag
    const field = 2 + Math.floor(rand() * 3);
    const bytes = kbB64UrlDecode(parts[field]);
    const index = Math.floor(rand() * bytes.length);
    const bit = 1 << Math.floor(rand() * 8);
    bytes[index] ^= bit;
    parts[field] = kbB64UrlEncode(bytes);
    const tampered = parts.join('|');

    let outcome = 'accepted';
    let recovered = null;
    try {
      recovered = await kbDecrypt(tampered, passphrase);
    } catch (error) {
      outcome = error.code || error.name;
    }
    assert.notEqual(outcome, 'accepted', `iteration ${i}: tampered envelope decrypted to ${JSON.stringify(recovered)}`);
    assert.equal(outcome, 'AUTH_FAILED', `iteration ${i}: expected AUTH_FAILED, got ${outcome}`);
    checks++;
  }
  assert.equal(checks, 120);
});

test('fuzz: structural damage is rejected as malformed, not as a crypto failure', async () => {
  const rand = mulberry32(0xdead);
  const passphrase = 'fuzz-passphrase';

  for (let i = 0; i < 80; i++) {
    const envelope = await kbEncrypt(randomString(rand, 40) || 'y', passphrase);
    const parts = envelope.split('|');
    const damage = Math.floor(rand() * 4);

    let candidate = envelope;
    if (damage === 0) candidate = parts.slice(0, 4).join('|'); // dropped field
    if (damage === 1) candidate = `${envelope}|extra`;
    if (damage === 2) candidate = envelope.replace('v1|', 'v2|'); // wrong version
    if (damage === 3) parts[3] = parts[3].slice(0, -3); // truncated ciphertext
    if (damage === 3) candidate = parts.join('|');

    let code = null;
    try {
      await kbDecrypt(candidate, passphrase);
    } catch (error) {
      code = error.code;
    }
    assert.ok(
      ['BAD_ENVELOPE', 'UNSUPPORTED_VERSION', 'AUTH_FAILED'].includes(code),
      `iteration ${i}: damage ${damage} produced ${code}`
    );
    if (damage === 0 || damage === 1) assert.equal(code, 'BAD_ENVELOPE');
    if (damage === 2) assert.equal(code, 'UNSUPPORTED_VERSION');
  }
});

test('fuzz: a wrong passphrase never yields plaintext', async () => {
  const rand = mulberry32(0x1234);
  for (let i = 0; i < 40; i++) {
    const plaintext = randomString(rand, 60) || 'z';
    const right = `right-${i}`;
    const wrong = `wrong-${i}-${Math.floor(rand() * 1e9)}`;
    const envelope = await kbEncrypt(plaintext, right);
    await assert.rejects(
      () => kbDecrypt(envelope, wrong),
      (error) => error.code === 'AUTH_FAILED',
      `iteration ${i}`
    );
  }
});

test('ciphertext never contains the plaintext, and nonces never repeat', async () => {
  const rand = mulberry32(0xbeef);
  const seen = new Set();

  for (let i = 0; i < 120; i++) {
    // long, highly recognisable plaintexts make an accidental leak obvious
    const plaintext = 'LEAK-CANARY-' + randomString(rand, 120).replace(/[^A-Za-z0-9]/g, '') + '-END';
    const envelope = await kbEncrypt(plaintext, 'pw');
    assert.equal(envelope.includes('LEAK-CANARY'), false, `iteration ${i} leaked plaintext into the envelope`);

    const nonce = envelope.split('|')[2];
    assert.equal(seen.has(nonce), false, `iteration ${i} reused a nonce`);
    seen.add(nonce);
  }
  assert.equal(seen.size, 120);
});

test('re-formatting a parsed envelope reproduces it exactly (canonical form)', async () => {
  const rand = mulberry32(0x9999);
  for (let i = 0; i < 60; i++) {
    const envelope = await kbEncrypt(randomString(rand, 100), 'pw', { aad: 'ctx' });
    assert.equal(kbFormatEnvelope(kbParseEnvelope(envelope)), envelope, `iteration ${i}`);
  }
});

test('64 KiB stays comfortably fast (no accidental quadratic behaviour)', async () => {
  const plaintext = 'a'.repeat(64 * 1024);
  const started = Date.now();
  const envelope = await kbEncrypt(plaintext, 'pw');
  const recovered = await kbDecrypt(envelope, 'pw');
  const elapsed = Date.now() - started;
  assert.equal(recovered.length, plaintext.length);
  assert.ok(elapsed < 5000, `64 KiB round-trip took ${elapsed} ms`);
});
