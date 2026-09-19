/**
 * KryptBoard — crypto core (browser port of `crypto-lib`)
 * =====================================================================
 * This module is the JavaScript counterpart of the Android `crypto-lib`
 * module. It keeps the *envelope contract* of the Android app byte for
 * byte, so a ciphertext produced by the browser extension can be pasted
 * into the Android keyboard's buffer (and vice versa):
 *
 *     v1|CHACHA20-POLY1305|<nonce>|<ciphertext>|<tag>
 *
 * where nonce / ciphertext / tag are base64url (RFC 4648 §5, unpadded)
 * and `v1` is a 1-byte version prefix, exactly as `Envelope.kt` writes it.
 *
 * Unlike the Android stubs (`ChaCha20Poly1305Stub.kt` XORs nothing and
 * only base64-encodes the plaintext), this implementation performs real
 * ChaCha20-Poly1305 AEAD as specified in RFC 8439.
 *
 * Everything here is dependency-free and runs both in the browser and in
 * Node >= 18, so the exact same code path is unit-testable.
 *
 * Cryptographic design (documented for the paper's reproducibility section)
 * ---------------------------------------------------------------------
 *   AEAD       : ChaCha20-Poly1305 (RFC 8439), 12-byte nonce, 16-byte tag
 *   KDF        : HKDF-SHA256 (RFC 5869), 32-byte output key
 *                  IKM  = UTF-8(passphrase)
 *                  salt = nonce (12 bytes, fresh per message)
 *                  info = "KryptBoard v1|CHACHA20-POLY1305|aad=<aad>"
 *                A weak-passphrase hardening mode is available:
 *                  IKM  = PBKDF2-HMAC-SHA256(passphrase, salt=nonce, iters)
 *                and is signalled per message through the envelope's `alg`
 *                field ("CHACHA20-POLY1305+PBKDF2"), so the receiver always
 *                knows which KDF to run. The envelope stays 5 fields wide.
 *   AAD        : optional UTF-8 "context label" bound into the tag. It is
 *                deliberately *not* carried in the envelope: the receiver
 *                must know it out of band, which is what makes it useful as
 *                a channel binding.
 *
 * SHA-256 / HMAC / HKDF / PBKDF2 are implemented in portable JavaScript;
 * PBKDF2 transparently uses WebCrypto when the runtime offers it (same
 * output, much faster). No network, no third-party code, no eval.
 */

/* ------------------------------------------------------------------ */
/* Errors                                                              */
/* ------------------------------------------------------------------ */

/** Typed error so callers can react to *why* an operation failed. */
export class KBError extends Error {
  constructor(code, message) {
    super(message || code);
    this.name = 'KBError';
    this.code = code;
  }
}

const KB_ERR = {
  BAD_ENVELOPE: 'BAD_ENVELOPE',
  UNSUPPORTED_VERSION: 'UNSUPPORTED_VERSION',
  UNSUPPORTED_ALG: 'UNSUPPORTED_ALG',
  AUTH_FAILED: 'AUTH_FAILED',
  NO_PASSPHRASE: 'NO_PASSPHRASE',
  RNG_UNAVAILABLE: 'RNG_UNAVAILABLE'
};

/* ------------------------------------------------------------------ */
/* Constants                                                           */
/* ------------------------------------------------------------------ */

export const KB_ENVELOPE_VERSION = 1;
export const KB_ALGORITHM = 'CHACHA20-POLY1305';
export const KB_ALGORITHM_HARDENED = 'CHACHA20-POLY1305+PBKDF2';
// Paper §III (Algorithm 1): the proof-of-concept's single-session key model
// encrypts with a raw 32-byte key held in the extension's storage, with no
// passphrase and therefore no KDF.
export const KB_ALGORITHM_SESSION = 'CHACHA20-POLY1305+SESSIONKEY';
export const KB_SESSION_KEY_BYTES = 32;
export const KB_SESSION_KEY_PREFIX = 'kbk1.';
export const KB_NONCE_BYTES = 12;
export const KB_TAG_BYTES = 16;
export const KB_KEY_BYTES = 32;
export const KB_PBKDF2_ITERATIONS = 200000;
export const KB_PBKDF2_MIN_ITERATIONS = 1000;
/** Upper bound so a hostile envelope cannot pin the CPU for hours. */
export const KB_PBKDF2_MAX_ITERATIONS = 5000000;

/** Hard cap so a hostile paste cannot lock up the tab. */
export const KB_MAX_PAYLOAD_BYTES = 1 << 20; // 1 MiB decoded

export const KB_ENC = new TextEncoder();
export const KB_DEC = new TextDecoder();

/* ------------------------------------------------------------------ */
/* Small byte helpers                                                  */
/* ------------------------------------------------------------------ */

export function kbUtf8(str) {
  return KB_ENC.encode(String(str));
}

export function kbFromUtf8(bytes) {
  return KB_DEC.decode(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes));
}

export function kbConcat(...chunks) {
  let total = 0;
  for (const c of chunks) total += c.length;
  const out = new Uint8Array(total);
  let at = 0;
  for (const c of chunks) {
    out.set(c, at);
    at += c.length;
  }
  return out;
}

export function kbEqualCT(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/** Constant-time-ish; the loop never exits early on early mismatches. */
export function kbPad16(bytes) {
  const rem = bytes.length % 16;
  if (rem === 0) return new Uint8Array(0);
  return new Uint8Array(16 - rem);
}

export function kbU64LE(value) {
  const out = new Uint8Array(8);
  const dv = new DataView(out.buffer);
  dv.setUint32(0, value >>> 0, true);
  dv.setUint32(4, Math.floor(value / 4294967296), true);
  return out;
}

/* ------------------------------------------------------------------ */
/* Randomness — must never be predictable                              */
/* ------------------------------------------------------------------ */

export function kbRandomBytes(length) {
  const c = globalThis.crypto;
  if (!c || typeof c.getRandomValues !== 'function') {
    throw new KBError(KB_ERR.RNG_UNAVAILABLE, 'No cryptographic RNG available in this context.');
  }
  const out = new Uint8Array(length);
  c.getRandomValues(out);
  return out;
}

/* ------------------------------------------------------------------ */
/* base64url (RFC 4648 §5, unpadded) — mirrors Base64Url.kt            */
/* ------------------------------------------------------------------ */

const KB_B64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

export function kbB64UrlEncode(bytes) {
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let out = '';
  for (let i = 0; i < b.length; i += 3) {
    const b0 = b[i];
    const b1 = i + 1 < b.length ? b[i + 1] : undefined;
    const b2 = i + 2 < b.length ? b[i + 2] : undefined;
    out += KB_B64_ALPHABET[b0 >> 2];
    out += KB_B64_ALPHABET[((b0 & 0x03) << 4) | ((b1 ?? 0) >> 4)];
    if (b1 === undefined) break;
    out += KB_B64_ALPHABET[((b1 & 0x0f) << 2) | ((b2 ?? 0) >> 6)];
    if (b2 === undefined) break;
    out += KB_B64_ALPHABET[b2 & 0x3f];
  }
  return out;
}

const KB_B64_LOOKUP = (() => {
  const table = new Int16Array(128).fill(-1);
  for (let i = 0; i < KB_B64_ALPHABET.length; i++) table[KB_B64_ALPHABET.charCodeAt(i)] = i;
  // Accept padded / standard-alphabet input on the way in as well.
  table['+'.charCodeAt(0)] = 62;
  table['/'.charCodeAt(0)] = 63;
  return table;
})();

export function kbB64UrlDecode(str, what = 'base64url value') {
  const s = String(str).replace(/=+$/, '');
  let outLen = Math.floor((s.length * 3) / 4);
  const out = new Uint8Array(outLen);
  let buf = 0;
  let bits = 0;
  let at = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    const v = c < 128 ? KB_B64_LOOKUP[c] : -1;
    if (v < 0) throw new KBError(KB_ERR.BAD_ENVELOPE, `Invalid character in ${what} at index ${i}.`);
    buf = (buf << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[at++] = (buf >> bits) & 0xff;
    }
  }
  return at === outLen ? out : out.subarray(0, at);
}

/* ------------------------------------------------------------------ */
/* Standard base64 (Algorithm 1's wire encoding) and memory hygiene     */
/* ------------------------------------------------------------------ */

const KB_B64_STD = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

/**
 * Algorithm 1 returns `base64.b64encode(...)` output, i.e. the standard
 * alphabet *with* padding. Envelopes keep using the unpadded URL-safe
 * alphabet; the dictionary form matches the paper byte for byte.
 */
export function kbB64Encode(bytes) {
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let out = '';
  for (let i = 0; i < b.length; i += 3) {
    const b0 = b[i];
    const b1 = i + 1 < b.length ? b[i + 1] : undefined;
    const b2 = i + 2 < b.length ? b[i + 2] : undefined;
    out += KB_B64_STD[b0 >> 2];
    out += KB_B64_STD[((b0 & 0x03) << 4) | ((b1 ?? 0) >> 4)];
    out += b1 === undefined ? '=' : KB_B64_STD[((b1 & 0x0f) << 2) | ((b2 ?? 0) >> 6)];
    out += b2 === undefined ? '=' : KB_B64_STD[b2 & 0x3f];
  }
  return out;
}

/** Lenient reader: accepts padded or unpadded, standard or URL-safe alphabet. */
export function kbB64Decode(str, what = 'base64 value') {
  const s = String(str).trim().replace(/=+$/, '');
  if (/=[^=]/.test(s)) throw new KBError(KB_ERR.BAD_ENVELOPE, `Invalid padding in ${what}.`);
  return kbB64UrlDecode(s, what);
}

/**
 * Best-effort zeroization (paper §III, "immediate zeroization").
 *
 * JavaScript strings are immutable, so a plaintext string that has already
 * been handed to the engine cannot be rewritten. Every *byte buffer* we own,
 * however, is overwritten with zeros the moment it stops being needed — the
 * UTF-8 plaintext, the derived or supplied key, and any caller-provided
 * scratch buffer. Callers can pass `options.scratch` to keep the plaintext in
 * memory they control and have it wiped for them.
 */
export function kbZeroizeBytes(view) {
  if (!view) return false;
  if (view instanceof Uint8Array) {
    view.fill(0);
    return true;
  }
  if (ArrayBuffer.isView(view)) {
    new Uint8Array(view.buffer, view.byteOffset, view.byteLength).fill(0);
    return true;
  }
  if (view instanceof ArrayBuffer) {
    new Uint8Array(view).fill(0);
    return true;
  }
  return false;
}

/* ------------------------------------------------------------------ */
/* Single-session keys (paper: "the encryption key is generated and     */
/* managed locally within the extension's secure storage")              */
/* ------------------------------------------------------------------ */

/**
 * Runs `fn(plaintextBytes, plaintextLength)` with the UTF-8 bytes of the
 * message, then zeroizes them — whether they live in our own buffer or in the
 * caller's `options.scratch`. Every encryption path goes through here, so the
 * "buffer is wiped the moment it is no longer needed" rule (paper §III) holds
 * in one place instead of five.
 */
function kbWithPlaintextBytes(plaintext, options, fn) {
  const encoded = kbUtf8(plaintext);
  let owned = encoded;
  try {
    if (encoded.length > KB_MAX_PAYLOAD_BYTES) {
      throw new KBError(KB_ERR.BAD_ENVELOPE, 'Message exceeds the 1 MiB safety limit.');
    }
    let body = encoded;
    if (options.scratch && options.scratch.length >= encoded.length) {
      options.scratch.set(encoded, 0);
      kbZeroizeBytes(encoded);
      owned = null;
      body = options.scratch.subarray(0, encoded.length);
    }
    return fn(body, encoded.length);
  } finally {
    kbZeroizeBytes(owned);
    if (options.scratch) kbZeroizeBytes(options.scratch);
  }
}

export function kbGenerateSessionKey() {
  return kbRandomBytes(KB_SESSION_KEY_BYTES);
}

/** Accepts raw bytes, a `kbk1.` sharing string, or base64/base64url text. */
export function kbNormalizeKeyBytes(key, what = 'key') {
  let bytes;
  if (key instanceof Uint8Array) {
    bytes = key.slice();
  } else if (key && typeof key === 'object' && typeof key.byteLength === 'number') {
    bytes = new Uint8Array(key).slice();
  } else if (typeof key === 'string') {
    const text = key.trim();
    if (!text) throw new KBError(KB_ERR.NO_PASSPHRASE, `A ${what} is required.`);
    bytes = kbB64Decode(text.startsWith(KB_SESSION_KEY_PREFIX) ? text.slice(KB_SESSION_KEY_PREFIX.length) : text, what);
  } else {
    throw new KBError(KB_ERR.NO_PASSPHRASE, `A ${what} is required.`);
  }
  if (bytes.length !== KB_SESSION_KEY_BYTES) {
    kbZeroizeBytes(bytes);
    throw new KBError(KB_ERR.BAD_ENVELOPE, `A ${what} must be ${KB_SESSION_KEY_BYTES} bytes (got ${bytes.length}).`);
  }
  return bytes;
}

/** Text a recipient can paste into their own KryptBoard to read your messages. */
export function kbEncodeSessionKey(key) {
  return KB_SESSION_KEY_PREFIX + kbB64UrlEncode(kbNormalizeKeyBytes(key));
}

/** The inverse of kbEncodeSessionKey (accepts the `kbk1.` prefix, or bare base64). */
export function kbDecodeSessionKey(value) {
  return kbNormalizeKeyBytes(value, 'session key');
}

export function kbLooksLikeSessionKey(value) {
  if (typeof value !== 'string') return false;
  const text = value.trim();
  if (!text.startsWith(KB_SESSION_KEY_PREFIX)) return false;
  try {
    kbNormalizeKeyBytes(text);
    return true;
  } catch (e) {
    return false;
  }
}

/**
 * Short, human-checkable fingerprint of a key, so two parties can confirm out
 * of band that they hold the same one (paper §III: robust key management).
 */
export function kbKeyFingerprint(key) {
  const bytes = kbNormalizeKeyBytes(key);
  try {
    const digest = kbSha256(bytes);
    // 8 bytes → 16 uppercase hex characters → four readable groups. Hex avoids
    // the ambiguity of a base64url group that may itself contain "-".
    const hex = [...digest.subarray(0, 8)].map((b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
    return hex.match(/.{4}/g).join('-');
  } finally {
    kbZeroizeBytes(bytes);
  }
}

/* ------------------------------------------------------------------ */
/* SHA-256 / HMAC-SHA256 (portable)                                    */
/* ------------------------------------------------------------------ */

const KB_SHA256_K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]);

export function kbSha256(bytes) {
  const msg = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  const bitLenHi = Math.floor((msg.length / 0x20000000)); // msg.length * 8 / 2^32
  const bitLenLo = (msg.length * 8) >>> 0;
  const totalLen = Math.ceil((msg.length + 9) / 64) * 64; // msg || 0x80 || 0* || len64
  const padded = new Uint8Array(totalLen);
  padded.set(msg, 0);
  padded[msg.length] = 0x80;
  const dv = new DataView(padded.buffer);
  dv.setUint32(totalLen - 8, bitLenHi, false);
  dv.setUint32(totalLen - 4, bitLenLo, false);

  const h = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
  ]);
  const w = new Uint32Array(64);

  for (let off = 0; off < totalLen; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4, false);
    for (let i = 16; i < 64; i++) {
      const w15 = w[i - 15];
      const w2 = w[i - 2];
      const s0 = ((w15 >>> 7) | (w15 << 25)) ^ ((w15 >>> 18) | (w15 << 14)) ^ (w15 >>> 3);
      const s1 = ((w2 >>> 17) | (w2 << 15)) ^ ((w2 >>> 19) | (w2 << 13)) ^ (w2 >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, hh] = h;
    for (let i = 0; i < 64; i++) {
      const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
      const ch = (e & f) ^ (~e & g);
      const t1 = (hh + S1 + ch + KB_SHA256_K[i] + w[i]) >>> 0;
      const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      hh = g; g = f; f = e; e = (d + t1) >>> 0;
      d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    h[0] = (h[0] + a) >>> 0; h[1] = (h[1] + b) >>> 0; h[2] = (h[2] + c) >>> 0; h[3] = (h[3] + d) >>> 0;
    h[4] = (h[4] + e) >>> 0; h[5] = (h[5] + f) >>> 0; h[6] = (h[6] + g) >>> 0; h[7] = (h[7] + hh) >>> 0;
  }

  const out = new Uint8Array(32);
  const odv = new DataView(out.buffer);
  for (let i = 0; i < 8; i++) odv.setUint32(i * 4, h[i], false);
  return out;
}

export function kbHmacSha256(key, msg) {
  let k = key instanceof Uint8Array ? key : new Uint8Array(key);
  const m = msg instanceof Uint8Array ? msg : new Uint8Array(msg);
  if (k.length > 64) k = kbSha256(k);
  const ipad = new Uint8Array(64 + m.length);
  const opad = new Uint8Array(64 + 32);
  for (let i = 0; i < 64; i++) {
    const kb = i < k.length ? k[i] : 0;
    ipad[i] = kb ^ 0x36;
    opad[i] = kb ^ 0x5c;
  }
  ipad.set(m, 64);
  opad.set(kbSha256(ipad), 64);
  return kbSha256(opad);
}

/* ------------------------------------------------------------------ */
/* HKDF-SHA256 (RFC 5869) — the paper's KDF                            */
/* ------------------------------------------------------------------ */

export function kbHkdfExtract(salt, ikm) {
  const s = salt && salt.length ? salt : new Uint8Array(32);
  return kbHmacSha256(s, ikm);
}

export function kbHkdfExpand(prk, info, length) {
  const out = new Uint8Array(length);
  let t = new Uint8Array(0);
  let at = 0;
  let counter = 1;
  while (at < length) {
    t = kbHmacSha256(prk, kbConcat(t, info, new Uint8Array([counter & 0xff])));
    const take = Math.min(t.length, length - at);
    out.set(t.subarray(0, take), at);
    at += take;
    counter++;
  }
  return out;
}

export function kbHkdf(ikm, salt, info, length = KB_KEY_BYTES) {
  return kbHkdfExpand(kbHkdfExtract(salt, ikm), info, length);
}

/* ------------------------------------------------------------------ */
/* PBKDF2-HMAC-SHA256 (RFC 8018) — optional passphrase hardening       */
/* ------------------------------------------------------------------ */

export function kbPbkdf2Sha256Js(passphrase, salt, iterations, dkLen = KB_KEY_BYTES) {
  const blocks = Math.ceil(dkLen / 32);
  const out = new Uint8Array(blocks * 32);
  const pw = passphrase instanceof Uint8Array ? passphrase : kbUtf8(passphrase);
  for (let b = 1; b <= blocks; b++) {
    const counter = new Uint8Array(4);
    new DataView(counter.buffer).setUint32(0, b, false);
    let u = kbHmacSha256(pw, kbConcat(salt, counter));
    const acc = u.slice();
    for (let i = 1; i < iterations; i++) {
      u = kbHmacSha256(pw, u);
      for (let j = 0; j < 32; j++) acc[j] ^= u[j];
    }
    out.set(acc, (b - 1) * 32);
  }
  return out.subarray(0, dkLen);
}

export async function kbPbkdf2Sha256(passphrase, salt, iterations, dkLen = KB_KEY_BYTES) {
  const subtle = globalThis.crypto && globalThis.crypto.subtle;
  if (subtle) {
    try {
      const key = await subtle.importKey(
        'raw',
        passphrase instanceof Uint8Array ? passphrase : kbUtf8(passphrase),
        'PBKDF2',
        false,
        ['deriveBits']
      );
      const bits = await subtle.deriveBits(
        { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
        key,
        dkLen * 8
      );
      return new Uint8Array(bits);
    } catch (e) {
      /* fall through to the portable path */
    }
  }
  return kbPbkdf2Sha256Js(passphrase, salt, iterations, dkLen);
}

/* ------------------------------------------------------------------ */
/* ChaCha20 (RFC 8439 §2.3)                                            */
/* ------------------------------------------------------------------ */

function kbRotl32(v, c) {
  return ((v << c) | (v >>> (32 - c))) >>> 0;
}

function kbQuarterRound(s, a, b, c, d) {
  s[a] = (s[a] + s[b]) >>> 0; s[d] = kbRotl32(s[d] ^ s[a], 16);
  s[c] = (s[c] + s[d]) >>> 0; s[b] = kbRotl32(s[b] ^ s[c], 12);
  s[a] = (s[a] + s[b]) >>> 0; s[d] = kbRotl32(s[d] ^ s[a], 8);
  s[c] = (s[c] + s[d]) >>> 0; s[b] = kbRotl32(s[b] ^ s[c], 7);
}

export function kbBytesToU32LE(bytes, offset, count) {
  const out = new Uint32Array(count);
  for (let i = 0; i < count; i++) {
    const o = offset + i * 4;
    out[i] = (bytes[o] | (bytes[o + 1] << 8) | (bytes[o + 2] << 16) | (bytes[o + 3] << 24)) >>> 0;
  }
  return out;
}

/** One 64-byte ChaCha20 keystream block. */
export function kbChaCha20Block(keyWords, nonceWords, counter) {
  const st = new Uint32Array(16);
  st[0] = 0x61707865; st[1] = 0x3320646e; st[2] = 0x79622d32; st[3] = 0x6b206574;
  st.set(keyWords, 4);
  st[12] = counter >>> 0;
  st.set(nonceWords, 13);
  const w = st.slice();
  for (let i = 0; i < 10; i++) {
    kbQuarterRound(w, 0, 4, 8, 12);
    kbQuarterRound(w, 1, 5, 9, 13);
    kbQuarterRound(w, 2, 6, 10, 14);
    kbQuarterRound(w, 3, 7, 11, 15);
    kbQuarterRound(w, 0, 5, 10, 15);
    kbQuarterRound(w, 1, 6, 11, 12);
    kbQuarterRound(w, 2, 7, 8, 13);
    kbQuarterRound(w, 3, 4, 9, 14);
  }
  const out = new Uint8Array(64);
  const dv = new DataView(out.buffer);
  for (let i = 0; i < 16; i++) dv.setUint32(i * 4, (w[i] + st[i]) >>> 0, true);
  return out;
}

/** XOR `data` with the ChaCha20 keystream starting at `counter`. */
export function kbChaCha20Xor(keyBytes, nonceBytes, counter, data) {
  const keyWords = kbBytesToU32LE(keyBytes, 0, 8);
  const nonceWords = kbBytesToU32LE(nonceBytes, 0, 3);
  const out = new Uint8Array(data.length);
  let at = 0;
  let ctr = counter;
  while (at < data.length) {
    const block = kbChaCha20Block(keyWords, nonceWords, ctr);
    const take = Math.min(64, data.length - at);
    for (let i = 0; i < take; i++) out[at + i] = data[at + i] ^ block[i];
    at += take;
    ctr = (ctr + 1) >>> 0;
  }
  return out;
}

/* ------------------------------------------------------------------ */
/* Poly1305 (RFC 8439 §2.5) — BigInt reference implementation          */
/* ------------------------------------------------------------------ */

const KB_POLY_P = (1n << 130n) - 5n;
const KB_POLY_R_MASK = 0x0ffffffc0ffffffc0ffffffc0fffffffn;
const KB_POLY_128 = (1n << 128n) - 1n;

function kbBytesToBigIntLE(bytes) {
  let out = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) out = (out << 8n) | BigInt(bytes[i]);
  return out;
}

function kbBigIntToBytesLE(value, length) {
  const out = new Uint8Array(length);
  let v = value;
  for (let i = 0; i < length; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

export function kbPoly1305(msg, key32) {
  const r = kbBytesToBigIntLE(key32.subarray(0, 16)) & KB_POLY_R_MASK;
  const s = kbBytesToBigIntLE(key32.subarray(16, 32));
  let acc = 0n;
  for (let i = 0; i < msg.length; i += 16) {
    const chunk = msg.subarray(i, Math.min(i + 16, msg.length));
    const n = kbBytesToBigIntLE(chunk) + (1n << BigInt(8 * chunk.length));
    acc = ((acc + n) * r) % KB_POLY_P;
  }
  return kbBigIntToBytesLE((acc + s) & KB_POLY_128, 16);
}

/* ------------------------------------------------------------------ */
/* ChaCha20-Poly1305 AEAD (RFC 8439 §2.8)                              */
/* ------------------------------------------------------------------ */

function kbPoly1305Tag(oneTimeKey, aad, ct) {
  const macData = kbConcat(
    aad,
    kbPad16(aad),
    ct,
    kbPad16(ct),
    kbU64LE(aad.length),
    kbU64LE(ct.length)
  );
  return kbPoly1305(macData, oneTimeKey);
}

/** Returns ciphertext || tag. */
export function kbAeadSeal(key, nonce, plaintext, aad) {
  const a = aad || new Uint8Array(0);
  const oneTimeKey = kbChaCha20Block(kbBytesToU32LE(key, 0, 8), kbBytesToU32LE(nonce, 0, 3), 0).subarray(0, 32);
  const ct = kbChaCha20Xor(key, nonce, 1, plaintext);
  const tag = kbPoly1305Tag(oneTimeKey, a, ct);
  return { ct, tag };
}

/** Throws KBError(AUTH_FAILED) when the tag does not verify. */
export function kbAeadOpen(key, nonce, ct, tag, aad) {
  const a = aad || new Uint8Array(0);
  const oneTimeKey = kbChaCha20Block(kbBytesToU32LE(key, 0, 8), kbBytesToU32LE(nonce, 0, 3), 0).subarray(0, 32);
  const expected = kbPoly1305Tag(oneTimeKey, a, ct);
  if (!kbEqualCT(expected, tag)) {
    throw new KBError(KB_ERR.AUTH_FAILED, 'Authentication failed — wrong passphrase, wrong context label, or tampered ciphertext.');
  }
  return kbChaCha20Xor(key, nonce, 1, ct);
}

/* ------------------------------------------------------------------ */
/* Key derivation — ties the KDF choice to the envelope's `alg` field   */
/* ------------------------------------------------------------------ */

export function kbKdfInfo(aadString) {
  return kbUtf8(`KryptBoard v1|${KB_ALGORITHM}|aad=${aadString || ''}`);
}

/**
 * The `alg` field is self-describing: it carries both the AEAD and, when the
 * passphrase-hardening KDF is used, its work factor, e.g.
 * "CHACHA20-POLY1305+PBKDF2-200000". That keeps the envelope 5 fields wide
 * while letting the receiver derive the exact same key.
 */
export function kbAlgorithmFor({ hardened, iterations }) {
  if (!hardened) return KB_ALGORITHM;
  return `${KB_ALGORITHM_HARDENED}-${kbClampIterations(iterations)}`;
}

export function kbClampIterations(iterations) {
  const n = Number.parseInt(iterations, 10);
  if (!Number.isFinite(n)) return KB_PBKDF2_ITERATIONS;
  return Math.min(KB_PBKDF2_MAX_ITERATIONS, Math.max(KB_PBKDF2_MIN_ITERATIONS, n));
}

export function kbIsHardenedAlgorithm(alg) {
  return typeof alg === 'string' && alg.startsWith(`${KB_ALGORITHM_HARDENED}-`);
}

export function kbIsSessionKeyAlgorithm(alg) {
  return alg === KB_ALGORITHM_SESSION;
}

/** Returns the work factor encoded in an `alg` string (0 when not hardened). */
export function kbIterationsFromAlg(alg) {
  if (!kbIsHardenedAlgorithm(alg)) return 0;
  const parsed = Number.parseInt(alg.slice(`${KB_ALGORITHM_HARDENED}-`.length), 10);
  if (!Number.isFinite(parsed) || parsed < KB_PBKDF2_MIN_ITERATIONS || parsed > KB_PBKDF2_MAX_ITERATIONS) {
    throw new KBError(KB_ERR.UNSUPPORTED_ALG, `Refusing PBKDF2 iteration count in "${alg}".`);
  }
  return parsed;
}

/** Human-readable summary of a parsed envelope, for UI readouts. */
export function kbDescribeEnvelope(env) {
  // Envelopes are pure ASCII, so string length is the byte count.
  const envelope = kbFormatEnvelope(env);
  return {
    algorithm: env.alg,
    hardened: kbIsHardenedAlgorithm(env.alg),
    iterations: kbIterationsFromAlg(env.alg),
    plaintextBytes: env.ct.length,
    envelopeBytes: envelope.length
  };
}

/**
 * Derives the 32-byte message key from a passphrase.
 * salt = nonce; info = KDF context string (see header comment).
 */
export async function kbDeriveKey(passphrase, salt, aadString, options = {}) {
  if (passphrase === undefined || passphrase === null || String(passphrase).length === 0) {
    throw new KBError(KB_ERR.NO_PASSPHRASE, 'A passphrase is required.');
  }
  const hardened = options.hardened === true || kbIsHardenedAlgorithm(options.alg);
  const info = kbKdfInfo(aadString);
  if (hardened) {
    const iterations = kbClampIterations(options.iterations ?? KB_PBKDF2_ITERATIONS);
    const ikm = await kbPbkdf2Sha256(passphrase, salt, iterations, KB_KEY_BYTES);
    return kbHkdf(ikm, salt, info, KB_KEY_BYTES);
  }
  return kbHkdf(passphrase instanceof Uint8Array ? passphrase : kbUtf8(passphrase), salt, info, KB_KEY_BYTES);
}

/* ------------------------------------------------------------------ */
/* Envelope — identical wire format to Envelope.kt                     */
/* ------------------------------------------------------------------ */

/** envelope = "v1|ALG|<nonce>|<ct>|<tag>" */
export function kbFormatEnvelope({ version = KB_ENVELOPE_VERSION, alg, nonce, ct, tag }) {
  return [
    `v${version}`,
    alg,
    kbB64UrlEncode(nonce),
    kbB64UrlEncode(ct),
    kbB64UrlEncode(tag)
  ].join('|');
}

export function kbParseEnvelope(str) {
  const s = String(str).trim();
  const parts = s.split('|');
  if (parts.length !== 5 || !/^v\d+$/.test(parts[0])) {
    throw new KBError(KB_ERR.BAD_ENVELOPE, 'Not a KryptBoard envelope (expected 5 fields: v1|alg|nonce|ct|tag).');
  }
  const version = Number.parseInt(parts[0].slice(1), 10);
  if (version !== KB_ENVELOPE_VERSION) {
    throw new KBError(KB_ERR.UNSUPPORTED_VERSION, `Unsupported envelope version v${version}.`);
  }
  const alg = parts[1];
  if (alg !== KB_ALGORITHM && !kbIsHardenedAlgorithm(alg) && !kbIsSessionKeyAlgorithm(alg)) {
    throw new KBError(KB_ERR.UNSUPPORTED_ALG, `Unsupported algorithm "${alg}".`);
  }
  const iterations = kbIterationsFromAlg(alg); // throws when out of range
  // Reject over-long payloads *before* allocating the decode buffers.
  const maxEncoded = Math.ceil(KB_MAX_PAYLOAD_BYTES * 4 / 3) + 8;
  if (parts[3].length > maxEncoded) {
    throw new KBError(KB_ERR.BAD_ENVELOPE, 'Envelope payload exceeds the 1 MiB safety limit.');
  }
  const nonce = kbB64UrlDecode(parts[2], 'nonce');
  const ct = kbB64UrlDecode(parts[3], 'ciphertext');
  const tag = kbB64UrlDecode(parts[4], 'tag');
  if (nonce.length !== KB_NONCE_BYTES) {
    throw new KBError(KB_ERR.BAD_ENVELOPE, `Nonce must be ${KB_NONCE_BYTES} bytes (got ${nonce.length}).`);
  }
  if (tag.length !== KB_TAG_BYTES) {
    throw new KBError(KB_ERR.BAD_ENVELOPE, `Tag must be ${KB_TAG_BYTES} bytes (got ${tag.length}).`);
  }
  if (ct.length > KB_MAX_PAYLOAD_BYTES) {
    throw new KBError(KB_ERR.BAD_ENVELOPE, 'Envelope payload exceeds the 1 MiB safety limit.');
  }
  return { version, alg, iterations, nonce, ct, tag };
}

export function kbLooksLikeEnvelope(str) {
  try {
    kbParseEnvelope(str);
    return true;
  } catch (e) {
    return false;
  }
}

/* ------------------------------------------------------------------ */
/* Algorithm 1 / Algorithm 2 — raw-key AEAD, base64 component dictionary */
/* ------------------------------------------------------------------ */

/**
 * Paper Algorithm 1, verbatim in shape:
 *
 *   nonce       <- 12 random bytes
 *   ciphertext,
 *   tag         <- ChaCha20-Poly1305(key_bytes, nonce).encrypt_and_digest(msg)
 *   result      <- { "nonce": b64, "ciphertext": b64, "tag": b64 }
 *
 * @param {string} plaintext
 * @param {Uint8Array|string} key 32 raw bytes, or their base64 / `kbk1.` form
 * @param {{aad?: string, nonce?: Uint8Array, scratch?: Uint8Array}} [options]
 * @returns {{nonce: string, ciphertext: string, tag: string}}
 */
export function kbEncryptToDict(plaintext, key, options = {}) {
  const keyBytes = kbNormalizeKeyBytes(key);
  try {
    const nonce = options.nonce ? options.nonce.slice() : kbRandomBytes(KB_NONCE_BYTES);
    if (nonce.length !== KB_NONCE_BYTES) {
      throw new KBError(KB_ERR.BAD_ENVELOPE, `Nonce must be ${KB_NONCE_BYTES} bytes.`);
    }
    return kbWithPlaintextBytes(plaintext, options, (body) => {
      const { ct, tag } = kbAeadSeal(keyBytes, nonce, body, kbUtf8(options.aad || ''));
      return { nonce: kbB64Encode(nonce), ciphertext: kbB64Encode(ct), tag: kbB64Encode(tag) };
    });
  } finally {
    kbZeroizeBytes(keyBytes);
  }
}

/**
 * Paper Algorithm 2: decode the three base64 components, decrypt and verify.
 * A failed tag is reported with the same wording as the paper's `ValueError`.
 */
export function kbDecryptFromDict(dict, key, options = {}) {
  // Accepts the object Algorithm 1 returns, or its JSON text (what a recipient
  // pastes from a chat window).
  const parsed = kbParseDict(dict);
  const nonce = kbB64Decode(parsed.nonce, 'nonce');
  const ct = kbB64Decode(parsed.ciphertext, 'ciphertext');
  const tag = kbB64Decode(parsed.tag, 'tag');
  if (nonce.length !== KB_NONCE_BYTES) {
    throw new KBError(KB_ERR.BAD_ENVELOPE, `Nonce must be ${KB_NONCE_BYTES} bytes (got ${nonce.length}).`);
  }
  if (tag.length !== KB_TAG_BYTES) {
    throw new KBError(KB_ERR.BAD_ENVELOPE, `Tag must be ${KB_TAG_BYTES} bytes (got ${tag.length}).`);
  }
  if (ct.length > KB_MAX_PAYLOAD_BYTES) {
    throw new KBError(KB_ERR.BAD_ENVELOPE, 'Payload exceeds the 1 MiB safety limit.');
  }
  const keyBytes = kbNormalizeKeyBytes(key);
  let plainBytes = null;
  try {
    plainBytes = kbAeadOpen(keyBytes, nonce, ct, tag, kbUtf8(options.aad || ''));
  } finally {
    kbZeroizeBytes(keyBytes);
  }
  try {
    if (options.scratch && options.scratch.length >= plainBytes.length) {
      options.scratch.set(plainBytes, 0);
      return kbFromUtf8(options.scratch.subarray(0, plainBytes.length));
    }
    return kbFromUtf8(plainBytes);
  } finally {
    kbZeroizeBytes(plainBytes);
    if (options.scratch) kbZeroizeBytes(options.scratch);
  }
}

/** Recognises a JSON dictionary (or a parsed object) from Algorithm 1. */
export function kbParseDict(value) {
  let candidate = value;
  if (typeof value === 'string') {
    const text = value.trim();
    if (!text.startsWith('{')) throw new KBError(KB_ERR.BAD_ENVELOPE, 'Not a KryptBoard dictionary.');
    try {
      candidate = JSON.parse(text);
    } catch (e) {
      throw new KBError(KB_ERR.BAD_ENVELOPE, 'Malformed JSON dictionary.');
    }
  }
  if (!candidate || typeof candidate !== 'object') {
    throw new KBError(KB_ERR.BAD_ENVELOPE, 'Not a KryptBoard dictionary.');
  }
  // nonce and tag are always non-empty; an empty ciphertext is legal (an
  // empty message still authenticates its AAD).
  const required = ['nonce', 'tag'];
  if (!required.every((name) => typeof candidate[name] === 'string' && candidate[name].trim().length > 0)
    || typeof candidate.ciphertext !== 'string') {
    throw new KBError(KB_ERR.BAD_ENVELOPE, 'Expected base64 nonce, ciphertext and tag fields.');
  }
  return { nonce: candidate.nonce, ciphertext: candidate.ciphertext, tag: candidate.tag };
}

export function kbLooksLikeDict(value) {
  try {
    kbParseDict(value);
    return true;
  } catch (e) {
    return false;
  }
}

/** The dictionary form of an envelope, for recipients that expect Alg. 1 output. */
export function kbEnvelopeToDict(envelopeOrParsed) {
  const env = typeof envelopeOrParsed === 'string' ? kbParseEnvelope(envelopeOrParsed) : envelopeOrParsed;
  return { nonce: kbB64Encode(env.nonce), ciphertext: kbB64Encode(env.ct), tag: kbB64Encode(env.tag) };
}

/** Wraps Algorithm 1's output back into the KryptBoard envelope string. */
export function kbDictToEnvelope(dict, { alg = KB_ALGORITHM_SESSION } = {}) {
  const parsed = kbParseDict(dict);
  return kbFormatEnvelope({
    alg,
    nonce: kbB64Decode(parsed.nonce, 'nonce'),
    ct: kbB64Decode(parsed.ciphertext, 'ciphertext'),
    tag: kbB64Decode(parsed.tag, 'tag')
  });
}

/* ------------------------------------------------------------------ */
/* High level API                                                      */
/* ------------------------------------------------------------------ */

/**
 * Encrypts a UTF-8 string and returns the KryptBoard envelope string.
 * @param {string} plaintext
 * @param {string} passphrase
 * @param {{aad?: string, hardened?: boolean, iterations?: number, nonce?: Uint8Array, scratch?: Uint8Array}} [options]
 */
export async function kbEncrypt(plaintext, passphrase, options = {}) {
  const aadString = options.aad || '';
  const nonce = options.nonce ? options.nonce.slice() : kbRandomBytes(KB_NONCE_BYTES);
  if (nonce.length !== KB_NONCE_BYTES) {
    throw new KBError(KB_ERR.BAD_ENVELOPE, `Nonce must be ${KB_NONCE_BYTES} bytes.`);
  }
  const hardened = options.hardened === true;
  const iterations = kbClampIterations(options.iterations ?? KB_PBKDF2_ITERATIONS);
  let key = null;
  try {
    key = await kbDeriveKey(passphrase, nonce, aadString, { hardened, iterations });
    return await kbWithPlaintextBytes(plaintext, options, (body) => {
      const { ct, tag } = kbAeadSeal(key, nonce, body, kbUtf8(aadString));
      return kbFormatEnvelope({ alg: kbAlgorithmFor({ hardened, iterations }), nonce, ct, tag });
    });
  } finally {
    kbZeroizeBytes(key);
  }
}

/**
 * Session-key variant of the high level API (paper §III single-session key).
 * The envelope carries `CHACHA20-POLY1305+SESSIONKEY` so the recipient knows
 * that the same raw key — and no KDF — was used.
 */
export function kbEncryptWithKey(plaintext, key, options = {}) {
  const keyBytes = kbNormalizeKeyBytes(key);
  try {
    const nonce = options.nonce ? options.nonce.slice() : kbRandomBytes(KB_NONCE_BYTES);
    if (nonce.length !== KB_NONCE_BYTES) {
      throw new KBError(KB_ERR.BAD_ENVELOPE, `Nonce must be ${KB_NONCE_BYTES} bytes.`);
    }
    return kbWithPlaintextBytes(plaintext, options, (body) => {
      const { ct, tag } = kbAeadSeal(keyBytes, nonce, body, kbUtf8(options.aad || ''));
      return kbFormatEnvelope({ alg: KB_ALGORITHM_SESSION, nonce, ct, tag });
    });
  } finally {
    kbZeroizeBytes(keyBytes);
  }
}

export function kbDecryptWithKey(envelopeString, key, options = {}) {
  const env = kbParseEnvelope(envelopeString);
  if (!kbIsSessionKeyAlgorithm(env.alg)) {
    throw new KBError(KB_ERR.UNSUPPORTED_ALG, `Envelope uses ${env.alg}, which is not a session-key envelope.`);
  }
  const keyBytes = kbNormalizeKeyBytes(key);
  let plainBytes = null;
  try {
    plainBytes = kbAeadOpen(keyBytes, env.nonce, env.ct, env.tag, kbUtf8(options.aad || ''));
  } finally {
    kbZeroizeBytes(keyBytes);
  }
  try {
    return kbFromUtf8(plainBytes);
  } finally {
    kbZeroizeBytes(plainBytes);
  }
}

/**
 * Decrypts a KryptBoard envelope back to a UTF-8 string.
 * The KDF (plain HKDF or PBKDF2-hardened) is read from the envelope.
 */
export async function kbDecrypt(envelopeString, passphrase, options = {}) {
  const env = kbParseEnvelope(envelopeString);
  if (kbIsSessionKeyAlgorithm(env.alg)) {
    throw new KBError(KB_ERR.UNSUPPORTED_ALG, 'This envelope needs a session key, not a passphrase.');
  }
  const aadString = options.aad || '';
  let key = null;
  let plaintext = null;
  try {
    key = await kbDeriveKey(passphrase, env.nonce, aadString, {
      hardened: kbIsHardenedAlgorithm(env.alg),
      iterations: env.iterations || options.iterations
    });
    plaintext = kbAeadOpen(key, env.nonce, env.ct, env.tag, kbUtf8(aadString));
    return kbFromUtf8(plaintext);
  } finally {
    kbZeroizeBytes(key);
    kbZeroizeBytes(plaintext);
  }
}

