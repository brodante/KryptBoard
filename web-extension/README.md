# KryptBoard — Encrypted Keyboard for the Browser

A browser extension that reproduces the **KryptBoard / Secure IME** idea on the web: an
on-screen keyboard overlay that *buffers* keystrokes instead of handing them to the page,
seals the buffer with authenticated encryption, and commits only the resulting envelope to
the focused field.

It is the browser sibling of the Android IME in this repository (`app-ime/` + `crypto-lib/`)
and speaks the **same wire format**, so a message sealed in the browser can be opened on the
phone and vice versa:

```
KryptBoard v1 envelope
v1|CHACHA20-POLY1305|<nonce>|<ciphertext>|<tag>          (all base64url, unpadded)
v1|CHACHA20-POLY1305+PBKDF2-200000|<nonce>|<ct>|<tag>    (passphrase-hardened variant)
```

> **Note on the paper.** The published paper is not part of this checkout, so the design here
> was derived from the Android implementation it describes: the buffered plaintext, the
> `v1|alg|nonce|ct|tag` envelope, ChaCha20-Poly1305, and a locally-held passphrase.
> **[Section "Matching the paper exactly"](#matching-the-paper-exactly)** lists every constant
> and function to adjust if the paper pins different parameters — all of them live in one file.

---

## Contents

- [Install it](#install-it)
- [What it does](#what-it-does)
- [How the crypto works](#how-the-crypto-works)
- [Threat model](#threat-model)
- [Limitations](#limitations)
- [Architecture](#architecture)
- [Interoperating with the Android app](#interoperating-with-the-android-app)
- [Matching the paper exactly](#matching-the-paper-exactly)
- [Tests](#tests)
- [Try it without installing](#try-it-without-installing)

---

## Install it

No build step is required to load it — `bundle/content.js` is committed and current.

1. Open `chrome://extensions` (or `edge://extensions`, `brave://extensions`).
2. Turn on **Developer mode**.
3. **Load unpacked** → select this folder (`web-extension/`).
4. Open any normal website (not a `chrome://` page), focus a text box, and press
   **Ctrl+Shift+K** — or click the extension icon and press *Open keyboard*.

After editing any file under `src/`, rebuild the content bundle:

```bash
npm run build      # bundles src/*.js → bundle/content.js
npm test           # crypto vectors, DOM integration tests, packaging checks
npm run build -- --zip   # also produce kryptboard-<version>.zip for the Web Store
```

Node 18+ is required for the tooling only. The shipped extension has **zero runtime
dependencies**.

## What it does

| | Android IME (`app-ime`) | This extension |
|---|---|---|
| Plain mode | keys commit straight to the target app | keys commit straight to the focused field |
| Encrypted mode | keystrokes buffer in the keyboard, unreadable by the app | keystrokes buffer in the overlay, unreadable by the page |
| Commit | `commitText(envelope)` via `InputConnection` | native value setter + `InputEvent` (or `execCommand('insertText')`) |
| Target tracking | system gives the IME the target | `focusin` tracking, password fields excluded |
| Cipher | ChaCha20-Poly1305 (stub in the current Kotlin tree) | RFC 8439 ChaCha20-Poly1305, real AEAD |
| Key material | local, no network | local, in `chrome.storage.session` at most — never on disk |
| Network | none | none (the manifest has no host permissions at all) |

Concretely, the extension gives you:

- **An overlay keyboard** with letters/symbols layers, one-shot and locked shift, space,
  backspace and enter, dark/light/auto themes, and a live character/byte counter.
- **Two modes**, switchable at any time, with an always-visible badge for the active one.
- **Envelope awareness**: paste an envelope into the buffer and a *Decrypt* action appears;
  a tag failure is reported instead of silently returning garbage.
- **A popup** with connection status for the current tab, a standalone encrypt/decrypt
  console, and all settings.
- **Interop affordances**: *Copy* takes the sealed envelope to any other channel, and the
  popup can open an envelope that the Android keyboard produced.

## How the crypto works

Both sides derive the same key from a shared passphrase and the per-message nonce:

```
salt = nonce (12 bytes, fresh per message)
info = "KryptBoard v1|CHACHA20-POLY1305|aad=<context label>"
key  = HKDF-SHA256(passphrase, salt, info, 32)

ct, tag = ChaCha20-Poly1305(key, nonce, plaintext, aad = context label)
```

- **AEAD.** ChaCha20-Poly1305 exactly as specified in RFC 8439 (§2.6 one-time key, §2.8 MAC
  over `aad ‖ pad ‖ ct ‖ pad ‖ len(aad) ‖ len(ct)`). Implemented in portable JavaScript in
  `src/crypto.js` — no WebCrypto dependency, so behaviour is identical in every browser and
  testable in Node.
- **KDF.** HKDF-SHA256 with the nonce as salt and the string above as `info`. Supported by
  HMAC-SHA256 and SHA-256 implementations validated against RFC 4231 / FIPS 180-4 vectors.
- **Passphrase hardening (optional).** When enabled, the passphrase first goes through
  PBKDF2-HMAC-SHA256 (default 200 000 iterations, configurable up to 5 000 000) and the
  result is fed into HKDF. The **work factor is recorded in the envelope's `alg` field**
  (`CHACHA20-POLY1305+PBKDF2-200000`) so the receiver derives the identical key. Values
  outside 1 000 … 5 000 000 are refused on parse, which stops a hostile paste from pinning
  the CPU.
- **Context label (AAD).** Optional and *not* transmitted: both sides must know it, which is
  what makes it useful as a channel binding (e.g. `room-42`). A mismatch fails the tag.
- **Nonces.** 12 random bytes from `crypto.getRandomValues` per message; the AEAD key is
  re-derived from that nonce, so repeated plaintext yields unrelated ciphertexts.
- **Wiped state.** The buffer is cleared as soon as it has been sealed; nothing is written to
  disk, and the passphrase never leaves the extension's own storage (see below).

## Threat model

**Who is the adversary.** The page you are typing into, and any script running inside it.
The scenario mirrors the Android app's: the application that receives the text must not
learn the plaintext, the page must not observe your keystrokes, and nothing may leave the
machine.

**What the extension protects**

| Property | How |
|---|---|
| The page never receives plaintext in encrypted mode | Only the sealed envelope is committed to the field; keystrokes go to the overlay buffer. |
| The page cannot read the buffer | The overlay lives in a **closed** shadow root; `host.shadowRoot` is `null` and the internals are unreachable from page scripts. A test asserts the closed mode. |
| The page never sees the passphrase | It lives in the content script's closure, or in `chrome.storage.session` when *remember* is ticked — extension-only storage the page cannot address. Nothing touches `localStorage`. |
| Credentials are not hoovered up | Password fields are excluded as commit targets by default (`ignorePasswordFields`); a test drives a password field and asserts it stays empty. |
| Ciphertext cannot be forged or silently altered | ChaCha20-Poly1305 tags; a tampered envelope raises an authentication error rather than returning garbage. |
| Nothing is transmitted | The manifest requests only `storage`, declares no host permissions, and the source contains no `fetch`, `XMLHttpRequest`, `WebSocket`, `EventSource`, `sendBeacon` or `eval` — enforced by tests that read the shipped sources. The popup shows a “0 network calls” badge. |
| Keystrokes are not replayable across contexts | The optional context label is mixed into both the KDF `info` and the AEAD associated data. |

**Two operating modes, two levels of isolation**

1. **In-page overlay** (default). Convenient: it works in any field on any site. The
   plaintext is typed into the page's own document tree, inside a closed shadow root, so page
   scripts cannot read it — but the page still shares a process with the overlay, and it can
   observe that key events were delivered to the overlay's host element *if you type on your
   physical keyboard while the buffer has focus*. Prefer clicking the on-screen keys, or use
   the second mode, when the page is hostile.
2. **Isolated composer** (the popup's *Try the crypto* panel). The message is typed in an
   extension page (`chrome-extension://…`), where page scripts genuinely cannot observe any
   event, and the sealed envelope is copied to your clipboard for pasting. This is the
   browser equivalent of the Android IME's process separation, and it is the mode to use for
   the strongest claim.

## Limitations

Being honest about where the guarantee stops matters more than the feature list:

- **The overlay cannot hide the *existence* of input from the page.** Synthetic clicks and
  focus changes are observable by design — only the buffer's *contents* are hidden. Use the
  isolated composer when even that matters.
- **A hostile page can read what you commit.** Anything that reaches the field is the page's.
  This is the same trust boundary as the Android IME: encryption protects the channel, not
  the recipient.
- **The passphrase is shared out of band.** There is no key agreement, no forward secrecy and
  no per-contact identity in this version: it is a symmetric AEAD with a pre-shared secret,
  matching the Android implementation. If the paper specifies X3DH/Signal-style ratcheting,
  that is a different (larger) design — see the note above.
- **A weak passphrase is weak.** HKDF is not a password-stretching function; enable PBKDF2
  hardening for anything human-chosen. The default remains plain HKDF so the browser and the
  Android `crypto-lib` stay byte-compatible.
- **No keystroke-level protection for password fields.** The extension deliberately refuses to
  target them rather than offering to encrypt credentials.
- **Clipboard is a shared surface.** *Copy* is the interop path, and on a compromised machine
  the clipboard is readable by other software.
- **Not audited.** The crypto primitives are validated against published vectors, but no
  external review or side-channel analysis has been performed, and the JavaScript
  implementation is not constant-time at the level a native library would be.
- **`file://` pages need the browser's permission** to be extended at all; on `chrome://`,
  Web Store and other privileged pages the extension simply cannot run (the popup says so).

## Architecture

```
web-extension/
├── manifest.json               MV3, permissions: ["storage"], no host permissions
├── bundle/content.js           generated: settings + crypto + keyboard + wiring + content
├── src/
│   ├── crypto.js               ChaCha20-Poly1305, HKDF, PBKDF2, base64url, envelope
│   ├── settings.js             settings store, hotkey parsing, passphrase vault
│   ├── keyboard.js             the overlay component + target editing primitives
│   ├── keyboard.css            shadow-scoped styles, dark/light/auto themes
│   ├── wiring.js               page integration: hotkey, focus tracking, target rules
│   ├── content.js              chrome.storage + message API glue
│   ├── popup.html/.css/.js     status, isolated composer, all settings
├── demo/demo.html              live demo of the real modules (see below)
├── tests/crypto.test.mjs       RFC vectors + golden interop vectors
├── tests/dom.test.mjs          the built bundle driven inside a simulated page
├── tests/static.test.mjs       packaging, permissions, no-network, markup/script checks
└── scripts/bundler.mjs         ~120-line ES-module bundler (content scripts can't be modules)
```

Data flow, encrypted mode:

```
on-screen key ──▶ overlay buffer (closed shadow root)
                      │  Encrypt & Send
                      ▼
      HKDF ─▶ ChaCha20-Poly1305 seal ─▶ "v1|CHACHA20-POLY1305|…"
                      │
                      ▼
        native value setter + InputEvent ──▶ page field
                      │
                      ▼
              buffer wiped, envelope logged
```

## Interoperating with the Android app

The envelope is the contract. A round trip looks like this:

```kotlin
// Kotlin side (crypto-lib): open what the browser produced
val cipher = ChaCha20Poly1305Stub()          // replace with a real RFC 8439 AEAD
val parsed = Envelope.parse(envelopeFromBrowser)   // "v1|CHACHA20-POLY1305|nonce|ct|tag"
val plaintext = cipher.decrypt(parsed, aad = "".toByteArray())
```

```js
// Browser side: open what the phone produced
import { kbDecrypt } from './src/crypto.js';
const plaintext = await kbDecrypt(envelopeFromPhone, passphrase, { aad: '' });
```

Both sides must agree on: the envelope layout, the KDF (`info` string and salt), the AEAD, and
the context label. The repository's test suite pins the browser's half with golden vectors
(`tests/crypto.test.mjs`) whose derived keys were recomputed independently with Python's
`hashlib`/`hmac` — so the Kotlin implementation can be checked against those same vectors.

## Matching the paper exactly

Everything the paper could pin down lives in two places, both small:

| Parameter | Where | Current value |
|---|---|---|
| Envelope layout | `kbFormatEnvelope` / `kbParseEnvelope` in `src/crypto.js` | `v1\|alg\|nonce\|ct\|tag`, base64url |
| AEAD | `kbAeadSeal` / `kbAeadOpen` | ChaCha20-Poly1305, RFC 8439 |
| KDF | `kbDeriveKey`, `kbKdfInfo` | HKDF-SHA256, salt = nonce, documented `info` string |
| Hardening | `KB_PBKDF2_ITERATIONS`, `kbAlgorithmFor` | PBKDF2-HMAC-SHA256, 200 000, recorded in `alg` |
| Nonce size | `KB_NONCE_BYTES` | 12 |
| Tag size | `KB_TAG_BYTES` | 16 |
| Context binding | `aad` setting / `AAD` parameter | off by default |
| Mode semantics | `src/keyboard.js` (`applyMode`, `handleSend`) | buffered vs. direct commit |

If the paper's construction differs (for example a different `info` string, an X25519 exchange
instead of a shared passphrase, or a different envelope separator), change it in
`src/crypto.js` only — the UI, the tests and the DOM layer all consume that module, and
`tests/crypto.test.mjs` will tell you exactly which vectors moved.

## Tests

```bash
npm test              # all three suites (jsdom is a devDependency)
npm run test:crypto   # 26 tests: primitives + envelope + interop vectors
npm run test:dom      # 16 tests: the built bundle inside a simulated page
npm run build -- --check   # fail if bundle/content.js is stale
```

What is actually verified, not merely claimed:

- **Primitives against their standards** — ChaCha20 block function, ChaCha20 encryption,
  Poly1305 and the full ChaCha20-Poly1305 AEAD against RFC 8439's published vectors; HKDF
  against RFC 5869 A.1–A.3; HMAC against RFC 4231; SHA-256 against FIPS 180-4; PBKDF2 against
  RFC 7914 §11.
- **The KDF chain against a second implementation** — the derived keys for a fixed nonce,
  passphrase and context label were recomputed with Python's `hashlib`/`hmac` and are pinned
  as golden vectors.
- **Behaviour through the shipped artefact** — the DOM suite bundles `src/`, evaluates it in
  jsdom with a stubbed `chrome` API, presses the hotkey, clicks keys and asserts: the page
  field receives only `v1|CHACHA20-POLY1305|…`, the buffer is wiped after sealing, an envelope
  pasted into the buffer decrypts, a tampered one fails, password fields stay empty, the
  shadow root is closed, settings propagate live, and no network API is ever called.
- **Packaging** — manifest version matches `package.json`, every referenced file exists, icons
  are real PNGs of the declared size, no remote assets, no `eval`, and every settings control
  the popup touches exists in its markup.

## Try it without installing

`demo/demo.html` loads the **real** `src/keyboard.js`, `src/wiring.js` and `src/crypto.js`
over a normal HTTP origin (the extension ships them as a content script instead), so you can
exercise the overlay, watch what the page receives in its event log, and decrypt envelopes
round-trip. Serve the folder and open the page:

```bash
python3 -m http.server 8787        # then open http://localhost:8787/demo/demo.html
```

## License

Same as the parent project: educational/demonstration purposes.
