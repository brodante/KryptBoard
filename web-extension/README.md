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
v1|CHACHA20-POLY1305|<nonce>|<ciphertext>|<tag>             (all base64url, unpadded)
v1|CHACHA20-POLY1305+PBKDF2-200000|<nonce>|<ct>|<tag>       (passphrase-hardened variant)
v1|CHACHA20-POLY1305+SESSIONKEY|<nonce>|<ct>|<tag>          (session-key variant)

Paper Algorithm 1 dictionary (the session-key model)
{"nonce":"…","ciphertext":"…","tag":"…"}                    (standard base64, padded)
```

The paper's construction — the single-session key, Algorithm 1's `{nonce, ciphertext, tag}`
dictionary and Algorithm 2's verify-then-decrypt — is implemented in full; the passphrase
model is kept alongside it because it is what the Android app shares.
**[Section "Matching the paper exactly"](#matching-the-paper-exactly)** maps every
requirement of the paper to the file that implements it, including the two deliberate
deviations.

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
- [The paper's session-key model](#the-papers-session-key-model)
- [Buffer lifecycle and zeroization](#buffer-lifecycle-and-zeroization)
- [Performance](#performance)
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

There are two key models. Both use the same AEAD and the same 12-byte random nonce; they
differ only in where the 32-byte key comes from.

**Passphrase model (default, interoperable with the Android app):** both sides derive the
same key from a shared passphrase and the per-message nonce:

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

**Session-key model (the paper's Algorithm 1):** a 32-byte key generated locally by the
extension is used directly, with no KDF at all, and the message is emitted either as the
paper's base64 dictionary or as the `+SESSIONKEY` envelope. See
[The paper's session-key model](#the-papers-session-key-model) for how the key is created,
shared, fingerprinted and wiped.

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

**Residual risks the paper lists, and where we stand**

| Paper's caveat | This implementation |
|---|---|
| A fully compromised browser or OS can intercept keystrokes before the extension sees them | Out of scope, as in the paper. Pre-send encryption defends against page-level and extension-level threats, not a hostile kernel or a compromised browser binary. |
| A malicious extension installed *before* KryptBoard could capture input | Same scope limit. Note the asymmetry: with Encrypt mode the only thing a page-reading extension receives is ciphertext, but it can still read the *overlay's* on-screen key labels and timing. |
| The user may forget to switch to Encrypt mode | Mitigated, not solved: the mode is shown in the toolbar switch, in the overlay's header chip and in its colour, and `Encrypt mode` is the default (`startMode`). |
| Traffic analysis — timing and message length stay visible | True here too. The envelope's length reveals the plaintext's length (base64 expansion ≈ 1.37×) and typing rhythm is unchanged. Padding is future work. |

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
├── tests/                      ten suites, 140 tests — see “Tests” below
├── scripts/bundler.mjs         ~120-line ES-module bundler (content scripts can't be modules)
└── scripts/build.mjs           bundle → manifest check → optional .zip
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

The paper (*Secure Your Words Before You Send: The KryptBoard Pre-Send Encryption
Method*, §III and Algorithms 1–2) specifies the method; this is where each piece of it
lives and how faithful the implementation is.

| Paper requirement | Where it lives | Status |
|---|---|---|
| Two modes, Plain and Encrypt, toggled from a persistent browser-toolbar UI | `src/popup.html` / `popup.js` — the *Plain mode* / *Encrypt mode* switch that drives the live overlay over the message API (`kryptboard:set-mode`); mode chips inside the overlay keep it visible while typing | ✅ implemented — the switch reflects the page's current mode, changes it live, and stores it as the default for the next page |
| Keystrokes held in an isolated buffer, encrypted as one message on demand | `src/keyboard.js` — encrypted mode buffers; `Encrypt & Send` seals | ✅ implemented |
| **Algorithm 1** — 12-byte random nonce, `ChaCha20-Poly1305(key_bytes, nonce).encrypt_and_digest(msg)`, result `{nonce, ciphertext, tag}` base64-encoded | `kbEncryptToDict` in `src/crypto.js` | ✅ implemented byte-for-byte: standard base64 **with** padding, exactly the fields the paper names |
| **Algorithm 2** — decode the three base64 components, `decrypt_and_verify`, fail on a bad tag | `kbDecryptFromDict` | ✅ implemented; a failed tag raises `AUTH_FAILED` (the paper's `ValueError`) |
| Ciphertext injected into the web app's own text field, no site modifications | `commitToPage` (`kbCommitToTarget`) | ✅ implemented; works on `input`, `textarea` and `contenteditable` |
| Single-session key generated and managed locally in extension storage, no key exchange in the PoC | `kbGenerateSessionKey`, `kbCreateSessionKeyVault`, `src/content.js` (in-memory), popup *Session key* card | ✅ implemented as the `session` key model; the key can be shared out of band as a `kbk1.…` string and verified by fingerprint |
| Immediate zeroization of the plaintext buffer after encryption or on cancel | `kbZeroizeBytes` + `kbZeroizeBytes`/scratch handling in every encrypt path; buffer and textarea wiped on send, cancel and hide | ✅ implemented for every byte buffer we own — see the caveat below |
| Plaintext never visible to the page | closed shadow root + content-script closure; keystroke/input/composition/paste events stopped at the shadow boundary | ✅ implemented, with tests |
| No clipboard use for sensitive data unless the user asks | clipboard is touched only by explicit Copy/Paste buttons, and the seal-with-no-target fallback copies **ciphertext** | ✅ implemented |
| Recipient-side client to decrypt | the popup's *Decrypt* tab (standalone tool for envelopes **and** Algorithm-1 dictionaries) plus the in-page overlay | ✅ implemented |
| Performance: negligible encryption overhead, linear in message length | `npm run bench` | ✅ measured, with a caveat — see [Performance](#performance) |

Two deliberate deviations, both to keep the wire format interoperable:

1. **Envelopes stay base64url, dictionaries use standard base64.** The paper's Algorithm 1
   returns `base64.b64encode` output, and `kbEncryptToDict` matches it exactly. The
   `v1|alg|nonce|ct|tag` envelope — which the Android IME and the golden interop vectors
   use — keeps the unpadded URL-safe alphabet so a single string survives being pasted
   into a URL, a JSON field or a chat box. Both are implemented; the session model can
   emit either (`Session output` in the popup, `sessionFormat` in settings).
2. **A passphrase key model is kept alongside the paper's raw-key model.** The paper's
   proof of concept has no KDF (Algorithm 1 takes `key_bytes` directly). Deriving the key
   from a passphrase (HKDF-SHA256, optional PBKDF2 hardening) is what makes the extension
   usable without transferring a key first, and it is the model the Android app shares.
   The passphrase model remains the default; `keyModel: "session"` switches the overlay
   to the paper's construction.

## The paper's session-key model

Set **Key model → Single-session key** in the popup, press **Generate key**, and the
overlay seals with that raw key instead of a passphrase:

```
overlay buffer ──▶ kbEncryptToDict(msg, key) ──▶ {"nonce":"…","ciphertext":"…","tag":"…"}
                                                  (or v1|CHACHA20-POLY1305+SESSIONKEY|…)
```

- The key is 32 random bytes. The popup keeps it in `chrome.storage.session`
  (extension-only, cleared when the browser session ends) and hands it to the page's
  content script over the message API; the content script holds it **in memory only** —
  it is never written to `sync`/`local` storage, and the previous key is overwritten with
  zeros when it is replaced or cleared.
- **Share** it with the other side as `kbk1.<base64url>` (the popup has a *Copy sharing
  string* button). Anyone holding that string can read the messages — send it over a
  different channel.
- Both sides compare the **fingerprint** (e.g. `A1B2-C3D4-E5F6-0718`, the first 8 bytes of
  SHA-256 of the key) out of band before trusting the channel.
- To read a message that used the session key, paste it into either the in-page overlay or
  the popup's *Decrypt* tab; both detect Algorithm-1 dictionaries automatically and say so
  if no key is loaded.

## Buffer lifecycle and zeroization

The paper requires the plaintext buffer to be overwritten the moment it is not needed
(after sealing, or on cancel). What that means concretely here:

| Moment | What is wiped |
|---|---|
| `Encrypt & Send` | The overlay's buffer string and textarea are cleared, and every byte buffer involved in sealing (UTF-8 plaintext, derived key, scratch) is overwritten with zeros inside `kbEncrypt`/`kbEncryptToDict` before the call returns |
| Cancel / Hide (with *Wipe the buffer when hiding it*) | Buffer and textarea cleared; no plaintext byte buffer survives the seal path |
| Replacing or clearing a session key | The old key bytes are zeroed before the new value is stored (`kbZeroizeBytes`) |
| Browser session end | `chrome.storage.session` is dropped by the browser |

**Caveat, stated plainly:** JavaScript strings are immutable. Once the buffer has been read
into a string by the engine, that particular copy cannot be overwritten — only dropped for
the garbage collector. Every *byte buffer* this extension owns is zeroed, and callers can
pass `options.scratch` to `kbEncrypt`/`kbEncryptToDict`/`kbDecryptFromDict` to keep the
plaintext in memory they control; a test asserts the scratch is all zeros afterwards. A
byte-exact zeroization guarantee would need a WASM memory region, which is future work.

## Performance

Measured with `npm run bench` (Node 22, single core, this implementation, no hardware
acceleration). The paper's Table 4 quotes ~450 MB/s for ChaCha20-Poly1305 and Figs. 4–5
show negligible, linear overhead — those figures come from a native build; the extension
ships a **portable pure-JS** implementation (no WASM, no dependencies, identical on every
browser), so the honest numbers are these:

| message | envelope | AEAD seal | AEAD open | AEAD MB/s | passphrase seal (incl. HKDF) |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 500 B | 728 B | 0.149 ms | 0.078 ms | 3.2 | 0.191 ms |
| 1 KiB | 1 427 B | 0.137 ms | 0.120 ms | 7.1 | 0.177 ms |
| 16 KiB | 21 907 B | 1.850 ms | 1.610 ms | 8.4 | 1.869 ms |
| 64 KiB | 87 443 B | 8.100 ms | 6.423 ms | 7.7 | 8.200 ms |
| 256 KiB | 349 587 B | 28.7 ms | 27.7 ms | 8.7 | 32.5 ms |
| 1 MiB | 1 398 163 B | 193 ms | 127 ms | 5.2 | 222 ms |

- **The usability claim holds**: a 500-character message adds ~0.15 ms of sealing on top of
  a ~0.19 ms total, i.e. far below one frame. There is no per-keystroke derivation —
  encryption happens once, when the user asks for it.
- **Scaling is linear**: per-byte cost varies by 1.6× between 500 B and 1 MiB (constant
  until cache pressure appears), not quadratically. `tests/bench.test.mjs` fails if that
  ever changes class.
- **Throughput is not the paper's 450 MB/s.** The bottleneck is the portable Poly1305
  big-integer accumulator; 8 MB/s is ~40 000× faster than a person types, so it does not
  matter for this workload. Two ways to close the gap if it ever does: a 32-bit-limb
  Poly1305 (pure JS, ~10×), or `crypto.subtle` where the browser supports
  `ChaCha20-Poly1305` (Firefox and Safari do; Chrome and Node's WebCrypto do not, which is
  exactly why the portable path is the default).

## Tests

```bash
npm test                   # everything: 170 tests across eleven suites
npm run test:crypto        # 44 tests: primitives, envelope + dictionary, interop vectors, fuzzing
npm run test:dom           # 37 tests: the built bundle inside a simulated page
npm run bench              # measured throughput / overhead / scaling
npm run build -- --check   # fail if bundle/content.js is stale
```

| suite | tests | what it pins down |
| --- | ---: | --- |
| `crypto.test.mjs` | 44 | RFC 8439 / 5869 / 4231 / 7914 vectors, the golden interop envelope, Algorithm 1/2 dictionaries (shape, padding, JSON round-trip, tampering, wrong key), session keys and fingerprints, zeroization, plus fuzzing: 250 random round-trips, every single-bit corruption of nonce/ciphertext/tag rejected, 80 structural mutilations classified, no plaintext or repeated nonce in 120 envelopes |
| `dom.test.mjs` | 37 | the *built* bundle in jsdom driven like a user (hotkey → keys → Encrypt & Send), the paper's session-key sealing (dictionary and envelope output, refusal without a key, Algorithm-2 decryption of a pasted dictionary), plus the editing primitives: maxlength, selection replacement, `beforeinput` cancellation, framework events, caret handling, clipboard copy/paste, shift lock, themes |
| `settings.test.mjs` | 16 | frozen defaults, hostile input (prototype pollution, garbage types), hotkey parsing/matching, the store's load/save/reset/subscribe paths, the passphrase vault's memory-vs-remembered rules, and a change landing mid-load |
| `wiring.test.mjs` | 13 | exact hotkey matching (near-miss combos, auto-repeat, disabled), target rules (readonly, `contenteditable`, buttons, selects), password exclusion and its opt-out, focus inside the overlay, teardown |
| `content.test.mjs` | 13 | double injection, foreign/unknown messages, the popup message API (including the toolbar's mode switch), session-key hand-over and wiping, replies that wait for storage to load, and settings/passphrase pushes from other tabs |
| `popup.test.mjs` | 13 | popup boot, the isolated composer (passphrase **and** session-key models, seal, verify, wrong passphrase, AAD, work factor), session-key generate/import/copy/forget, the toolbar Plain/Encrypt switch, settings persistence, tabs, blocked pages, clipboard fallback |
| `bench.test.mjs` | 3 | performance guards: a 500-character seal stays far below a frame, per-byte cost stays linear from 1 KiB to 64 KiB |
| `bundler.test.mjs` | 9 | dependency order, per-module scope, async/class/destructuring, diamond and cyclic imports, determinism, and refusal to emit unhandled module syntax |
| `build.test.mjs` | 4 | the staleness gate, the manifest cross-check (including a deliberately broken manifest), and the exact file list inside the packaged zip |
| `static.test.mjs` | 13 | packaging, permissions, no-network, markup/script cross-checks, the `[hidden]` CSS guard |
| `demo.test.mjs` | 5 | the demo page loads the real modules and round-trips, including the paper's session-key panel: generate, fingerprint, Algorithm 1 dictionary, Algorithm 2 decryption, and the wipe on *Forget* |

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
  shadow root is closed, settings propagate live, keystrokes typed into the overlay never
  reach page listeners, and no network API is ever called.
- **The build itself** — the bundle is compared byte-for-byte with a fresh build, a tampered
  copy is proven to fail `--check`, a broken manifest is proven to be rejected, and the store
  zip is asserted to contain the runtime files and none of the development ones.
- **Packaging** — manifest version matches `package.json`, every referenced file exists, icons
  are real PNGs of the declared size, no remote assets, no `eval`, and every settings control
  the popup touches exists in its markup.

The fuzzing and concurrency tests use fixed seeds, so a failure reproduces from its iteration
number. No test needs a browser: the DOM suites run on jsdom, and every suite skips (rather
than fails) when jsdom is not installed.

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
