/**
 * Integration tests: the *built* content bundle, evaluated inside a simulated
 * web page.
 *
 * These run the shipped artefact (bundle/content.js, produced by
 * scripts/bundler.mjs) against a jsdom document and a stub chrome API, and
 * then drive it the way a user would: focus a field, hit the hotkey, click
 * keys, press Encrypt & Send. They assert the security-relevant properties —
 * ciphertext (never plaintext) reaches the page, the buffer is wiped after
 * sealing, password fields are never used as commit targets, and the shadow
 * root is closed so page scripts cannot read the buffer.
 *
 * jsdom is a devDependency; when it is not installed these tests skip rather
 * than fail, so `node --test tests/` always works on a bare checkout.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { bundleSources, readBundleHash } from '../scripts/bundler.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

let JSDOM = null;
try {
  ({ JSDOM } = await import('jsdom'));
} catch (error) {
  JSDOM = null;
}

const skip = JSDOM ? false : 'jsdom is not installed (run: npm install)';

const PAGE_HTML = `<!doctype html><html><body>
  <textarea id="msg" placeholder="message"></textarea>
  <input id="pw" type="password" />
  <div id="rich" contenteditable="true"></div>
</body></html>`;

/* ------------------------------------------------------------------ */
/* chrome API stub                                                     */
/* ------------------------------------------------------------------ */

function createChromeStub(initialSync = {}, initialSession = {}) {
  const sync = new Map(Object.entries(initialSync));
  const session = new Map(Object.entries(initialSession));
  const created = { sync, session };

  const area = (map, name) => ({
    async get(keys) {
      const out = {};
      const list = typeof keys === 'string' ? [keys] : Array.isArray(keys) ? keys : Object.keys(keys || {});
      for (const key of list) if (map.has(key)) out[key] = map.get(key);
      return out;
    },
    async set(items) {
      const changes = {};
      for (const [key, value] of Object.entries(items)) {
        changes[key] = { oldValue: map.get(key), newValue: value };
        map.set(key, value);
      }
      created.emit(name, changes);
    },
    async remove(keys) {
      const changes = {};
      for (const key of [].concat(keys)) {
        changes[key] = { oldValue: map.get(key), newValue: undefined };
        map.delete(key);
      }
      created.emit(name, changes);
    },
    async clear() {
      map.clear();
    }
  });

  const onChangedListeners = [];
  const onMessageListeners = [];
  // chrome.storage.onChanged delivers (changesForArea, areaName)
  created.emit = (areaName, changes) => {
    for (const listener of onChangedListeners) listener(changes, areaName);
  };
  created.onMessageListeners = onMessageListeners;

  const stub = {
    storage: {
      sync: area(sync, 'sync'),
      session: area(session, 'session'),
      onChanged: { addListener: (fn) => onChangedListeners.push(fn) }
    },
    runtime: {
      getURL: (relative) => `chrome-extension://kryptboard-test/${relative}`,
      onMessage: { addListener: (fn) => onMessageListeners.push(fn) },
      getManifest: () => ({ version: '1.0.0' })
    },
    tabs: {
      query: async () => [],
      sendMessage: async () => ({ ok: true })
    }
  };
  return { stub, created, sync, session };
}

/* ------------------------------------------------------------------ */
/* page harness                                                        */
/* ------------------------------------------------------------------ */

async function createHarness(options = {}) {
  const { code } = await bundleSources({ root: ROOT, entry: 'src/content.js' });
  const dom = new JSDOM(options.html || PAGE_HTML, {
    url: 'https://example.test/',
    runScripts: 'outside-only',
    pretendToBeVisual: true
  });
  const { window } = dom;
  const { document } = window;

  // globals that jsdom does not provide but the crypto core needs
  window.TextEncoder = TextEncoder;
  window.TextDecoder = TextDecoder;
  if (!window.crypto || typeof window.crypto.getRandomValues !== 'function') {
    window.crypto = globalThis.crypto;
  }

  // Capture closed shadow roots: production uses mode 'closed', so tests must
  // record the roots at creation time, exactly like the extension holds them.
  const shadowRoots = [];
  const originalAttachShadow = window.Element.prototype.attachShadow;
  window.Element.prototype.attachShadow = function (init) {
    const root = originalAttachShadow.call(this, init);
    shadowRoots.push({ host: this, root, mode: init && init.mode });
    return root;
  };

  const chromeStub = createChromeStub(options.sync || {}, options.session || {});
  window.chrome = chromeStub.stub;

  window.eval(code);

  // The overlay is mounted lazily on first open, so the host is reached
  // through the attachShadow record rather than by querying the document.
  const record = shadowRoots[0];
  const host = record ? record.host : null;
  const shadow = record ? record.root : null;
  assert.ok(host, 'the content script did not create an overlay host');
  assert.ok(shadow, 'the content script did not create a shadow root');

  function shadowQuery(selector) {
    return shadow.querySelector(selector);
  }

  function focusField(id) {
    const field = document.getElementById(id);
    field.dispatchEvent(new window.FocusEvent('focusin', { bubbles: true }));
    field.focus();
    return field;
  }

  function pressHotkey(overrides = {}) {
    const event = new window.KeyboardEvent('keydown', {
      key: 'k', code: 'KeyK', ctrlKey: true, shiftKey: true, bubbles: true, cancelable: true, ...overrides
    });
    window.dispatchEvent(event);
    return event;
  }

  function clickKey(selector) {
    const el = shadowQuery(selector);
    assert.ok(el, `key not found: ${selector}`);
    el.click();
    return el;
  }

  async function waitFor(predicate, { timeout = 10000, step = 8 } = {}) {
    const deadline = Date.now() + timeout;
    while (Date.now() < deadline) {
      if (predicate()) return true;
      await new Promise((resolve) => setTimeout(resolve, step));
    }
    throw new Error('timed out waiting for condition');
  }

  /** Drives the content-script message API (this is what the popup uses). */
  async function sendMessage(message) {
    const listener = chromeStub.created.onMessageListeners[0];
    assert.ok(listener, 'content script registered no message listener');
    return new Promise((resolve) => {
      const keepAlive = listener(message, {}, resolve);
      assert.equal(keepAlive, true, 'listener must keep the channel open for async replies');
    });
  }

  const typeBuffer = (text) => {
    const field = shadowQuery('[data-role="buffer"]');
    field.value = text;
    field.dispatchEvent(new window.Event('input', { bubbles: true }));
    return field;
  };

  const harness = {
    dom,
    window,
    document,
    host,
    shadow,
    shadowRoots,
    chromeStub,
    shadowQuery,
    focusField,
    pressHotkey,
    clickKey,
    waitFor,
    sendMessage,
    typeBuffer,
    isMounted: () => !!host && document.body.contains(host),
    isVisible: () => !!host && document.body.contains(host) && shadowQuery('.kb').hidden === false
  };

  // The content script loads settings and the passphrase vault asynchronously;
  // the ping round-trip resolves once that bootstrap has finished.
  await harness.sendMessage({ type: 'kryptboard:ping' });
  return harness;
}

/* ------------------------------------------------------------------ */
/* the bundle itself                                                   */
/* ------------------------------------------------------------------ */

test('the committed bundle is in sync with the sources', { skip }, async () => {
  const { hash } = await bundleSources({ root: ROOT, entry: 'src/content.js' });
  const onDisk = await readBundleHash(path.join(ROOT, 'bundle/content.js'));
  assert.equal(onDisk, hash, 'run `npm run build` — bundle/content.js is stale');
});

test('bundle is a self-contained classic script (content scripts cannot be modules)', { skip }, async () => {
  const { code, modules } = await bundleSources({ root: ROOT, entry: 'src/content.js' });
  // module syntax must be gone entirely (the bundler's own residue scan is
  // string-aware, so a UI message may still *mention* the word)
  assert.equal(/^\s*(import|export)\s/m.test(code), false, 'bundle must not contain module syntax');
  assert.equal(code.includes('document.currentScript'), false);
  assert.equal(/\beval\s*\(/.test(code), false, 'no runtime eval');
  assert.deepEqual(modules, ['src/crypto.js', 'src/settings.js', 'src/keyboard.js', 'src/wiring.js', 'src/content.js']);
  assert.ok(code.length > 20000, 'bundle looks truncated');
});

/* ------------------------------------------------------------------ */
/* installation + overlay                                              */
/* ------------------------------------------------------------------ */

test('installs an overlay with a closed shadow root and no page-visible internals', { skip }, async () => {
  const harness = await createHarness();
  const { window, document, host, shadow } = harness;

  assert.equal(harness.isMounted(), false, 'the overlay must stay off the page until it is opened');
  assert.equal(window.__kryptboardInstalled, true);
  assert.equal(harness.shadowRoots.length, 1, 'exactly one overlay per frame');
  assert.equal(harness.shadowRoots[0].mode, 'closed', 'the shadow root must be closed so page scripts cannot read the buffer');
  assert.equal(host.shadowRoot, null, 'host.shadowRoot must not leak the internals');
  assert.equal(document.querySelector('[data-kryptboard="root"]'), null, 'the host must not be discoverable before it is used');

  // the page cannot see the plaintext buffer element through normal selectors
  assert.equal(document.querySelector('[data-role="buffer"]'), null);
  assert.ok(shadow.querySelector('[data-role="buffer"]'));

  await harness.waitFor(() => shadow.querySelectorAll('.kb-key').length > 0);
  harness.focusField('msg');
  harness.pressHotkey();
  assert.equal(harness.isMounted(), true, 'opening mounts the overlay into the page');
  assert.ok(shadow.querySelectorAll('.kb-key').length >= 30, 'keyboard should render a full layout');
  assert.equal(shadow.querySelectorAll('.kb-keyrow').length, 5);
});

test('the overlay stays hidden until the hotkey is pressed', { skip }, async () => {
  const harness = await createHarness();
  harness.focusField('msg');
  assert.equal(harness.isVisible(), false);

  harness.pressHotkey();
  assert.equal(harness.isVisible(), true);
  assert.equal(harness.shadowQuery('.kb-mode[data-v="encrypted"]').classList.contains('is-active'), true);

  harness.pressHotkey();
  assert.equal(harness.isVisible(), false);
});

test('a disabled extension ignores the hotkey', { skip }, async () => {
  const harness = await createHarness({
    sync: { 'kryptboard:settings': { enabled: false } }
  });
  harness.focusField('msg');
  await harness.waitFor(() => harness.shadowQuery('.kb-key'));
  harness.pressHotkey();
  assert.equal(harness.isVisible(), false, 'hotkey must be inert when the extension is disabled');
});

/* ------------------------------------------------------------------ */
/* encrypted mode: the core promise of the project                     */
/* ------------------------------------------------------------------ */

test('encrypted mode buffers keystrokes and commits only the sealed envelope', { skip }, async () => {
  const harness = await createHarness({
    session: { 'kryptboard:passphrase': 'session-passphrase' }
  });
  const { shadowQuery, document } = harness;
  const field = harness.focusField('msg');
  harness.pressHotkey();

  // type "hi" on the on-screen keyboard
  harness.clickKey('[data-act="char"][data-v="h"]');
  harness.clickKey('[data-act="char"][data-v="i"]');
  harness.clickKey('[data-act="space"]');

  assert.equal(shadowQuery('[data-role="buffer"]').value, 'hi ');
  assert.equal(field.value, '', 'nothing may be committed while typing in encrypted mode');

  harness.clickKey('[data-act="send"]');
  await harness.waitFor(() => field.value.length > 0);

  assert.match(field.value, /^v1\|CHACHA20-POLY1305\|/);
  assert.equal(field.value.includes('hi'), false, 'plaintext must never reach the page');
  assert.equal(shadowQuery('[data-role="buffer"]').value, '', 'the buffer must be wiped after sealing');

  // and the envelope really is decryptable with that passphrase
  const { kbDecrypt } = await import('../src/crypto.js');
  assert.equal(await kbDecrypt(field.value, 'session-passphrase'), 'hi ');
  void document;
});

test('shift, backspace, layers and enter all compose correctly in the buffer', { skip }, async () => {
  const harness = await createHarness({ session: { 'kryptboard:passphrase': 'pw' } });
  const { shadowQuery } = harness;
  harness.focusField('msg');
  harness.pressHotkey();

  harness.clickKey('[data-act="shift"]');
  harness.clickKey('[data-act="char"][data-v="a"]'); // shifted → "A"
  assert.equal(shadowQuery('[data-role="buffer"]').value, 'A');
  assert.equal(shadowQuery('[data-act="char"][data-v="a"]').textContent, 'a', 'shift is one-shot');

  harness.clickKey('[data-act="char"][data-v="b"]');
  harness.clickKey('[data-act="backspace"]');
  assert.equal(shadowQuery('[data-role="buffer"]').value, 'A');

  harness.clickKey('[data-act="layer"][data-v="symbols"]');
  harness.clickKey('[data-act="char"][data-v="@"]');
  assert.equal(shadowQuery('[data-role="buffer"]').value, 'A@');
  harness.clickKey('[data-act="layer"][data-v="letters"]');

  harness.clickKey('[data-act="enter"]');
  assert.equal(shadowQuery('[data-role="buffer"]').value, 'A@\n');

  harness.clickKey('[data-act="clear"]');
  assert.equal(shadowQuery('[data-role="buffer"]').value, '');
});

test('sealing without a passphrase is refused, with the buffer preserved', { skip }, async () => {
  const harness = await createHarness(); // no passphrase in session storage
  const { shadowQuery } = harness;
  const field = harness.focusField('msg');
  harness.pressHotkey();
  harness.clickKey('[data-act="char"][data-v="x"]');
  harness.clickKey('[data-act="send"]');

  await harness.waitFor(() => /passphrase/.test(shadowQuery('[data-role="status"]').textContent));
  assert.equal(field.value, '', 'nothing may be committed without a passphrase');
  assert.equal(shadowQuery('[data-role="buffer"]').value, 'x', 'the user must not lose their text');
  assert.equal(shadowQuery('[data-role="pass-row"]').hidden, false, 'the passphrase row should be revealed');
});

/* ------------------------------------------------------------------ */
/* plain mode                                                          */
/* ------------------------------------------------------------------ */

test('plain mode commits keystrokes straight into the focused field', { skip }, async () => {
  const harness = await createHarness({
    sync: { 'kryptboard:settings': { startMode: 'plain' } }
  });
  const field = harness.focusField('msg');
  harness.pressHotkey();

  assert.equal(harness.shadowQuery('.kb-mode[data-v="plain"]').classList.contains('is-active'), true);
  harness.clickKey('[data-act="char"][data-v="h"]');
  harness.clickKey('[data-act="char"][data-v="i"]');
  harness.clickKey('[data-act="space"]');

  assert.equal(field.value, 'hi ');
  assert.equal(harness.shadowQuery('[data-role="buffer"]').value, '', 'plain mode does not buffer');
  assert.match(harness.shadowQuery('[data-role="status"]').textContent, /^Plain mode/);
});

test('plain mode writes into contenteditable elements', { skip }, async () => {
  const harness = await createHarness({ sync: { 'kryptboard:settings': { startMode: 'plain' } } });
  const rich = harness.focusField('rich');
  harness.pressHotkey();
  harness.clickKey('[data-act="char"][data-v="z"]');
  assert.equal(rich.textContent, 'z');
});

test('password fields are never used as a commit target', { skip }, async () => {
  const harness = await createHarness({ sync: { 'kryptboard:settings': { startMode: 'plain' } } });
  const password = harness.focusField('pw');
  harness.pressHotkey();

  assert.match(harness.shadowQuery('.kb-target').textContent, /pick a text field/);
  harness.clickKey('[data-act="char"][data-v="s"]');
  assert.equal(password.value, '', 'the overlay must keep out of password fields');
  assert.match(harness.shadowQuery('[data-role="status"]').textContent, /No text field selected/);
});

/* ------------------------------------------------------------------ */
/* envelope detection / decryption in the overlay                      */
/* ------------------------------------------------------------------ */

test('an envelope pasted into the buffer can be decrypted from the overlay', { skip }, async () => {
  const { kbEncrypt } = await import('../src/crypto.js');
  const envelope = await kbEncrypt('recovered plaintext', 'pw');
  const harness = await createHarness({ session: { 'kryptboard:passphrase': 'pw' } });
  harness.focusField('msg');
  harness.pressHotkey();

  harness.typeBuffer(envelope);
  assert.equal(harness.shadowQuery('[data-role="env-chip"]').hidden, false, 'the envelope chip should light up');
  assert.equal(harness.shadowQuery('[data-role="decrypt"]').hidden, false);

  harness.clickKey('[data-act="decrypt"]');
  await harness.waitFor(() => harness.shadowQuery('[data-role="buffer"]').value === 'recovered plaintext');
  assert.match(harness.shadowQuery('[data-role="status"]').textContent, /tag verified/i);
});

test('a tampered envelope fails loudly and is not silently decrypted', { skip }, async () => {
  const { kbEncrypt } = await import('../src/crypto.js');
  const envelope = await kbEncrypt('recovered plaintext', 'pw');
  const parts = envelope.split('|');
  parts[3] = parts[3].slice(0, -2) + (parts[3].endsWith('AA') ? 'BB' : 'AA');

  const harness = await createHarness({ session: { 'kryptboard:passphrase': 'pw' } });
  harness.focusField('msg');
  harness.pressHotkey();
  harness.typeBuffer(parts.join('|'));
  harness.clickKey('[data-act="decrypt"]');

  await harness.waitFor(() => /failed|Authentication/i.test(harness.shadowQuery('[data-role="status"]').textContent));
  assert.equal(harness.shadowQuery('[data-role="buffer"]').value, parts.join('|'), 'the buffer is left untouched');
});

/* ------------------------------------------------------------------ */
/* settings plumbing                                                   */
/* ------------------------------------------------------------------ */

test('the popup message API toggles the overlay and reports state', { skip }, async () => {
  const harness = await createHarness({ session: { 'kryptboard:passphrase': 'pw' } });
  harness.focusField('msg');

  const initial = await harness.sendMessage({ type: 'kryptboard:ping' });
  assert.equal(initial.ok, true);
  assert.equal(initial.open, false);
  assert.equal(initial.hasTarget, true);
  assert.equal(initial.hasPassphrase, true);
  assert.equal(initial.hotkey, 'Ctrl+Shift+K');

  const opened = await harness.sendMessage({ type: 'kryptboard:toggle' });
  assert.equal(opened.open, true);
  assert.equal(harness.isVisible(), true);

  const closed = await harness.sendMessage({ type: 'kryptboard:toggle' });
  assert.equal(closed.open, false);

  const cleared = await harness.sendMessage({ type: 'kryptboard:clear-passphrase' });
  assert.equal(cleared.ok, true);
  const after = await harness.sendMessage({ type: 'kryptboard:ping' });
  assert.equal(after.hasPassphrase, false);

  const unknown = await harness.sendMessage({ type: 'kryptboard:nope' });
  assert.equal(unknown.ok, false);
});

test('settings changes made elsewhere are picked up live', { skip }, async () => {
  const harness = await createHarness();
  harness.focusField('msg');
  await harness.waitFor(() => harness.shadowQuery('.kb-key'));

  await harness.chromeStub.stub.storage.sync.set({
    'kryptboard:settings': { theme: 'light', startMode: 'plain', showHints: false }
  });
  await harness.waitFor(() => harness.shadowQuery('[data-role="hint"]').hidden === true);
  assert.equal(harness.shadowQuery('.kb').dataset.theme, 'light');

  harness.pressHotkey();
  assert.equal(harness.shadowQuery('.kb-mode[data-v="plain"]').classList.contains('is-active'), true,
    'a new open should honour the new default mode');
});

test('the overlay never issues a network request', { skip }, async () => {
  const harness = await createHarness({ session: { 'kryptboard:passphrase': 'pw' } });
  const { window } = harness;
  const attempts = [];
  for (const name of ['fetch', 'XMLHttpRequest', 'WebSocket', 'EventSource', 'sendBeacon']) {
    const original = window[name];
    const spy = (...args) => {
      attempts.push(`${name}(${String(args[0] && args[0].url ? args[0].url : args[0]).slice(0, 40)})`);
      return original ? original.apply(window, args) : undefined;
    };
    try {
      window[name] = spy;
      if (window.navigator && name === 'sendBeacon') window.navigator.sendBeacon = spy;
    } catch (error) {
      /* read-only in this environment */
    }
  }

  harness.focusField('msg');
  harness.pressHotkey();
  harness.clickKey('[data-act="char"][data-v="h"]');
  harness.clickKey('[data-act="send"]');
  await harness.waitFor(() => harness.document.getElementById('msg').value.length > 0);

  assert.deepEqual(attempts, [], 'the keyboard must stay offline');
});

/* ------------------------------------------------------------------ */
/* target editing primitives                                           */
/* ------------------------------------------------------------------ */

async function primitiveHarness(html) {
  const dom = new JSDOM(`<!doctype html><body>${html}</body>`, { url: 'https://example.test/', runScripts: 'outside-only' });
  const { window } = dom;
  window.TextEncoder = TextEncoder;
  window.TextDecoder = TextDecoder;
  const { kbInsertText, kbDeleteBackward, kbCommitEnter, kbCommitToTarget, kbIsEditable, kbIsContentEditable, kbIsPasswordField } =
    await import('../src/keyboard.js');
  return { window, document: window.document, kbInsertText, kbDeleteBackward, kbCommitEnter, kbCommitToTarget, kbIsEditable, kbIsContentEditable, kbIsPasswordField };
}

test('inserting text respects maxlength, replaces the selection and leaves the caret after it', { skip }, async () => {
  const h = await primitiveHarness('<input id="short" maxlength="5" value="ab" /><input id="plain" value="hello" />');

  const short = h.document.getElementById('short');
  short.setSelectionRange(2, 2); // caret at the end of "ab"
  h.kbInsertText(short, 'cdefgh');
  assert.equal(short.value, 'abcde', 'the field must not exceed its own maxlength');

  // overflow must not destroy what already sits after the caret
  short.value = 'ab';
  short.setSelectionRange(0, 0);
  h.kbInsertText(short, 'XYZWVU');
  assert.equal(short.value, 'XYZab', 'existing characters survive an overflowing insert');

  const plain = h.document.getElementById('plain');
  plain.setSelectionRange(1, 4); // replace "ell"
  h.kbInsertText(plain, 'ipp');
  assert.equal(plain.value, 'hippo');
  assert.equal(plain.selectionStart, 4);
  assert.equal(plain.selectionEnd, 4);
});

test('inserting text fires beforeinput and input so frameworks notice', { skip }, async () => {
  const h = await primitiveHarness('<input id="f" value="" />');
  const field = h.document.getElementById('f');
  const events = [];
  field.addEventListener('beforeinput', () => events.push('beforeinput'));
  field.addEventListener('input', (event) => events.push(`input:${event.inputType || 'event'}`));
  h.kbInsertText(field, 'x');
  assert.deepEqual(events.slice(0, 1), ['beforeinput']);
  assert.equal(events.some((e) => e.startsWith('input')), true);
});

test('a cancelled beforeinput aborts the insert', { skip }, async () => {
  const h = await primitiveHarness('<input id="f" value="keep" />');
  const field = h.document.getElementById('f');
  field.addEventListener('beforeinput', (event) => event.preventDefault());
  const result = h.kbInsertText(field, 'nope');
  assert.equal(result.ok, false);
  assert.equal(result.reason, 'cancelled');
  assert.equal(field.value, 'keep');
});

test('backspace deletes the selection, then single characters, and stops at the start', { skip }, async () => {
  const h = await primitiveHarness('<input id="f" value="abcdef" />');
  const field = h.document.getElementById('f');

  field.setSelectionRange(2, 5);
  h.kbDeleteBackward(field);
  assert.equal(field.value, 'abf', 'a selection is deleted wholesale');

  field.setSelectionRange(2, 2);
  h.kbDeleteBackward(field);
  assert.equal(field.value, 'af');

  field.setSelectionRange(0, 0);
  assert.equal(h.kbDeleteBackward(field).reason, 'at-start');
  assert.equal(field.value, 'af', 'nothing happens at position 0');
});

test('enter submits a single-line form but inserts a newline in a textarea', { skip }, async () => {
  const h = await primitiveHarness('<form id="frm"><input id="line" value="" /></form><textarea id="area"></textarea>');
  let submitted = 0;
  h.document.getElementById('frm').addEventListener('submit', (event) => {
    event.preventDefault();
    submitted++;
  });

  const line = h.document.getElementById('line');
  const lineResult = h.kbCommitEnter(line, () => ({ ok: true }));
  assert.equal(lineResult.ok, true);
  assert.equal(lineResult.submitted, true, 'a single-line field should let the page submit');
  assert.equal(submitted, 1);

  const area = h.document.getElementById('area');
  let committed = '';
  h.kbCommitEnter(area, (text) => {
    committed = text;
    return { ok: true };
  });
  assert.equal(committed, '\n', 'a textarea gets a literal newline');
});

test('the execCommand commit path is used when the page relies on it', { skip }, async () => {
  const h = await primitiveHarness('<input id="f" value="" />');
  const field = h.document.getElementById('f');
  const calls = [];
  h.document.execCommand = (command, ui, value) => {
    calls.push({ command, value });
    field.value += value; // pretend the browser did the insert
    return true;
  };

  const result = h.kbCommitToTarget(field, 'typed', 'execCommand');
  assert.equal(result.ok, true);
  assert.equal(result.via, 'execCommand');
  assert.deepEqual(calls, [{ command: 'insertText', value: 'typed' }]);

  // a refusing document falls back to the native path rather than losing text
  h.document.execCommand = () => false;
  const fallback = h.kbCommitToTarget(field, 'X', 'execCommand');
  assert.equal(fallback.reason, 'refused');
});

test('editability classification covers the fields that matter', { skip }, async () => {
  const h = await primitiveHarness([
    '<input id="text" type="text" />',
    '<input id="search" type="search" />',
    '<input id="pw" type="password" />',
    '<input id="ro" readonly value="x" />',
    '<input id="dis" disabled />',
    '<textarea id="ta"></textarea>',
    '<div id="ce" contenteditable="true"></div>',
    '<div id="celess"></div>',
    '<div id="inherit"><span id="child"></span></div>'
  ].join(''));

  const doc = h.document;
  assert.equal(h.kbIsEditable(doc.getElementById('text')), true);
  assert.equal(h.kbIsEditable(doc.getElementById('search')), true);
  assert.equal(h.kbIsEditable(doc.getElementById('pw')), true, 'a password field is editable — it is the *targeting* rule that excludes it');
  assert.equal(h.kbIsEditable(doc.getElementById('ro')), false, 'readonly must never be written to');
  assert.equal(h.kbIsEditable(doc.getElementById('dis')), false);
  assert.equal(h.kbIsEditable(doc.getElementById('ta')), true);
  assert.equal(h.kbIsEditable(doc.getElementById('ce')), true);
  assert.equal(h.kbIsEditable(doc.getElementById('celess')), false);
  assert.equal(h.kbIsEditable(null), false);

  assert.equal(h.kbIsPasswordField(doc.getElementById('pw')), true);
  assert.equal(h.kbIsPasswordField(doc.getElementById('text')), false);
  assert.equal(h.kbIsContentEditable(doc.getElementById('ce')), true);
  assert.equal(h.kbIsContentEditable(doc.getElementById('celess')), false);

  // a detached element is not a valid target
  const orphan = doc.createElement('input');
  assert.equal(h.kbIsEditable(orphan), false);
});

/* ------------------------------------------------------------------ */
/* settings-driven overlay behaviour                                   */
/* ------------------------------------------------------------------ */

test('password fields can be opted back in, and are excluded by default', { skip }, async () => {
  const { kbEncrypt: _unused } = {}; // keep the import graph obvious
  void _unused;

  const strict = await createHarness({ sync: { 'kryptboard:settings': { startMode: 'plain' } } });
  const strictField = strict.focusField('pw');
  strict.pressHotkey();
  strict.clickKey('[data-act="char"][data-v="s"]');
  assert.equal(strictField.value, '', 'default: password fields stay untouched');

  const relaxed = await createHarness({
    sync: { 'kryptboard:settings': { startMode: 'plain', ignorePasswordFields: false } }
  });
  const relaxedField = relaxed.focusField('pw');
  relaxed.pressHotkey();
  relaxed.clickKey('[data-act="char"][data-v="s"]');
  assert.equal(relaxedField.value, 's', 'opting out of the guard targets the field again');
});

test('escape hides the overlay unless that shortcut is disabled', { skip }, async () => {
  const standard = await createHarness();
  standard.focusField('msg');
  standard.pressHotkey();
  assert.equal(standard.isVisible(), true);
  standard.shadowQuery('[data-role="buffer"]').dispatchEvent(new standard.window.KeyboardEvent('keydown', {
    key: 'Escape', bubbles: true, cancelable: true
  }));
  assert.equal(standard.isVisible(), false);

  const sticky = await createHarness({ sync: { 'kryptboard:settings': { hideOnEscape: false } } });
  sticky.focusField('msg');
  sticky.pressHotkey();
  sticky.shadowQuery('[data-role="buffer"]').dispatchEvent(new sticky.window.KeyboardEvent('keydown', {
    key: 'Escape', bubbles: true, cancelable: true
  }));
  assert.equal(sticky.isVisible(), true, 'the shortcut is documented as configurable');
});

test('keystrokes in the buffer never reach page listeners', { skip }, async () => {
  const harness = await createHarness({ session: { 'kryptboard:passphrase': 'pw' } });
  harness.focusField('msg');
  harness.pressHotkey();

  // Bubble phase, i.e. exactly what a page's own keydown/input handlers use.
  // (Capture listeners on document are inherently first — no handler inside a
  // shadow tree can pre-empt them; that is true of every web page.)
  const leaked = [];
  for (const type of ['keydown', 'keyup', 'keypress', 'beforeinput', 'input', 'compositionupdate', 'paste']) {
    harness.document.addEventListener(type, (event) => leaked.push(`${type}:${event.data || event.key || ''}`), false);
    harness.document.body.addEventListener(type, (event) => leaked.push(`body-${type}`), false);
  }

  const bufferField = harness.shadowQuery('[data-role="buffer"]');
  for (const key of ['s', 'e', 'c']) {
    bufferField.value += key;
    bufferField.dispatchEvent(new harness.window.KeyboardEvent('keydown', { key, bubbles: true, composed: true }));
    bufferField.dispatchEvent(new harness.window.InputEvent('input', { data: key, bubbles: true, composed: true }));
    bufferField.dispatchEvent(new harness.window.KeyboardEvent('keyup', { key, bubbles: true, composed: true }));
  }

  assert.deepEqual(leaked, [], 'the page must not be able to observe what is typed into the overlay');
  assert.equal(bufferField.value, 'sec', 'the overlay itself still received the keys');

  // clicks and buttons inside the overlay are still fully functional
  harness.clickKey('[data-act="char"][data-v="x"]');
  assert.equal(harness.shadowQuery('[data-role="buffer"]').value, 'secx');
});

test('the buffer can be kept after hiding, and is wiped by default', { skip }, async () => {
  const keep = await createHarness({
    session: { 'kryptboard:passphrase': 'pw' },
    sync: { 'kryptboard:settings': { clearBufferOnClose: false } }
  });
  keep.focusField('msg');
  keep.pressHotkey();
  keep.clickKey('[data-act="char"][data-v="k"]');
  keep.clickKey('[data-act="hide"]');
  assert.equal(keep.shadowQuery('[data-role="buffer"]').value, 'k', 'kept when asked');

  const wipe = await createHarness({ session: { 'kryptboard:passphrase': 'pw' } });
  wipe.focusField('msg');
  wipe.pressHotkey();
  wipe.clickKey('[data-act="char"][data-v="k"]');
  wipe.clickKey('[data-act="hide"]');
  assert.equal(wipe.shadowQuery('[data-role="buffer"]').value, '', 'wiped by default');
});

test('sealing can leave the overlay open for a second message', { skip }, async () => {
  const harness = await createHarness({
    session: { 'kryptboard:passphrase': 'pw' },
    sync: { 'kryptboard:settings': { closeAfterSend: false } }
  });
  const field = harness.focusField('msg');
  harness.pressHotkey();
  harness.clickKey('[data-act="char"][data-v="o"]');
  harness.clickKey('[data-act="char"][data-v="k"]');
  harness.clickKey('[data-act="send"]');
  await harness.waitFor(() => harness.document.getElementById('msg').value.startsWith('v1|'));

  assert.equal(harness.isVisible(), true, 'stays open when configured');
  assert.equal(harness.shadowQuery('[data-role="buffer"]').value, '', 'but the buffer is still wiped');

  // a second message seals independently
  harness.clickKey('[data-act="char"][data-v="z"]');
  harness.clickKey('[data-act="send"]');
  await harness.waitFor(() => field.value.split('v1|').length === 3);
  assert.notEqual(field.value.split('v1|')[1], field.value.split('v1|')[2], 'fresh nonce per message');
});

test('copy puts the envelope on the clipboard and paste reads one back', { skip }, async () => {
  const harness = await createHarness({
    session: { 'kryptboard:passphrase': 'pw' },
    sync: { 'kryptboard:settings': { closeAfterSend: false } }
  });
  const copied = [];
  let clipboardValue = '';
  Object.defineProperty(harness.window.navigator, 'clipboard', {
    configurable: true,
    value: {
      writeText: async (text) => {
        copied.push(text);
        clipboardValue = text;
      },
      readText: async () => clipboardValue
    }
  });

  const buffer = () => harness.shadowQuery('[data-role="buffer"]').value;
  const field = harness.focusField('msg');
  harness.pressHotkey();

  // 1. copy the plain buffer
  harness.clickKey('[data-act="char"][data-v="h"]');
  harness.clickKey('[data-act="copy"]');
  await harness.waitFor(() => copied.length === 1);
  assert.equal(copied[0], 'h');

  // 2. paste it back into an emptied buffer
  harness.clickKey('[data-act="clear"]');
  assert.equal(buffer(), '');
  harness.clickKey('[data-act="paste"]');
  await harness.waitFor(() => buffer() === 'h');

  // 3. seal it, then copy the *last envelope* (the buffer is empty now)
  harness.clickKey('[data-act="send"]');
  await harness.waitFor(() => field.value.startsWith('v1|'));
  assert.equal(buffer(), '');
  harness.clickKey('[data-act="copy"]');
  await harness.waitFor(() => copied.length === 2);
  assert.match(copied[1], /^v1\|CHACHA20-POLY1305\|/);

  // 4. paste the envelope and decrypt it back to plaintext
  harness.clickKey('[data-act="paste"]');
  await harness.waitFor(() => buffer() === copied[1]);
  harness.clickKey('[data-act="decrypt"]');
  await harness.waitFor(() => buffer() === 'h');
  assert.match(harness.shadowQuery('[data-role="status"]').textContent, /AEAD tag verified|Decrypted/);
});

test('shift locks after a double press, and theme cycles through its three states', { skip }, async () => {
  const harness = await createHarness({ session: { 'kryptboard:passphrase': 'pw' } });
  harness.focusField('msg');
  harness.pressHotkey();

  harness.clickKey('[data-act="shift"]');
  harness.clickKey('[data-act="shift"]');
  const shiftKey = harness.shadowQuery('[data-act="shift"]');
  assert.equal(shiftKey.classList.contains('is-active'), true);
  assert.equal(shiftKey.textContent, '⇪', 'shift lock has its own glyph');

  harness.clickKey('[data-act="char"][data-v="a"]');
  harness.clickKey('[data-act="char"][data-v="b"]');
  assert.equal(harness.shadowQuery('[data-role="buffer"]').value, 'AB', 'lock keeps producing capitals');
  harness.clickKey('[data-act="shift"]');
  harness.clickKey('[data-act="char"][data-v="c"]');
  assert.equal(harness.shadowQuery('[data-role="buffer"]').value, 'ABc', 'a third press releases it');

  const theme = () => harness.shadowQuery('.kb').dataset.theme;
  const before = theme();
  harness.clickKey('[data-act="theme"]');
  assert.notEqual(theme(), before, 'the theme button cycles');
  harness.clickKey('[data-act="theme"]');
  harness.clickKey('[data-act="theme"]');
  assert.equal(theme(), before, 'and wraps around');
});

test('backspace on an empty buffer and empty sends are handled quietly', { skip }, async () => {
  const harness = await createHarness({ session: { 'kryptboard:passphrase': 'pw' } });
  harness.focusField('msg');
  harness.pressHotkey();

  harness.clickKey('[data-act="backspace"]');
  assert.equal(harness.shadowQuery('[data-role="buffer"]').value, '');

  // the button advertises its own state rather than firing into the void
  assert.equal(harness.shadowQuery('[data-act="send"]').disabled, true, 'nothing to send');

  // and the Ctrl+Enter shortcut takes the same guard
  harness.shadowQuery('[data-role="buffer"]').dispatchEvent(new harness.window.KeyboardEvent('keydown', {
    key: 'Enter', ctrlKey: true, bubbles: true, cancelable: true
  }));
  await harness.waitFor(() => /Nothing to send/.test(harness.shadowQuery('[data-role="status"]').textContent));
  assert.equal(harness.document.getElementById('msg').value, '', 'an empty send writes nothing');

  // empty copy is equally harmless and must not throw
  harness.clickKey('[data-act="copy"]');
  await harness.waitFor(() => /Nothing to copy/.test(harness.shadowQuery('[data-role="status"]').textContent));

  // typing re-enables the button
  harness.clickKey('[data-act="char"][data-v="q"]');
  await harness.waitFor(() => harness.shadowQuery('[data-act="send"]').disabled === false);
});

test('a long message still seals and round-trips exactly', { skip }, async () => {
  const { kbDecrypt } = await import('../src/crypto.js');
  const harness = await createHarness({ session: { 'kryptboard:passphrase': 'pw' } });
  const field = harness.focusField('msg');
  harness.pressHotkey();

  const message = 'The quick brown fox jumps over the lazy dog. '.repeat(20).trim();
  harness.typeBuffer(message);
  assert.match(harness.shadowQuery('[data-role="count"]').textContent, new RegExp(`${message.length} ch`));

  harness.clickKey('[data-act="send"]');
  await harness.waitFor(() => field.value.startsWith('v1|'));
  assert.equal(await kbDecrypt(field.value, 'pw'), message);
  assert.match(harness.shadowQuery('[data-role="status"]').textContent, /Sealed \d+ B → \d+ B envelope/);
});

/* ------------------------------------------------------------------ */
/* Paper Algorithm 1 / 2 in the overlay (single-session key model)      */
/* ------------------------------------------------------------------ */

test('session mode seals the buffer into Algorithm 1 output', { skip }, async () => {
  const { kbGenerateSessionKey, kbDecryptFromDict, kbDecryptWithKey, kbParseEnvelope, kbEncodeSessionKey } =
    await import('../src/crypto.js');

  for (const format of ['json', 'envelope']) {
    const harness = await createHarness({
      sync: { 'kryptboard:settings': { keyModel: 'session', sessionFormat: format } }
    });
    const key = kbGenerateSessionKey();
    const reply = await harness.sendMessage({ type: 'kryptboard:set-session-key', key: kbEncodeSessionKey(key) });
    assert.equal(reply.ok, true, 'the popup can hand over a session key');
    assert.match(reply.fingerprint, /^[0-9A-F]{4}(-[0-9A-F]{4}){3}$/);

    const field = harness.focusField('msg');
    harness.pressHotkey();
    harness.typeBuffer('session secret');
    harness.clickKey('[data-act="send"]');
    await harness.waitFor(() => field.value.length > 0);

    if (format === 'json') {
      // exactly the paper's dictionary
      const dict = JSON.parse(field.value);
      assert.deepEqual(Object.keys(dict).sort(), ['ciphertext', 'nonce', 'tag']);
      assert.equal(dict.ciphertext.includes('session secret'), false);
      assert.equal(kbDecryptFromDict(dict, key), 'session secret');
      assert.match(harness.shadowQuery('[data-role="status"]').textContent, /dictionary/);
    } else {
      assert.match(field.value, /^v1\|CHACHA20-POLY1305\+SESSIONKEY\|/);
      assert.equal(kbDecryptWithKey(field.value, key), 'session secret');
      assert.equal(kbParseEnvelope(field.value).alg, 'CHACHA20-POLY1305+SESSIONKEY');
    }
    assert.equal(harness.shadowQuery('[data-role="buffer"]').value, '', 'the buffer is wiped either way');
  }
});

test('session mode refuses to seal without a key, and picks one up live', { skip }, async () => {
  const { kbGenerateSessionKey, kbEncodeSessionKey } = await import('../src/crypto.js');
  const harness = await createHarness({ sync: { 'kryptboard:settings': { keyModel: 'session' } } });
  const field = harness.focusField('msg');
  harness.pressHotkey();
  harness.typeBuffer('no key yet');
  harness.clickKey('[data-act="send"]');

  await harness.waitFor(() => /no key yet/.test(harness.shadowQuery('[data-role="status"]').textContent));
  assert.equal(field.value, '', 'nothing was committed');
  assert.equal(harness.shadowQuery('[data-role="buffer"]').value, 'no key yet', 'the buffer is preserved');

  // the popup hands a key over while the overlay is open
  await harness.sendMessage({ type: 'kryptboard:set-session-key', key: kbEncodeSessionKey(kbGenerateSessionKey()) });
  harness.clickKey('[data-act="send"]');
  await harness.waitFor(() => JSON.parse(field.value || '{}').ciphertext);
  assert.match(harness.shadowQuery('[data-role="status"]').textContent, /committed/);
});

test('a dictionary pasted into the buffer decrypts with the session key', { skip }, async () => {
  const { kbGenerateSessionKey, kbEncryptToDict, kbEncodeSessionKey } = await import('../src/crypto.js');
  const harness = await createHarness({ session: { 'kryptboard:passphrase': 'irrelevant' } });
  const key = kbGenerateSessionKey();
  const dict = kbEncryptToDict('read me back', key);

  // without the key the overlay explains what is missing
  harness.typeBuffer(JSON.stringify(dict));
  harness.clickKey('[data-act="decrypt"]');
  await harness.waitFor(() => /session key/.test(harness.shadowQuery('[data-role="status"]').textContent));
  assert.equal(harness.shadowQuery('[data-role="buffer"]').value.startsWith('{'), true);

  // and with it, Algorithm 2 runs
  await harness.sendMessage({ type: 'kryptboard:set-session-key', key: kbEncodeSessionKey(key) });
  harness.clickKey('[data-act="decrypt"]');
  await harness.waitFor(() => harness.shadowQuery('[data-role="buffer"]').value === 'read me back');
  assert.match(harness.shadowQuery('[data-role="status"]').textContent, /tag verified/i);
  assert.match(harness.shadowQuery('[data-role="status"]').textContent, /session key [0-9A-F]{4}/);
});

test('a dictionary is offered Decrypt and labelled, without a passphrase', { skip }, async () => {
  const { kbGenerateSessionKey, kbEncryptToDict } = await import('../src/crypto.js');
  const harness = await createHarness();
  harness.typeBuffer(JSON.stringify(kbEncryptToDict('detect me', kbGenerateSessionKey())));

  assert.equal(harness.shadowQuery('[data-act="decrypt"]').hidden, false);
  assert.equal(harness.shadowQuery('[data-role="env-chip"]').hidden, false);
  assert.match(harness.shadowQuery('[data-role="env-chip"]').textContent, /dictionary/);
});

test('a tampered dictionary is never silently accepted in the overlay', { skip }, async () => {
  const { kbGenerateSessionKey, kbEncryptToDict, kbEncodeSessionKey, kbB64Encode, kbB64Decode } = await import('../src/crypto.js');
  const harness = await createHarness();
  const key = kbGenerateSessionKey();
  const dict = kbEncryptToDict('untouched', key);
  const tag = kbB64Decode(dict.tag);
  tag[0] ^= 0xff;

  await harness.sendMessage({ type: 'kryptboard:set-session-key', key: kbEncodeSessionKey(key) });
  harness.typeBuffer(JSON.stringify({ ...dict, tag: kbB64Encode(tag) }));
  harness.clickKey('[data-act="decrypt"]');
  await harness.waitFor(() => /Tag verification failed/.test(harness.shadowQuery('[data-role="status"]').textContent));
  assert.equal(harness.shadowQuery('[data-role="buffer"]').value.includes('untouched'), false);
});
