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

  async function waitFor(predicate, { timeout = 3000, step = 8 } = {}) {
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
  assert.equal(/^\s*(import|export)\s/m.test(code), false, 'bundle must not contain module syntax');
  assert.equal(code.includes('document.currentScript'), false);
  assert.equal(/\beval\s*\(/.test(code), false, 'no runtime eval');
  assert.deepEqual(modules, ['src/settings.js', 'src/crypto.js', 'src/keyboard.js', 'src/wiring.js', 'src/content.js']);
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
