/**
 * Content-script glue tests: installation, the popup message API and the
 * storage listeners that keep the overlay in sync with chrome.storage.
 *
 * These complement tests/dom.test.mjs (which drives the overlay itself) by
 * targeting the seams: double injection, unknown messages, messages that
 * arrive before storage has loaded, and pushed changes from other tabs.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { bundleSources } from '../scripts/bundler.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

let JSDOM = null;
try {
  ({ JSDOM } = await import('jsdom'));
} catch (error) {
  JSDOM = null;
}
const skip = JSDOM ? false : 'jsdom is not installed (run: npm install)';

const PAGE_HTML = '<!doctype html><html><body><textarea id="msg"></textarea></body></html>';

/** Minimal chrome.storage + runtime stub with controllable latency. */
function createChromeStub({ sync = {}, session = {}, getDelayMs = 0 } = {}) {
  const maps = { sync: new Map(Object.entries(sync)), session: new Map(Object.entries(session)) };
  const onChangedListeners = [];
  const onMessageListeners = [];
  const calls = { get: 0, set: 0 };

  const delay = () => (getDelayMs ? new Promise((resolve) => setTimeout(resolve, getDelayMs)) : null);

  const area = (map, name) => ({
    async get(keys) {
      calls.get++;
      const wait = delay();
      if (wait) await wait;
      const out = {};
      const list = typeof keys === 'string' ? [keys] : Array.isArray(keys) ? keys : Object.keys(keys || {});
      for (const key of list) if (map.has(key)) out[key] = map.get(key);
      return out;
    },
    async set(items) {
      calls.set++;
      const changes = {};
      for (const [key, value] of Object.entries(items)) {
        changes[key] = { oldValue: map.get(key), newValue: value };
        map.set(key, value);
      }
      for (const listener of onChangedListeners) listener(changes, name);
    },
    async remove(keys) {
      const changes = {};
      for (const key of [].concat(keys)) {
        changes[key] = { oldValue: map.get(key), newValue: undefined };
        map.delete(key);
      }
      for (const listener of onChangedListeners) listener(changes, name);
    },
    async clear() {
      map.clear();
    }
  });

  const stub = {
    storage: {
      sync: area(maps.sync, 'sync'),
      session: area(maps.session, 'session'),
      onChanged: { addListener: (fn) => onChangedListeners.push(fn) }
    },
    runtime: {
      getURL: (relative) => `chrome-extension://kryptboard-test/${relative}`,
      onMessage: { addListener: (fn) => onMessageListeners.push(fn) },
      getManifest: () => ({ version: '1.0.0' })
    }
  };

  return { stub, maps, calls, onChangedListeners, onMessageListeners };
}

async function createHarness(options = {}) {
  const { code } = await bundleSources({ root: ROOT, entry: 'src/content.js' });
  const dom = new JSDOM(options.html || PAGE_HTML, { url: 'https://example.test/', runScripts: 'outside-only' });
  const { window } = dom;
  window.TextEncoder = TextEncoder;
  window.TextDecoder = TextDecoder;
  if (!window.crypto || typeof window.crypto.getRandomValues !== 'function') window.crypto = globalThis.crypto;

  const shadowRoots = [];
  const originalAttachShadow = window.Element.prototype.attachShadow;
  window.Element.prototype.attachShadow = function (init) {
    const root = originalAttachShadow.call(this, init);
    shadowRoots.push({ host: this, root, mode: init && init.mode });
    return root;
  };

  const chromeStub = createChromeStub(options);
  window.chrome = chromeStub.stub;
  window.eval(code);

  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

  /** Sends a message through the *last* registered listener. */
  function send(message) {
    const listener = chromeStub.onMessageListeners[chromeStub.onMessageListeners.length - 1];
    assert.ok(listener, 'the content script registered no message listener');
    return new Promise((resolve) => {
      const keepAlive = listener(message, {}, resolve);
      if (keepAlive !== true) resolve({ __noReply: keepAlive });
    });
  }

  async function waitFor(predicate, { timeout = 10000, step = 8 } = {}) {
    const deadline = Date.now() + timeout;
    while (Date.now() < deadline) {
      if (predicate()) return true;
      await sleep(step);
    }
    throw new Error('timed out waiting for condition');
  }

  // Visibility lives on the `.kb` card inside the shadow root (mount is lazy).
  const overlayOpen = () => {
    const record = shadowRoots[0];
    if (!record) return false;
    const card = record.root.querySelector('.kb');
    return !!card && card.hidden === false;
  };

  return { dom, window, document: window.document, shadowRoots, chromeStub, send, waitFor, sleep, overlayOpen, code, openHotkey };
}

function openHotkey(harness, overrides = {}) {
  harness.window.dispatchEvent(new harness.window.KeyboardEvent('keydown', {
    key: 'k', code: 'KeyK', ctrlKey: true, shiftKey: true, bubbles: true, cancelable: true, ...overrides
  }));
}

test('installing twice is a no-op — one overlay, one listener', { skip }, async () => {
  const harness = await createHarness();
  assert.equal(harness.shadowRoots.length, 1);
  assert.equal(harness.chromeStub.onMessageListeners.length, 1);

  // a page (or a second injection of the same script) running the bundle again
  harness.window.eval(harness.code);
  assert.equal(harness.shadowRoots.length, 1, 'a second copy must not mount a second overlay');
  assert.equal(harness.chromeStub.onMessageListeners.length, 1, 'a second copy must not register a second listener');
  assert.equal(harness.window.__kryptboardInstalled, true);
});

test('messages that are not ours are left alone', { skip }, async () => {
  const harness = await createHarness();
  const listener = harness.chromeStub.onMessageListeners[0];
  const seen = [];
  const result = listener({ type: 'some-other-extension:hello' }, {}, (reply) => seen.push(reply));
  assert.equal(result, undefined, 'foreign messages must not hold the channel open');
  assert.deepEqual(seen, []);
});

test('an unknown kryptboard message answers with an error instead of hanging', { skip }, async () => {
  const harness = await createHarness();
  const reply = await harness.send({ type: 'kryptboard:not-a-real-action' });
  assert.equal(reply.ok, false);
  assert.match(reply.error, /unknown message/);
});

test('ping reports the live overlay state, and open/close/toggle drive it', { skip }, async () => {
  const harness = await createHarness({ session: { 'kryptboard:passphrase': 'pw' }, sync: { 'kryptboard:settings': { startMode: 'plain' } } });

  const closed = await harness.send({ type: 'kryptboard:ping' });
  assert.deepEqual(
    { ok: closed.ok, open: closed.open, mode: closed.mode, hasPassphrase: closed.hasPassphrase, remembered: closed.passphraseRemembered },
    { ok: true, open: false, mode: 'encrypted', hasPassphrase: true, remembered: true }
    // `remembered` is true because the vault loaded it from storage.session
  );

  const opened = await harness.send({ type: 'kryptboard:open' });
  assert.equal(opened.ok, true);
  assert.equal(opened.open, true);
  await harness.waitFor(() => harness.overlayOpen());

  const whileOpen = await harness.send({ type: 'kryptboard:ping' });
  assert.equal(whileOpen.open, true);
  assert.equal(whileOpen.mode, 'plain', 'startMode applies when the overlay opens');

  const toggled = await harness.send({ type: 'kryptboard:toggle' });
  assert.equal(toggled.open, false, 'toggle from the popup closes it again');
  await harness.waitFor(() => !harness.overlayOpen());

  // the hotkey and the popup agree on the same state
  openHotkey(harness);
  await harness.waitFor(() => harness.overlayOpen());
  const afterHotkey = await harness.send({ type: 'kryptboard:ping' });
  assert.equal(afterHotkey.open, true);

  const closedByPopup = await harness.send({ type: 'kryptboard:close' });
  assert.equal(closedByPopup.ok, true);
  assert.equal(closedByPopup.open, false);
  await harness.waitFor(() => !harness.overlayOpen());
});

test('clearing the passphrase from the popup empties the vault and the overlay', { skip }, async () => {
  const harness = await createHarness({ session: { 'kryptboard:passphrase': 'pw' } });
  assert.equal((await harness.send({ type: 'kryptboard:ping' })).hasPassphrase, true);

  assert.equal((await harness.send({ type: 'kryptboard:clear-passphrase' })).ok, true);
  const after = await harness.send({ type: 'kryptboard:ping' });
  assert.equal(after.hasPassphrase, false, 'the vault no longer holds a passphrase');
  assert.equal(harness.chromeStub.maps.session.has('kryptboard:passphrase'), false, 'session storage is cleared too');

  // and the overlay can no longer seal anything
  harness.document.getElementById('msg').dispatchEvent(new harness.window.FocusEvent('focusin', { bubbles: true }));
  openHotkey(harness);
  await harness.waitFor(() => harness.overlayOpen());
  const shadow = harness.shadowRoots[0].root;
  shadow.querySelector('[data-act="char"][data-v="a"]').click();
  shadow.querySelector('[data-act="send"]').click();
  await harness.waitFor(() => /passphrase/i.test(shadow.querySelector('[data-role="status"]').textContent));
  assert.equal(harness.document.getElementById('msg').value, '', 'nothing was committed');
});

test('messages sent before storage finishes loading still get a correct answer', { skip }, async () => {
  // 60 ms of storage latency: the message is sent while `ready` is pending
  const harness = await createHarness({
    session: { 'kryptboard:passphrase': 'pw' },
    getDelayMs: 60
  });
  const reply = await harness.send({ type: 'kryptboard:ping' });
  assert.equal(reply.ok, true);
  assert.equal(reply.hasPassphrase, true, 'the reply must reflect the loaded vault, not an empty one');
  assert.equal(reply.enabled, true);
});

test('a settings change pushed from another tab applies without a reload', { skip }, async () => {
  const harness = await createHarness();
  const sync = harness.chromeStub.stub.storage.sync;

  // another tab edits the settings
  await sync.set({ 'kryptboard:settings': { enabled: false, hotkey: 'Alt+Shift+K' } });

  const disabled = await harness.send({ type: 'kryptboard:ping' });
  assert.equal(disabled.enabled, false);

  // a disabled extension ignores the old hotkey even while the overlay is open
  openHotkey(harness);
  await harness.sleep(20);
  assert.equal(harness.overlayOpen(), false, 'the new settings are live');

  await sync.set({ 'kryptboard:settings': { enabled: true, hotkey: 'Alt+Shift+K' } });
  openHotkey(harness, { ctrlKey: false, altKey: true });
  await harness.waitFor(() => harness.overlayOpen());
  assert.equal((await harness.send({ type: 'kryptboard:ping' })).enabled, true);
});

test('a passphrase written from another tab reaches the overlay', { skip }, async () => {
  const harness = await createHarness();
  harness.document.getElementById('msg').dispatchEvent(new harness.window.FocusEvent('focusin', { bubbles: true }));
  openHotkey(harness);
  await harness.waitFor(() => harness.overlayOpen());
  const shadow = harness.shadowRoots[0].root;

  // sealing is refused while the vault is empty
  shadow.querySelector('[data-act="char"][data-v="h"]').click();
  shadow.querySelector('[data-act="send"]').click();
  await harness.waitFor(() => /passphrase/i.test(shadow.querySelector('[data-role="status"]').textContent));

  // another tab stores a passphrase; the overlay must pick it up live
  await harness.chromeStub.stub.storage.session.set({ 'kryptboard:passphrase': 'from-another-tab' });
  shadow.querySelector('[data-act="send"]').click();
  await harness.waitFor(() => harness.document.getElementById('msg').value.startsWith('v1|'));

  const { kbDecrypt } = await import('../src/crypto.js');
  assert.equal(await kbDecrypt(harness.document.getElementById('msg').value, 'from-another-tab'), 'h');
});

/* ------------------------------------------------------------------ */
/* Single-session key (paper §III)                                     */
/* ------------------------------------------------------------------ */

test('the session key arrives from the popup, is reported, and can be wiped', { skip }, async () => {
  const { kbGenerateSessionKey, kbEncodeSessionKey, kbKeyFingerprint } = await import('../src/crypto.js');
  const harness = await createHarness();

  assert.equal((await harness.send({ type: 'kryptboard:ping' })).hasSessionKey, false);

  const key = kbGenerateSessionKey();
  const shared = kbEncodeSessionKey(key);
  const accepted = await harness.send({ type: 'kryptboard:set-session-key', key: shared });
  assert.equal(accepted.ok, true);
  assert.equal(accepted.fingerprint, kbKeyFingerprint(key));

  const withKey = await harness.send({ type: 'kryptboard:ping' });
  assert.equal(withKey.hasSessionKey, true);
  assert.equal(withKey.sessionKeyFingerprint, kbKeyFingerprint(key));
  assert.equal(withKey.keyModel, 'passphrase', 'the ping reports the key model too');

  assert.equal((await harness.send({ type: 'kryptboard:clear-session-key' })).ok, true);
  const cleared = await harness.send({ type: 'kryptboard:ping' });
  assert.equal(cleared.hasSessionKey, false);
  assert.equal(cleared.sessionKeyFingerprint, '');
});

test('a bad session key is refused with a reason and changes nothing', { skip }, async () => {
  const { kbGenerateSessionKey, kbEncodeSessionKey, kbKeyFingerprint } = await import('../src/crypto.js');
  const harness = await createHarness();
  const key = kbGenerateSessionKey();
  await harness.send({ type: 'kryptboard:set-session-key', key: kbEncodeSessionKey(key) });

  for (const bad of ['', 'not-a-key', 'kbk1.zzzz', 'AAAA']) {
    const reply = await harness.send({ type: 'kryptboard:set-session-key', key: bad });
    assert.equal(reply.ok, false, `"${bad}" must be rejected`);
    assert.ok(reply.error, 'the popup gets an explanation');
  }

  // the original key survived every rejected attempt
  const ping = await harness.send({ type: 'kryptboard:ping' });
  assert.equal(ping.hasSessionKey, true);
  assert.equal(ping.sessionKeyFingerprint, kbKeyFingerprint(key));
});

test('replacing the session key swaps the fingerprint immediately', { skip }, async () => {
  const { kbGenerateSessionKey, kbEncodeSessionKey, kbKeyFingerprint } = await import('../src/crypto.js');
  const harness = await createHarness();
  const first = kbGenerateSessionKey();
  const second = kbGenerateSessionKey();

  await harness.send({ type: 'kryptboard:set-session-key', key: kbEncodeSessionKey(first) });
  assert.equal((await harness.send({ type: 'kryptboard:ping' })).sessionKeyFingerprint, kbKeyFingerprint(first));
  await harness.send({ type: 'kryptboard:set-session-key', key: kbEncodeSessionKey(second) });

  const ping = await harness.send({ type: 'kryptboard:ping' });
  assert.equal(ping.sessionKeyFingerprint, kbKeyFingerprint(second));
  assert.notEqual(ping.sessionKeyFingerprint, kbKeyFingerprint(first));
});

test('the session key is never written to extension storage', { skip }, async () => {
  const { kbGenerateSessionKey, kbEncodeSessionKey } = await import('../src/crypto.js');
  const harness = await createHarness();
  await harness.send({ type: 'kryptboard:set-session-key', key: kbEncodeSessionKey(kbGenerateSessionKey()) });

  const written = [...harness.chromeStub.maps.sync.values(), ...harness.chromeStub.maps.session.values()];
  for (const value of written) {
    assert.equal(typeof value === 'string' && value.startsWith('kbk1.'), false, 'the key must stay in memory');
  }
  assert.equal(harness.chromeStub.maps.sync.size + harness.chromeStub.maps.session.size, 0, 'nothing was persisted at all');
});

test('the toolbar switch drives the live mode and sticks for the next page', { skip }, async () => {
  const harness = await createHarness();
  harness.document.getElementById('msg').dispatchEvent(new harness.window.FocusEvent('focusin', { bubbles: true }));

  const toPlain = await harness.send({ type: 'kryptboard:set-mode', mode: 'plain' });
  assert.deepEqual({ ok: toPlain.ok, mode: toPlain.mode }, { ok: true, mode: 'plain' });
  assert.equal((await harness.send({ type: 'kryptboard:ping' })).mode, 'plain');

  // plain mode commits keystrokes straight into the field
  openHotkey(harness);
  await harness.waitFor(() => harness.overlayOpen());
  const shadow = harness.shadowRoots[0].root;
  shadow.querySelector('[data-act="char"][data-v="p"]').click();
  assert.equal(harness.document.getElementById('msg').value, 'p');

  const toEncrypted = await harness.send({ type: 'kryptboard:set-mode', mode: 'encrypted' });
  assert.equal(toEncrypted.mode, 'encrypted');
  assert.equal((await harness.send({ type: 'kryptboard:ping' })).mode, 'encrypted');

  // the choice is remembered as the default for the next page
  assert.equal(harness.chromeStub.maps.sync.get('kryptboard:settings').startMode, 'encrypted');

  // an unknown mode value falls back to encrypted rather than doing nothing
  const weird = await harness.send({ type: 'kryptboard:set-mode', mode: 'nonsense' });
  assert.equal(weird.mode, 'encrypted');
});
