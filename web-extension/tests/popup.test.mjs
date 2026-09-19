/**
 * The popup, booted for real.
 *
 * `src/popup.js` runs as an extension page, so it is loaded here with jsdom
 * globals and a stubbed chrome API. This catches what the static id check
 * cannot: a popup that throws while booting, a composer that never fills its
 * output, or a settings form that saves something other than what is shown.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

let JSDOM = null;
try {
  ({ JSDOM } = await import('jsdom'));
} catch (error) {
  JSDOM = null;
}
const skip = JSDOM ? false : 'jsdom is not installed (run: npm install)';

/** Installs globals, boots the popup once and returns handles for assertions. */
async function bootPopup(options = {}) {
  const html = await fs.readFile(path.join(ROOT, 'src/popup.html'), 'utf8');
  const dom = new JSDOM(html, { url: 'chrome-extension://kryptboard/src/popup.html' });
  const sync = new Map(Object.entries(options.sync || {}));
  const session = new Map(Object.entries(options.session || {}));
  const messages = [];

  globalThis.window = dom.window;
  globalThis.document = dom.window.document;
  globalThis.chrome = {
    runtime: options.runtimeBroken ? {} : { getManifest: () => ({ version: '1.0.0' }) },
    storage: {
      sync: {
        async get(key) {
          const keys = typeof key === 'string' ? [key] : Object.keys(key || {});
          const out = {};
          for (const k of keys) if (sync.has(k)) out[k] = sync.get(k);
          return out;
        },
        async set(items) {
          for (const [k, v] of Object.entries(items)) sync.set(k, v);
        },
        async remove(key) {
          for (const k of [].concat(key)) sync.delete(k);
        }
      },
      session: {
        async get(key) {
          const keys = typeof key === 'string' ? [key] : Object.keys(key || {});
          const out = {};
          for (const k of keys) if (session.has(k)) out[k] = session.get(k);
          return out;
        },
        async set(items) {
          for (const [k, v] of Object.entries(items)) session.set(k, v);
        },
        async remove(key) {
          for (const k of [].concat(key)) session.delete(k);
        }
      },
      onChanged: { addListener() {} }
    },
    tabs: {
      async query() {
        return options.tabs === undefined ? [{ id: 1, url: 'https://example.test/' }] : options.tabs;
      },
      async sendMessage(tabId, message) {
        messages.push({ tabId, message });
        if (options.sendMessageThrows) throw new Error('no content script');
        if (message.type === 'kryptboard:ping') {
          return { ok: true, open: false, mode: 'encrypted', hotkey: 'Ctrl+Shift+K', hasTarget: true, target: 'textarea', hasPassphrase: false };
        }
        return { ok: true };
      }
    }
  };

  await import(`../src/popup.js?boot=${options.tag || 'default'}`);
  return { window: dom.window, document: dom.window.document, sync, session, messages };
}

/** Popup work is async; poll for the condition instead of guessing a delay. */
async function waitFor(predicate, timeout = 3000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    try {
      if (predicate()) return true;
    } catch (e) {
      /* the element may not exist yet */
    }
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error('popup did not reach the expected state');
}

test('the popup boots, fills its controls and reports the page status', { skip }, async () => {
  const popup = await bootPopup();
  const $ = (id) => popup.document.getElementById(id);

  await waitFor(() => $('page-status').textContent.length > 0);
  assert.match($('page-status').textContent, /hidden|open/i);
  assert.match($('version').textContent, /ChaCha20-Poly1305/);

  // the "0 network calls" privacy claim the UI makes
  assert.match(popup.document.body.textContent, /0 network calls/i);

  // defaults are rendered into the form
  assert.equal($('set-theme').value, 'dark');
  assert.equal($('set-startMode').value, 'encrypted');
  assert.equal($('set-enabled').checked, true);
  assert.equal($('set-hotkey').value, 'Ctrl+Shift+K', 'the stored hotkey is selected');
  assert.equal($('set-pbkdf2Iterations').disabled, true, 'iterations are inert until hardening is on');
});

test('the isolated composer seals a message and verifies it again', { skip }, async () => {
  const popup = await bootPopup({ tag: 'composer' });
  const $ = (id) => popup.document.getElementById(id);
  await waitFor(() => $('page-status').textContent.length > 0);

  $('enc-plain').value = 'panel secret';
  $('enc-pass').value = 'panel-passphrase';
  $('enc-run').click();
  await waitFor(() => $('enc-out').value.startsWith('v1|'));
  assert.match($('enc-out').value, /^v1\|CHACHA20-POLY1305\|/);
  assert.match($('enc-meta').textContent, /plaintext → \d+ B envelope/);

  $('dec-env').value = $('enc-out').value;
  $('dec-pass').value = 'panel-passphrase';
  $('dec-run').click();
  await waitFor(() => $('dec-out').value.length > 0);
  assert.equal($('dec-out').value, 'panel secret');
  assert.match($('dec-meta').textContent, /verified|recovered/i);

  // a wrong passphrase fails loudly and never shows plaintext
  $('dec-pass').value = 'wrong';
  $('dec-run').click();
  await waitFor(() => /failure|wrong passphrase|altered/i.test($('dec-meta').textContent));
  assert.equal($('dec-out').value, '');
});

test('changing a setting persists it and tells the page', { skip }, async () => {
  const popup = await bootPopup({ tag: 'settings' });
  const $ = (id) => popup.document.getElementById(id);
  await waitFor(() => $('page-status').textContent.length > 0);
  popup.messages.length = 0;

  const theme = $('set-theme');
  theme.value = 'light';
  theme.dispatchEvent(new popup.window.Event('change', { bubbles: true }));
  await waitFor(() => popup.sync.get('kryptboard:settings')?.theme === 'light');
  assert.equal(popup.sync.get('kryptboard:settings').theme, 'light');

  // the content script is told to re-read its settings
  await waitFor(() => popup.messages.some((m) => m.message.type === 'kryptboard:settings-changed'));
  assert.equal(popup.messages.find((m) => m.message.type === 'kryptboard:settings-changed').tabId, 1);
  // enabling KDF hardening enables the iteration field and is persisted
  const hardened = $('set-hardenedKdf');
  hardened.checked = true;
  hardened.dispatchEvent(new popup.window.Event('change', { bubbles: true }));
  await waitFor(() => popup.sync.get('kryptboard:settings')?.hardenedKdf === true);
  assert.equal($('set-pbkdf2Iterations').disabled, false);

  // reset restores the defaults (assert on the rendered form — every store
  // write is followed by a re-render, so waiting on storage alone would race)
  $('reset').click();
  await waitFor(() => $('set-theme').value === 'dark');
  assert.equal(popup.sync.get('kryptboard:settings').theme, 'dark');
  assert.equal($('set-hardenedKdf').checked, false);
  assert.equal($('set-pbkdf2Iterations').disabled, true);
  assert.equal($('set-startMode').value, 'encrypted');
});

test('the popup survives having no tabs to talk to', { skip }, async () => {
  const popup = await bootPopup({ tag: 'notabs', tabs: [] });
  const $ = (id) => popup.document.getElementById(id);
  await waitFor(() => /No active tab/.test($('page-status').textContent));
  assert.equal($('toggle').disabled, true, 'there is nothing to toggle on');
});

test('a page without the content script is reported instead of crashing', { skip }, async () => {
  const popup = await bootPopup({ tag: 'blocked', sendMessageThrows: true });
  const $ = (id) => popup.document.getElementById(id);
  await waitFor(() => /Cannot reach|allow extensions/i.test($('page-status').textContent));
  assert.equal($('toggle').disabled, true);
});

test('a broken runtime is surfaced in the popup instead of a blank panel', { skip }, async () => {
  const popup = await bootPopup({ tag: 'broken', runtimeBroken: true });
  const $ = (id) => popup.document.getElementById(id);
  await waitFor(() => /failed to start/i.test($('page-status').textContent));
  assert.match($('page-status').textContent, /getManifest/);
});

/* ------------------------------------------------------------------ */
/* Session key model (paper §III / Algorithm 1)                        */
/* ------------------------------------------------------------------ */

test('generating a session key stores it, shows the fingerprint and tells the page', { skip }, async () => {
  const popup = await bootPopup({ tag: 'session-generate' });
  const $ = (id) => popup.document.getElementById(id);
  await waitFor(() => $('page-status').textContent.length > 0);
  assert.match($('session-key-state').textContent, /No session key/);

  popup.messages.length = 0;
  $('session-generate').click();
  await waitFor(() => /Session key ready/.test($('session-key-state').textContent));

  const stored = popup.session.get('kryptboard:session-key');
  assert.match(stored, /^kbk1\.[A-Za-z0-9_-]{43}$/, 'the key is kept in storage.session only');
  assert.match($('session-key-state').textContent, /[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}/);

  // the page is handed the key so the overlay can seal with it
  await waitFor(() => popup.messages.some((m) => m.message.type === 'kryptboard:set-session-key'));
  const handed = popup.messages.find((m) => m.message.type === 'kryptboard:set-session-key');
  assert.equal(handed.tabId, 1);
  assert.equal(handed.message.key, stored, 'the sharing string is what travels');

  // and it is not written anywhere else
  assert.equal(popup.sync.has('kryptboard:session-key'), false, 'never in sync storage');
});

test('a key can be imported, and a bad one is refused with a message', { skip }, async () => {
  const popup = await bootPopup({ tag: 'session-import' });
  const $ = (id) => popup.document.getElementById(id);
  await waitFor(() => $('page-status').textContent.length > 0);

  $('session-import').value = 'this is not a key';
  $('session-import').dispatchEvent(new popup.window.Event('change', { bubbles: true }));
  await waitFor(() => /does not look like/.test($('session-key-state').textContent));
  assert.equal(popup.session.has('kryptboard:session-key'), false);

  // the other side's key, as a sharing string
  const { kbGenerateSessionKey, kbEncodeSessionKey, kbKeyFingerprint } = await import('../src/crypto.js');
  const theirs = kbGenerateSessionKey();
  $('session-import').value = kbEncodeSessionKey(theirs);
  $('session-import').dispatchEvent(new popup.window.Event('change', { bubbles: true }));
  await waitFor(() => /Session key ready/.test($('session-key-state').textContent));
  assert.match($('session-key-state').textContent, new RegExp(kbKeyFingerprint(theirs)));
  assert.equal($('session-import').value, '', 'the field is cleared after importing');

  // forgetting wipes both the vault and the page's copy
  popup.messages.length = 0;
  $('session-clear').click();
  await waitFor(() => /No session key/.test($('session-key-state').textContent));
  assert.equal(popup.session.has('kryptboard:session-key'), false);
  await waitFor(() => popup.messages.some((m) => m.message.type === 'kryptboard:clear-session-key'));
});

test('the composer produces Algorithm 1 dictionaries with a session key', { skip }, async () => {
  const { kbGenerateSessionKey, kbEncodeSessionKey, kbDecryptFromDict, kbDecryptWithKey } = await import('../src/crypto.js');
  const key = kbGenerateSessionKey();

  const popup = await bootPopup({
    tag: 'session-compose',
    sync: { 'kryptboard:settings': { keyModel: 'session', sessionFormat: 'json' } },
    session: { 'kryptboard:session-key': kbEncodeSessionKey(key) }
  });
  const $ = (id) => popup.document.getElementById(id);
  await waitFor(() => /Session key ready/.test($('session-key-state').textContent));

  $('enc-plain').value = 'paper algorithm one';
  $('enc-run').click();
  await waitFor(() => $('enc-out').value.startsWith('{'));
  const dict = JSON.parse($('enc-out').value);
  assert.deepEqual(Object.keys(dict).sort(), ['ciphertext', 'nonce', 'tag']);
  assert.equal(kbDecryptFromDict(dict, key), 'paper algorithm one');
  assert.match($('enc-meta').textContent, /session dictionary/);

  // decrypting the dictionary again needs no passphrase at all
  $('dec-env').value = $('enc-out').value;
  $('dec-run').click();
  await waitFor(() => $('dec-out').value.length > 0);
  assert.equal($('dec-out').value, 'paper algorithm one');

  // the same settings with the envelope format
  const envelopePopup = await bootPopup({
    tag: 'session-envelope',
    sync: { 'kryptboard:settings': { keyModel: 'session', sessionFormat: 'envelope' } },
    session: { 'kryptboard:session-key': kbEncodeSessionKey(key) }
  });
  const $$ = (id) => envelopePopup.document.getElementById(id);
  await waitFor(() => /Session key ready/.test($$('session-key-state').textContent));
  $$('enc-plain').value = 'envelope form';
  $$('enc-run').click();
  await waitFor(() => $$('enc-out').value.startsWith('v1|'));
  assert.match($$('enc-out').value, /^v1\|CHACHA20-POLY1305\+SESSIONKEY\|/);
  assert.equal(kbDecryptWithKey($$('enc-out').value, key), 'envelope form');
});

test('session mode without a key asks for one instead of guessing', { skip }, async () => {
  const popup = await bootPopup({
    tag: 'session-missing',
    sync: { 'kryptboard:settings': { keyModel: 'session' } }
  });
  const $ = (id) => popup.document.getElementById(id);
  await waitFor(() => $('page-status').textContent.length > 0);

  $('enc-plain').value = 'no key here';
  $('enc-run').click();
  await waitFor(() => /Generate or import a session key/.test($('enc-meta').textContent));
  assert.equal($('enc-out').value, '');

  $('dec-env').value = '{"nonce":"AAECAwQFBgcICQoL","ciphertext":"AAAA","tag":"AAAAAAAAAAAAAAAAAAAAAA=="}';
  $('dec-run').click();
  await waitFor(() => /needs the session key/.test($('dec-meta').textContent));
  assert.equal($('dec-out').value, '');
});

test('the session-output field only shows for the session key model', { skip }, async () => {
  const popup = await bootPopup({ tag: 'session-field' });
  const $ = (id) => popup.document.getElementById(id);
  await waitFor(() => $('page-status').textContent.length > 0);

  assert.equal($('session-format-field').hidden, true, 'hidden while passphrases are the model');
  $('set-keyModel').value = 'session';
  $('set-keyModel').dispatchEvent(new popup.window.Event('change', { bubbles: true }));
  await waitFor(() => $('session-format-field').hidden === false);
  await waitFor(() => popup.sync.get('kryptboard:settings')?.keyModel === 'session');
});
