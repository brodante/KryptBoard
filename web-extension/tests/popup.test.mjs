/**
 * Popup smoke + flow tests.
 *
 * The popup is a real extension page, so it runs `src/popup.js` as an ES module
 * against a jsdom document and a stubbed chrome API. This catches the failure
 * mode the static id check cannot: a control that exists but blows up when the
 * script boots, or a composer that does not actually seal/verify.
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

async function bootPopup() {
  const html = await fs.readFile(path.join(ROOT, 'src/popup.html'), 'utf8');
  const dom = new JSDOM(html, { url: 'chrome-extension://kryptboard-test/src/popup.html', runScripts: 'outside-only' });
  const { window } = dom;

  const sync = new Map();
  const syncArea = {
    async get(keys) {
      const out = {};
      for (const key of typeof keys === 'string' ? [keys] : Object.keys(keys || {})) {
        if (sync.has(key)) out[key] = sync.get(key);
      }
      return out;
    },
    async set(items) {
      for (const [key, value] of Object.entries(items)) sync.set(key, value);
    },
    async remove(keys) {
      for (const key of [].concat(keys)) sync.delete(key);
    }
  };

  const messages = [];
  const chromeStub = {
    storage: { sync: syncArea, onChanged: { addListener() {} } },
    runtime: { getManifest: () => ({ version: '1.0.0' }) },
    tabs: {
      query: async () => [{ id: 7, url: 'https://example.test/' }],
      sendMessage: async (tabId, message) => {
        messages.push({ tabId, message });
        if (message.type === 'kryptboard:ping') {
          return { ok: true, open: false, mode: 'encrypted', hotkey: 'Ctrl+Shift+K', hasTarget: true, target: 'textarea', hasPassphrase: false };
        }
        return { ok: true };
      }
    }
  };

  // `navigator` is getter-only in modern Node, so it is left alone: the popup
  // treats a missing clipboard API as "fall back to selecting the text".
  const previous = {
    window: globalThis.window,
    document: globalThis.document,
    chrome: globalThis.chrome
  };
  globalThis.window = window;
  globalThis.document = window.document;
  globalThis.chrome = chromeStub;

  await import(`../src/popup.js?boot=${Date.now()}`);

  const waitFor = async (predicate, timeout = 2000) => {
    const deadline = Date.now() + timeout;
    await new Promise((resolve) => setTimeout(resolve, 0));
    while (Date.now() < deadline) {
      if (predicate()) return true;
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    return false;
  };

  return {
    window,
    document: window.document,
    messages,
    sync,
    waitFor,
    restore() {
      for (const [key, value] of Object.entries(previous)) {
        if (value === undefined) delete globalThis[key];
        else globalThis[key] = value;
      }
    }
  };
}

test('the popup boots, fills its forms and reports the tab status', { skip }, async () => {
  const popup = await bootPopup();
  try {
    assert.ok(await popup.waitFor(() => popup.document.getElementById('page-status').textContent.length > 0));

    assert.match(popup.document.getElementById('page-status').textContent, /hidden on this page/i);
    assert.match(popup.document.getElementById('page-hint').textContent, /Hotkey: Ctrl\+Shift\+K/);
    assert.match(popup.document.getElementById('version').textContent, /^v1\.0\.0 · ChaCha20-Poly1305/);

    // defaults are rendered into the controls
    assert.equal(popup.document.getElementById('set-startMode').value, 'encrypted');
    assert.equal(popup.document.getElementById('set-theme').value, 'dark');
    assert.equal(popup.document.getElementById('set-enabled').checked, true);
    assert.equal(popup.document.getElementById('set-ignorePasswordFields').checked, true);
    assert.equal(popup.document.getElementById('set-hardenedKdf').checked, false);
    assert.equal(popup.document.getElementById('set-pbkdf2Iterations').disabled, true, 'iterations are inert until hardening is on');

    // an empty message is refused with a hint, not a crash
    popup.document.getElementById('enc-run').click();
    await popup.waitFor(() => /Enter a message/.test(popup.document.getElementById('enc-meta').textContent));
  } finally {
    popup.restore();
  }
});

test('the popup composer seals and re-opens a message', { skip }, async () => {
  const popup = await bootPopup();
  try {
    await popup.waitFor(() => popup.document.getElementById('page-status').textContent.length > 0);

    // encrypt
    popup.document.getElementById('enc-plain').value = 'isolated composer message';
    popup.document.getElementById('enc-pass').value = 'popup-passphrase';
    popup.document.getElementById('enc-run').click();
    assert.ok(await popup.waitFor(() => popup.document.getElementById('enc-out').value.startsWith('v1|')));

    const envelope = popup.document.getElementById('enc-out').value;
    assert.match(envelope, /^v1\|CHACHA20-POLY1305\|/);
    assert.equal(envelope.includes('isolated composer'), false);
    assert.match(popup.document.getElementById('enc-meta').textContent, /plaintext → \d+ B envelope in/);

    // decrypt it again
    popup.document.getElementById('dec-env').value = envelope;
    popup.document.getElementById('dec-pass').value = 'popup-passphrase';
    popup.document.getElementById('dec-run').click();
    assert.ok(await popup.waitFor(() => popup.document.getElementById('dec-out').value.length > 0));
    assert.equal(popup.document.getElementById('dec-out').value, 'isolated composer message');
    assert.match(popup.document.getElementById('dec-meta').textContent, /Tag verified/);

    // a wrong passphrase must clear the output and say why
    popup.document.getElementById('dec-pass').value = 'wrong';
    popup.document.getElementById('dec-run').click();
    assert.ok(await popup.waitFor(() => /Authentication failed/.test(popup.document.getElementById('dec-meta').textContent)));
    assert.equal(popup.document.getElementById('dec-out').value, '');
  } finally {
    popup.restore();
  }
});

test('changing a setting in the popup persists it and notifies the page', { skip }, async () => {
  const popup = await bootPopup();
  try {
    await popup.waitFor(() => popup.document.getElementById('page-status').textContent.length > 0);
    popup.messages.length = 0;

    const theme = popup.document.getElementById('set-theme');
    theme.value = 'light';
    theme.dispatchEvent(new popup.window.Event('change', { bubbles: true }));
    await popup.waitFor(() => popup.sync.get('kryptboard:settings')?.theme === 'light');
    const saved = popup.sync.get('kryptboard:settings');
    assert.equal(saved.theme, 'light');
    await popup.waitFor(() => popup.messages.some((entry) => entry.message.type === 'kryptboard:settings-changed'));
    assert.equal(popup.messages.find((entry) => entry.message.type === 'kryptboard:settings-changed').tabId, 7);

    // hardening turns the iteration control on
    const hardened = popup.document.getElementById('set-hardenedKdf');
    hardened.checked = true;
    hardened.dispatchEvent(new popup.window.Event('change', { bubbles: true }));
    await popup.waitFor(() => popup.document.getElementById('set-pbkdf2Iterations').disabled === false);
    assert.equal(popup.sync.get('kryptboard:settings').hardenedKdf, true);

    // and the restored defaults come back
    popup.document.getElementById('reset').click();
    await popup.waitFor(() => popup.document.getElementById('set-theme').value === 'dark');
    assert.equal(popup.sync.get('kryptboard:settings').theme, 'dark');
    assert.equal(popup.document.getElementById('set-startMode').value, 'encrypted');
    assert.equal(popup.document.getElementById('set-hardenedKdf').checked, false);
  } finally {
    popup.restore();
  }
});
