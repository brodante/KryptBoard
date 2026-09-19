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

async function bootPopup(options = {}) {
  const html = await fs.readFile(path.join(ROOT, 'src/popup.html'), 'utf8');
  const dom = new JSDOM(html, { url: 'chrome-extension://kryptboard-test/src/popup.html', runScripts: 'outside-only' });
  const { window } = dom;

  const sync = new Map(Object.entries(options.initialSettings || {}).map(([k, v]) => [k, v]));
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
      query: options.queryTabs || (async () => [{ id: 7, url: 'https://example.test/' }]),
      sendMessage: async (tabId, message) => {
        messages.push({ tabId, message });
        if (options.sendMessage) return options.sendMessage(tabId, message);
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

  const waitFor = async (predicate, timeout = 10000) => {
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
    async restore() {
      // let the popup's deferred refreshes (120 ms) run while the stub is
      // still installed, so they cannot fire after teardown
      await new Promise((resolve) => setTimeout(resolve, 140));
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
    await popup.restore();
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
    await popup.restore();
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
    await popup.restore();
  }
});

test('the page controls drive the active tab and surface blocked pages', { skip }, async () => {
  const popup = await bootPopup();
  try {
    await popup.waitFor(() => popup.document.getElementById('page-status').textContent.length > 0);
    popup.messages.length = 0;

    popup.document.getElementById('toggle').click();
    assert.ok(await popup.waitFor(() => popup.messages.some((entry) => entry.message.type === 'kryptboard:toggle')));
    assert.equal(popup.messages[0].tabId, 7);
    assert.ok(await popup.waitFor(() => /Keyboard opened|Keyboard hidden/.test(popup.document.getElementById('page-status').textContent)));

    popup.document.getElementById('clear-pass').click();
    assert.ok(await popup.waitFor(() => popup.messages.some((entry) => entry.message.type === 'kryptboard:clear-passphrase')));
    assert.match(popup.document.getElementById('page-status').textContent, /Passphrase cleared/);
  } finally {
    await popup.restore();
  }
});

test('a page that cannot be reached is explained instead of failing silently', { skip }, async () => {
  const popup = await bootPopup({
    sendMessage: async () => {
      throw new Error('Could not establish connection');
    }
  });
  try {
    assert.ok(await popup.waitFor(() => popup.document.getElementById('toggle').disabled === true));
    assert.match(popup.document.getElementById('page-status').textContent, /does not allow extensions/);
    assert.match(popup.document.getElementById('page-hint').textContent, /normal website/);
  } finally {
    await popup.restore();
  }
});

test('with no active tab the popup says so and disables the page controls', { skip }, async () => {
  const popup = await bootPopup({ queryTabs: async () => [] });
  try {
    assert.ok(await popup.waitFor(() => /No active tab/.test(popup.document.getElementById('page-status').textContent)));
    assert.equal(popup.document.getElementById('toggle').disabled, true);
  } finally {
    await popup.restore();
  }
});

test('tabs switch panels', { skip }, async () => {
  const popup = await bootPopup();
  try {
    await popup.waitFor(() => popup.document.getElementById('page-status').textContent.length > 0);
    const tabs = [...popup.document.querySelectorAll('.tab')];
    const panels = [...popup.document.querySelectorAll('.tabpanel')];
    assert.ok(tabs.length >= 2, 'the popup has several panels');
    assert.equal(tabs.length, panels.length, 'every tab has a panel');
    assert.equal(panels.filter((p) => !p.hidden).length, 1, 'exactly one panel is visible');

    for (const tab of tabs) {
      tab.click();
      assert.equal(tab.classList.contains('is-active'), true);
      const visible = panels.filter((p) => !p.hidden);
      assert.equal(visible.length, 1);
      assert.equal(visible[0].dataset.panel, tab.dataset.tab);
      assert.equal(panels.filter((p) => p.classList.contains('is-active')).length, 0, 'panels are toggled with hidden, not with a class');
    }
  } finally {
    await popup.restore();
  }
});

test('a hotkey that is not a preset is still offered and kept', { skip }, async () => {
  const popup = await bootPopup({ initialSettings: { 'kryptboard:settings': { hotkey: 'Ctrl+Alt+J' } } });
  try {
    await popup.waitFor(() => popup.document.getElementById('page-status').textContent.length > 0);
    const select = popup.document.getElementById('set-hotkey');
    assert.equal(select.value, 'Ctrl+Alt+J');
    const option = [...select.options].find((o) => o.value === 'Ctrl+Alt+J');
    assert.ok(option, 'the custom hotkey is appended to the dropdown');
    assert.equal([...select.options].filter((o) => o.value === 'Ctrl+Alt+J').length, 1, 'it is not duplicated');
  } finally {
    await popup.restore();
  }
});

test('the composer uses the configured KDF hardening and context label', { skip }, async () => {
  const popup = await bootPopup();
  try {
    await popup.waitFor(() => popup.document.getElementById('page-status').textContent.length > 0);

    // turn on hardening and set an AAD
    const hardened = popup.document.getElementById('set-hardenedKdf');
    hardened.checked = true;
    hardened.dispatchEvent(new popup.window.Event('change', { bubbles: true }));
    await popup.waitFor(() => popup.sync.get('kryptboard:settings')?.hardenedKdf === true);

    const iterations = popup.document.getElementById('set-pbkdf2Iterations');
    await popup.waitFor(() => iterations.disabled === false);
    iterations.value = '5000';
    iterations.dispatchEvent(new popup.window.Event('change', { bubbles: true }));
    await popup.waitFor(() => popup.sync.get('kryptboard:settings')?.pbkdf2Iterations === 5000);

    const aad = popup.document.getElementById('set-aad');
    aad.value = 'room-1';
    aad.dispatchEvent(new popup.window.Event('change', { bubbles: true }));
    await popup.waitFor(() => popup.sync.get('kryptboard:settings')?.aad === 'room-1');

    popup.document.getElementById('enc-plain').value = 'hardened message';
    popup.document.getElementById('enc-pass').value = 'pw';
    popup.document.getElementById('enc-run').click();
    assert.ok(await popup.waitFor(() => popup.document.getElementById('enc-out').value.startsWith('v1|')));
    const envelope = popup.document.getElementById('enc-out').value;
    assert.match(envelope, /CHACHA20-POLY1305\+PBKDF2-5000/, 'the envelope records the work factor');

    // same context label → readable
    popup.document.getElementById('dec-env').value = envelope;
    popup.document.getElementById('dec-pass').value = 'pw';
    popup.document.getElementById('dec-run').click();
    assert.ok(await popup.waitFor(() => popup.document.getElementById('dec-out').value === 'hardened message'));

    // different context label → authentication failure, never plaintext
    aad.value = 'room-2';
    aad.dispatchEvent(new popup.window.Event('change', { bubbles: true }));
    await popup.waitFor(() => popup.sync.get('kryptboard:settings')?.aad === 'room-2');
    popup.document.getElementById('dec-env').value = envelope;
    popup.document.getElementById('dec-run').click();
    assert.ok(await popup.waitFor(() => /Authentication failed/.test(popup.document.getElementById('dec-meta').textContent)));
    assert.equal(popup.document.getElementById('dec-out').value, '');
  } finally {
    await popup.restore();
  }
});

test('copying without a clipboard API falls back to selecting the envelope', { skip }, async () => {
  const popup = await bootPopup();
  try {
    await popup.waitFor(() => popup.document.getElementById('page-status').textContent.length > 0);

    popup.document.getElementById('enc-plain').value = 'copy me';
    popup.document.getElementById('enc-pass').value = 'pw';
    popup.document.getElementById('enc-run').click();
    assert.ok(await popup.waitFor(() => popup.document.getElementById('enc-out').value.startsWith('v1|')));

    const out = popup.document.getElementById('enc-out');
    popup.document.getElementById('enc-copy').click();
    await new Promise((resolve) => setTimeout(resolve, 20));
    assert.equal(out.selectionStart, 0);
    assert.equal(out.selectionEnd, out.value.length, 'the fallback selects the whole envelope');
  } finally {
    await popup.restore();
  }
});
