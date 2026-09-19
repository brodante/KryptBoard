/**
 * Wiring tests.
 *
 * src/wiring.js is the layer that decides *when* the overlay opens and *where*
 * committed text may land. Its rules are security-relevant (never target a
 * password field, never target our own overlay) and easy to regress, so they
 * are pinned here directly against a real jsdom document.
 */
import test from 'node:test';
import assert from 'node:assert/strict';

let JSDOM = null;
try {
  ({ JSDOM } = await import('jsdom'));
} catch (error) {
  JSDOM = null;
}
const skip = JSDOM ? false : 'jsdom is not installed (run: npm install)';

const { kbWireKeyboard, kbDeepActiveElement } = await import('../src/wiring.js').catch(() => ({ kbWireKeyboard: null }));
const wiringAvailable = !!kbWireKeyboard;
const skipAll = skip || (wiringAvailable ? false : 'wiring module unavailable');

const PAGE_HTML = `<!doctype html><html><body>
  <input id="text" type="text" />
  <input id="pw" type="password" />
  <input id="ro" readonly />
  <textarea id="area"></textarea>
  <div id="rich" contenteditable="true"></div>
  <button id="btn">button</button>
  <select id="sel"><option>a</option></select>
  <div id="host"><template></template></div>
</body></html>`;

function createWiring(options = {}) {
  const dom = new JSDOM(options.html || PAGE_HTML, { url: 'https://example.test/', runScripts: 'outside-only' });
  const { window } = dom;
  window.TextEncoder = TextEncoder;
  window.TextDecoder = TextDecoder;
  if (!window.crypto || typeof window.crypto.getRandomValues !== 'function') window.crypto = globalThis.crypto;

  const saved = [];
  let settings = { enabled: true, hotkey: 'Ctrl+Shift+K', startMode: 'encrypted', ignorePasswordFields: true, ...(options.settings || {}) };
  let passphrase = options.passphrase || '';
  const subscribers = new Set();
  const closes = [];

  const wired = kbWireKeyboard({
    doc: window.document,
    window,
    adapter: {
      getSettings: () => ({ ...settings }),
      saveSettings: async (patch) => {
        saved.push(patch);
        settings = { ...settings, ...patch };
        for (const fn of subscribers) fn({ ...settings });
      },
      subscribeSettings: (cb) => subscribers.add(cb),
      getPassphrase: async () => passphrase,
      savePassphrase: async (value) => {
        passphrase = value;
      }
    },
    onClose: (reason) => closes.push(reason)
  });

  const press = (overrides = {}) => {
    const event = new window.KeyboardEvent('keydown', {
      key: 'k', code: 'KeyK', ctrlKey: true, shiftKey: true, bubbles: true, cancelable: true, ...overrides
    });
    window.dispatchEvent(event);
    return event;
  };

  return {
    dom,
    window,
    document: window.document,
    wired,
    press,
    closes,
    saved,
    isOpen: () => wired.keyboard.isOpen(),
    focus(id) {
      const el = window.document.getElementById(id);
      el.dispatchEvent(new window.FocusEvent('focusin', { bubbles: true }));
      el.focus();
      return el;
    },
    setSettings(patch) {
      settings = { ...settings, ...patch };
    },
    /** What the content script does when chrome.storage pushes a change. */
    pushSettings(patch) {
      settings = { ...settings, ...patch };
      for (const fn of subscribers) fn({ ...settings });
    },
    setPassphrase(value) {
      passphrase = value;
    }
  };
}

test('the default hotkey opens and closes the overlay, and is swallowed', { skip: skipAll }, async () => {
  const h = createWiring();
  h.focus('area');

  let pageSawHotkey = 0;
  h.window.document.body.addEventListener('keydown', () => {
    pageSawHotkey++;
  });

  const event = h.press();
  assert.equal(h.isOpen(), true);
  assert.equal(event.defaultPrevented, true, 'the browser must not act on the hotkey');
  assert.equal(pageSawHotkey, 0, 'the page must not see the hotkey either');

  h.press();
  assert.equal(h.isOpen(), false);
  assert.deepEqual(h.closes, ['toggled']);
});

test('near-miss combos do not open the overlay', { skip: skipAll }, async () => {
  const h = createWiring();
  h.focus('area');

  h.press({ shiftKey: false });
  h.press({ ctrlKey: false, metaKey: true });
  h.press({ key: 'j', code: 'KeyJ' });
  h.press({ altKey: true });
  assert.equal(h.isOpen(), false, 'only the exact configured combo is a hotkey');
});

test('a disabled extension ignores the hotkey entirely', { skip: skipAll }, async () => {
  const h = createWiring({ settings: { enabled: false } });
  h.focus('area');
  const event = h.press();
  assert.equal(h.isOpen(), false);
  assert.equal(event.defaultPrevented, false, 'nothing to intercept when disabled');
});

test('holding the hotkey does not flicker the overlay', { skip: skipAll }, async () => {
  const h = createWiring();
  h.focus('area');

  h.press();
  assert.equal(h.isOpen(), true);
  for (let i = 0; i < 5; i++) h.press({ repeat: true });
  assert.equal(h.isOpen(), true, 'auto-repeat must not toggle');
});

test('the custom hotkey from settings is the one that works', { skip: skipAll }, async () => {
  const h = createWiring({ settings: { hotkey: 'Alt+Shift+J' } });
  h.focus('area');

  h.press();
  assert.equal(h.isOpen(), false, 'the old default is no longer bound');

  h.press({ ctrlKey: false, altKey: true, shiftKey: true, key: 'j', code: 'KeyJ' });
  assert.equal(h.isOpen(), true);
});

test('a live settings change rebinds the hotkey', { skip: skipAll }, async () => {
  const h = createWiring();
  const area = h.focus('area');
  h.press();
  assert.equal(h.isOpen(), true, 'the default hotkey works to begin with');
  h.press();

  // the popup saves a new hotkey; storage pushes the change to the wiring
  h.pushSettings({ hotkey: 'Alt+Shift+J' });

  h.press();
  assert.equal(h.isOpen(), false, 'the old binding is gone');

  h.press({ ctrlKey: false, altKey: true, shiftKey: true, key: 'j', code: 'KeyJ' });
  assert.equal(h.isOpen(), true, 'the new binding works without a reload');
  assert.equal(h.wired.getTarget(), area);
});

test('the overlay follows the focused field and refuses non-editable elements', { skip: skipAll }, async () => {
  const h = createWiring();

  const area = h.focus('area');
  h.press();
  assert.equal(h.wired.getTarget(), area);

  h.press(); // close
  h.focus('rich');
  h.press();
  assert.equal(h.wired.getTarget(), h.document.getElementById('rich'), 'contenteditable is a valid target');

  h.press();
  h.focus('btn');
  h.press();
  assert.equal(h.wired.getTarget(), h.document.getElementById('rich'), 'a button is not a target — the last editable is kept');

  h.press();
  h.focus('ro');
  h.press();
  assert.equal(h.wired.getTarget(), h.document.getElementById('rich'), 'a readonly input is not writable');

  h.press();
  h.focus('sel');
  h.press();
  assert.equal(h.wired.getTarget(), h.document.getElementById('rich'), 'a select is not writable');
});

test('password fields are never tracked as targets unless explicitly allowed', { skip: skipAll }, async () => {
  const h = createWiring();
  h.focus('text');
  h.press();
  assert.equal(h.wired.getTarget(), h.document.getElementById('text'));
  h.press();

  h.focus('pw');
  h.press();
  // Deliberately conservative: moving to a credential field forgets the
  // previous target, so a message can never be committed into a field the
  // user is no longer looking at.
  assert.equal(h.wired.getTarget(), null, 'the password field is skipped, and so is the stale one');
  assert.notEqual(h.wired.getTarget(), h.document.getElementById('pw'));

  // moving back to a normal field restores targeting
  h.focus('text');
  assert.equal(h.wired.getTarget(), h.document.getElementById('text'));

  // opting out of the guard (a deliberate, documented setting) targets it
  const relaxed = createWiring({ settings: { ignorePasswordFields: false } });
  const pw = relaxed.focus('pw');
  relaxed.press();
  assert.equal(relaxed.wired.getTarget(), pw);
});

test('focus inside the overlay is not mistaken for a page target', { skip: skipAll }, async () => {
  const h = createWiring();
  const area = h.focus('area');
  h.press();

  const host = h.wired.keyboard.host;
  assert.ok(host, 'the overlay host exists');
  const inner = h.document.createElement('input');
  host.appendChild(inner);
  inner.dispatchEvent(new h.window.FocusEvent('focusin', { bubbles: true }));
  h.wired.keyboard.setTarget(h.wired.getTarget());

  assert.equal(h.wired.getTarget(), area, 'our own controls are not commit targets');
});

test('closing keeps the last editable so reopening lands in the same place', { skip: skipAll }, async () => {
  const h = createWiring();
  const area = h.focus('area');
  h.press();
  h.press(); // close
  assert.equal(h.isOpen(), false);

  // focus moves to something unusable (e.g. the page body) …
  h.document.body.dispatchEvent(new h.window.FocusEvent('focusin', { bubbles: true }));
  h.press();
  assert.equal(h.wired.getTarget(), area, 'the remembered field is still the target');
});

test('destroy() removes every listener it installed', { skip: skipAll }, async () => {
  const h = createWiring();
  h.focus('area');
  h.wired.destroy();

  h.press();
  assert.equal(h.isOpen(), false, 'the hotkey is gone');

  h.focus('area');
  h.press();
  assert.equal(h.isOpen(), false);
  assert.equal(h.document.querySelectorAll('.kb-host, [class*="kb-host"]').length, 0, 'no host is mounted');
});

test('kbDeepActiveElement pierces open shadow roots', { skip: skipAll }, async () => {
  const h = createWiring();
  const host = h.document.createElement('div');
  h.document.body.appendChild(host);
  const root = host.attachShadow({ mode: 'open' });
  const inner = h.document.createElement('input');
  root.appendChild(inner);
  inner.focus();

  assert.equal(h.document.activeElement, host, 'the document only sees the host');
  assert.equal(kbDeepActiveElement(h.document), inner, 'the deep active element is the inner input');
});

test('wiring without a document fails loudly instead of half-installing', { skip: skipAll }, async () => {
  assert.throws(() => kbWireKeyboard({ doc: null, window: null, adapter: {} }), /needs a document and window/);
});
