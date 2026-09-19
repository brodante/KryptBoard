/**
 * Demo page smoke test.
 *
 * The demo is what a reviewer opens first (and what the paper's artefact
 * appendix can point at), so it is exercised here in jsdom: the page boots,
 * the overlay opens, the live event log fills up, and the round-trip panel
 * decrypts an envelope that the overlay produced.
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

const { canSimulateTrustedEvent, physicalKey } = await import('./support/trusted.mjs');
const skipTrustDemo = skip || (canSimulateTrustedEvent() ? false : 'this jsdom build cannot simulate a trusted event');

async function bootDemo() {
  const html = await fs.readFile(path.join(ROOT, 'demo/demo.html'), 'utf8');
  const dom = new JSDOM(html, { url: 'http://localhost:8787/demo/demo.html', runScripts: 'outside-only', pretendToBeVisual: true });
  const { window } = dom;

  // the demo overlay also uses a closed shadow root, so record roots as they
  // are created (the same trick the dom suite uses)
  const shadowRoots = [];
  const originalAttachShadow = window.Element.prototype.attachShadow;
  window.Element.prototype.attachShadow = function (init) {
    const root = originalAttachShadow.call(this, init);
    shadowRoots.push({ host: this, root, mode: init && init.mode });
    return root;
  };

  // localStorage is available in jsdom already; the demo uses it for settings.
  const previous = {
    window: globalThis.window,
    document: globalThis.document,
    localStorage: globalThis.localStorage,
    navigator: undefined,
    HTMLTextAreaElement: globalThis.HTMLTextAreaElement,
    HTMLInputElement: globalThis.HTMLInputElement
  };
  globalThis.window = window;
  globalThis.document = window.document;
  try {
    Object.defineProperty(globalThis, 'localStorage', { value: window.localStorage, configurable: true, writable: true });
  } catch (error) {
    /* older Node: assign directly */
    globalThis.localStorage = window.localStorage;
  }
  globalThis.HTMLTextAreaElement = window.HTMLTextAreaElement;
  globalThis.HTMLInputElement = window.HTMLInputElement;

  await import(`../demo/demo.js?boot=${Date.now()}`);

  const waitFor = async (predicate, timeout = 3000) => {
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
    shadowRoots,
    waitFor,
    restore() {
      for (const [key, value] of Object.entries(previous)) {
        if (value === undefined) delete globalThis[key];
        else globalThis[key] = value;
      }
    }
  };
}

test('the demo boots with the real modules and no console errors', { skip }, async () => {
  const errors = [];
  const demo = await bootDemo();
  try {
    demo.window.addEventListener('error', (event) => errors.push(String(event.error || event.message)));
    assert.ok(await demo.waitFor(() => /demo ready/.test(demo.document.getElementById('log').textContent)));
    assert.match(demo.document.getElementById('log').textContent, /Ctrl\+Shift\+K/);
    assert.deepEqual(errors, [], 'the demo must not raise page errors');

    // the same wiring the extension uses is live on this page
    assert.equal(demo.window.__kryptboardInstalled, undefined, 'the content-script installer must not run on the demo page');
  } finally {
    demo.restore();
  }
});

test('the demo button opens the overlay and the hotkey toggles it', { skip }, async () => {
  const demo = await bootDemo();
  try {
    await demo.waitFor(() => /demo ready/.test(demo.document.getElementById('log').textContent));
    demo.document.getElementById('open-kb').click();
    assert.ok(await demo.waitFor(() => demo.document.querySelector('[data-kryptboard="root"]')));
    assert.match(demo.document.getElementById('log').textContent, /keyboard opened by button/);

    // toggling with the hotkey hides it again
    demo.window.dispatchEvent(new demo.window.KeyboardEvent('keydown', {
      key: 'k', code: 'KeyK', ctrlKey: true, shiftKey: true, bubbles: true, cancelable: true
    }));
    await demo.waitFor(() => demo.document.querySelector('[data-kryptboard="root"]'));
    assert.match(demo.document.getElementById('log').textContent, /keyboard opened by button/);
  } finally {
    demo.restore();
  }
});

test('the demo round-trip panel decrypts an envelope', { skip }, async () => {
  const demo = await bootDemo();
  try {
    await demo.waitFor(() => /demo ready/.test(demo.document.getElementById('log').textContent));

    // a fixed-nonce vector, exactly what the "seal a sample" button produces
    demo.document.getElementById('gen-sample').click();
    assert.ok(await demo.waitFor(() => demo.document.getElementById('format-sample').textContent.startsWith('v1|')));
    const vector = demo.document.getElementById('format-sample').textContent;
    assert.match(vector, /^v1\|CHACHA20-POLY1305\|/);
    assert.match(vector, /algorithm {6}: CHACHA20-POLY1305/);
    assert.match(vector, /kdf {12}: HKDF-SHA256/);

    const envelope = vector.split('\n')[0];
    demo.document.getElementById('roundtrip-in').value = envelope;
    demo.document.getElementById('roundtrip-pass').value = 'demo-passphrase';
    demo.document.getElementById('roundtrip-run').click();
    assert.ok(await demo.waitFor(() => demo.document.getElementById('roundtrip-out').textContent.length > 0));
    assert.equal(demo.document.getElementById('roundtrip-out').textContent, 'Attack at dawn — demo vector');
    assert.match(demo.document.getElementById('roundtrip-meta').textContent, /Tag verified/);

    // the wrong passphrase is reported, not swallowed
    demo.document.getElementById('roundtrip-pass').value = 'nope';
    demo.document.getElementById('roundtrip-run').click();
    assert.ok(await demo.waitFor(() => /Authentication failed/.test(demo.document.getElementById('roundtrip-meta').textContent)));
    assert.equal(demo.document.getElementById('roundtrip-out').textContent, '');
  } finally {
    demo.restore();
  }
});

test("the demo can run the paper's session-key model end to end", { skip }, async () => {
  const demo = await bootDemo();
  try {
    await demo.waitFor(() => /demo ready/.test(demo.document.getElementById('log').textContent));
    const $ = (id) => demo.document.getElementById(id);

    // no key yet: the panel says so and refuses to share
    assert.equal($('session-fingerprint').textContent, 'no session key');
    $('session-copy').click();
    assert.ok(await demo.waitFor(() => /no session key to share/.test($('log').textContent)));

    // generate one — the fingerprint is shown, not the key
    $('session-generate').click();
    assert.ok(await demo.waitFor(() => /^[0-9A-F]{4}(-[0-9A-F]{4}){3}$/.test($('session-fingerprint').textContent)));
    const fingerprint = $('session-fingerprint').textContent;
    assert.match($('log').textContent, /generated a 32-byte session key/);

    // switching the model makes the overlay seal with it: Algorithm 1 output
    $('demo-keymodel').value = 'session';
    $('demo-keymodel').dispatchEvent(new demo.window.Event('change', { bubbles: true }));
    $('gen-sample').click();
    assert.ok(await demo.waitFor(() => $('format-sample').textContent.startsWith('{')));
    const dict = JSON.parse($('format-sample').textContent.split('\n')[0]);
    assert.deepEqual(Object.keys(dict), ['nonce', 'ciphertext', 'tag']);
    assert.match($('format-sample').textContent, /paper Algorithm 1/);
    assert.match($('format-sample').textContent, new RegExp(fingerprint));

    // Algorithm 2: the dictionary pastes back and opens with the session key, no passphrase
    $('roundtrip-in').value = JSON.stringify(dict);
    $('roundtrip-pass').value = '';
    $('roundtrip-run').click();
    assert.ok(await demo.waitFor(() => $('roundtrip-out').textContent.length > 0));
    assert.equal($('roundtrip-out').textContent, 'Attack at dawn — demo vector');
    assert.match($('log').textContent, /Algorithm 2/);

    // a dictionary without the key is a clear error, not a silent failure
    $('session-forget').click();
    await demo.waitFor(() => $('session-fingerprint').textContent === 'no session key');
    $('roundtrip-out').textContent = '';
    $('roundtrip-run').click();
    assert.ok(await demo.waitFor(() => /needs the session key/.test($('roundtrip-meta').textContent)));
  } finally {
    demo.restore();
  }
});

test('the demo envelope stays decryptable with the passphrase model after switching back', { skip }, async () => {
  const demo = await bootDemo();
  try {
    await demo.waitFor(() => /demo ready/.test(demo.document.getElementById('log').textContent));
    const $ = (id) => demo.document.getElementById(id);
    $('session-generate').click();
    await demo.waitFor(() => $('session-fingerprint').textContent !== 'no session key');
    $('demo-sessionformat').value = 'envelope';
    $('demo-sessionformat').dispatchEvent(new demo.window.Event('change', { bubbles: true }));
    await demo.waitFor(() => /session output format: envelope/.test($('log').textContent));

    // with the session model selected the sample is the envelope form of the same key
    $('demo-keymodel').value = 'session';
    $('demo-keymodel').dispatchEvent(new demo.window.Event('change', { bubbles: true }));
    $('gen-sample').click();
    assert.ok(await demo.waitFor(() => $('format-sample').textContent.startsWith('v1|CHACHA20-POLY1305+SESSIONKEY|')));
    assert.match($('format-sample').textContent, /fingerprint/);
    assert.match($('format-sample').textContent, /fresh per seal/);

    // ...and that envelope opens in the round-trip box with the session key
    $('roundtrip-in').value = $('format-sample').textContent.split('\n')[0];
    $('roundtrip-pass').value = '';
    $('roundtrip-run').click();
    assert.ok(await demo.waitFor(() => $('roundtrip-out').textContent === 'Attack at dawn — demo vector'));
    assert.match($('log').textContent, /decrypted a \+SESSIONKEY envelope/);

    // and the passphrase model still produces the interoperable envelope
    $('demo-keymodel').value = 'passphrase';
    $('demo-keymodel').dispatchEvent(new demo.window.Event('change', { bubbles: true }));
    $('gen-sample').click();
    assert.ok(await demo.waitFor(() => $('format-sample').textContent.startsWith('v1|CHACHA20-POLY1305|')));
    assert.match($('format-sample').textContent, /kdf {12}: HKDF-SHA256/);
  } finally {
    demo.restore();
  }
});

test('the demo overlay can capture the physical keyboard', { skip: skipTrustDemo }, async () => {
  const demo = await bootDemo();
  try {
    await demo.waitFor(() => /demo ready/.test(demo.document.getElementById('log').textContent));
    const $ = (id) => demo.document.getElementById(id);
    $('open-kb').click();
    assert.ok(await demo.waitFor(() => demo.document.querySelector('[data-kryptboard="root"]')));

    // the toggle is in the overlay's toolbar and persists through the demo adapter
    const host = demo.document.querySelector('[data-kryptboard="root"]');
    const capture = demo.shadowRoots[0].root.querySelector('[data-act="capture"]');
    capture.click();
    assert.equal(capture.classList.contains('is-active'), true);
    assert.ok(await demo.waitFor(() => JSON.parse(localStorage.getItem('kryptboard.demo.settings')).captureKeys === true));
    assert.equal(host, demo.shadowRoots[0].host);

    // a physical keystroke lands in the buffer and never reaches the page field
    const buffer = demo.shadowRoots[0].root.querySelector('[data-role="buffer"]');
    const field = $('msg');
    field.focus();
    const event = physicalKey(demo.window, 'd');
    field.dispatchEvent(event);
    assert.equal(event.defaultPrevented, true, 'the page default action is suppressed');
    assert.equal(buffer.value, 'd', 'the buffer shows the captured key');
    assert.equal(field.value, '', 'the demo field received nothing');
    assert.match($('log').textContent, /keyboard opened by button/, 'the page log stayed quiet about the keystroke');
  } finally {
    demo.restore();
  }
});
