/**
 * KryptBoard — popup.
 *
 * Runs as a native ES module inside the extension page (no build step), so
 * it imports the very same crypto core the content script uses. It talks to
 * the page through the content script's message API and never injects
 * anything itself.
 */

import { kbEncrypt, kbDecrypt, kbDescribeEnvelope, kbParseEnvelope, KBError } from './crypto.js';
import { kbCreateSettingsStore, KB_HOTKEY_PRESETS } from './settings.js';

const $ = (id) => document.getElementById(id);

const store = kbCreateSettingsStore(chrome.storage.sync, {});

/* ------------------------------------------------------------------ */
/* settings forms                                                      */
/* ------------------------------------------------------------------ */

const SETTING_FIELDS = [
  ['set-startMode', 'startMode', 'value'],
  ['set-theme', 'theme', 'value'],
  ['set-hotkey', 'hotkey', 'value'],
  ['set-enabled', 'enabled', 'checked'],
  ['set-closeAfterSend', 'closeAfterSend', 'checked'],
  ['set-clearBufferOnClose', 'clearBufferOnClose', 'checked'],
  ['set-ignorePasswordFields', 'ignorePasswordFields', 'checked'],
  ['set-autoDetectEnvelope', 'autoDetectEnvelope', 'checked'],
  ['set-showHints', 'showHints', 'checked'],
  ['set-hardenedKdf', 'hardenedKdf', 'checked'],
  ['set-pbkdf2Iterations', 'pbkdf2Iterations', 'value'],
  ['set-aad', 'aad', 'value'],
  ['set-commitStyle', 'commitStyle', 'value']
];

function fillForms(settings) {
  for (const [id, key, prop] of SETTING_FIELDS) {
    const el = $(id);
    if (!el) continue;
    if (prop === 'checked') el.checked = settings[key] === true;
    else el.value = String(settings[key] ?? '');
  }
  $('set-pbkdf2Iterations').disabled = settings.hardenedKdf !== true;
}

async function onFieldChange(event) {
  const entry = SETTING_FIELDS.find(([id]) => id === event.target.id);
  if (!entry) return;
  const [, key, prop] = entry;
  const value = prop === 'checked' ? event.target.checked : event.target.value;
  const next = await store.save({ [key]: value });
  fillForms(next);
  notifyPages(next);
}

function notifyPages(settings) {
  chrome.tabs.query({ active: true, currentWindow: true }).then(([tab]) => {
    if (!tab) return;
    chrome.tabs.sendMessage(tab.id, { type: 'kryptboard:settings-changed', settings }).catch(() => {});
  });
}

async function resetSettings() {
  const next = await store.reset();
  fillForms(next);
  notifyPages(next);
}

/* ------------------------------------------------------------------ */
/* active tab status                                                   */
/* ------------------------------------------------------------------ */

function setPageStatus(text, kind, hint) {
  const el = $('page-status');
  el.textContent = text;
  el.className = `status ${kind || ''}`;
  $('page-hint').textContent = hint || '';
}

async function activeTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab || null;
}

async function refresh() {
  const settings = store.get();
  $('toggle').disabled = false;
  $('toggle').textContent = settings.startMode === 'plain' ? 'Open keyboard (plain)' : 'Open keyboard (encrypted)';

  const tab = await activeTab();
  if (!tab || !tab.id) {
    setPageStatus('No active tab.', 'blocked');
    return;
  }
  try {
    const state = await chrome.tabs.sendMessage(tab.id, { type: 'kryptboard:ping' });
    if (!state || !state.ok) throw new Error('no state');
    setPageStatus(
      state.open ? `Keyboard is open on this page (${state.mode} mode).` : 'Keyboard is hidden on this page.',
      state.open ? 'open' : 'closed',
      [
        `Hotkey: ${state.hotkey}`,
        state.hasTarget ? `Target: <${state.target}>` : 'Target: none yet — click a text field',
        state.hasPassphrase ? 'Passphrase: in memory' : 'Passphrase: not set'
      ].join(' · ')
    );
    $('toggle').textContent = state.open ? 'Hide keyboard' : (settings.startMode === 'plain' ? 'Open keyboard (plain)' : 'Open keyboard (encrypted)');
  } catch (error) {
    setPageStatus(
      'This page does not allow extensions (browser pages, the Web Store, and local files cannot be extended).',
      'blocked',
      'Open a normal website, then use the hotkey or this button.'
    );
    $('toggle').disabled = true;
  }
}

async function onToggle() {
  const tab = await activeTab();
  if (!tab || !tab.id) return;
  try {
    const result = await chrome.tabs.sendMessage(tab.id, { type: 'kryptboard:toggle' });
    setPageStatus(result && result.open ? 'Keyboard opened.' : 'Keyboard hidden.', result && result.open ? 'open' : 'closed');
    window.setTimeout(refresh, 120);
  } catch (error) {
    setPageStatus('Could not reach the page.', 'blocked', String(error && error.message ? error.message : error));
  }
}

async function onClearPassphrase() {
  const tab = await activeTab();
  if (!tab || !tab.id) return;
  try {
    await chrome.tabs.sendMessage(tab.id, { type: 'kryptboard:clear-passphrase' });
    setPageStatus('Passphrase cleared from this session.', 'closed');
    window.setTimeout(refresh, 120);
  } catch (error) {
    /* ignore */
  }
}

/* ------------------------------------------------------------------ */
/* crypto console                                                      */
/* ------------------------------------------------------------------ */

function currentOptions() {
  const settings = store.get();
  return { aad: settings.aad || '', hardened: settings.hardenedKdf === true, iterations: settings.pbkdf2Iterations };
}

async function runEncrypt() {
  const meta = $('enc-meta');
  const plaintext = $('enc-plain').value;
  const passphrase = $('enc-pass').value;
  if (!plaintext) {
    meta.className = 'hint warn';
    meta.textContent = 'Enter a message to seal.';
    return;
  }
  if (!passphrase) {
    meta.className = 'hint warn';
    meta.textContent = 'Enter a passphrase.';
    return;
  }
  try {
    const started = performance.now();
    const envelope = await kbEncrypt(plaintext, passphrase, currentOptions());
    const elapsed = performance.now() - started;
    $('enc-out').value = envelope;
    const info = kbDescribeEnvelope(kbParseEnvelope(envelope));
    meta.className = 'hint ok';
    meta.textContent = `${info.plaintextBytes} B plaintext → ${info.envelopeBytes} B envelope in ${elapsed.toFixed(1)} ms (${info.algorithm}).`;
  } catch (error) {
    meta.className = 'hint error';
    meta.textContent = error instanceof KBError ? error.message : String(error);
  }
}

async function runDecrypt() {
  const meta = $('dec-meta');
  const envelope = $('dec-env').value.trim();
  const passphrase = $('dec-pass').value;
  if (!envelope) {
    meta.className = 'hint warn';
    meta.textContent = 'Paste an envelope first.';
    return;
  }
  try {
    const started = performance.now();
    const plaintext = await kbDecrypt(envelope, passphrase, currentOptions());
    const elapsed = performance.now() - started;
    $('dec-out').value = plaintext;
    meta.className = 'hint ok';
    meta.textContent = `Tag verified ✓ — ${plaintext.length} characters recovered in ${elapsed.toFixed(1)} ms.`;
  } catch (error) {
    $('dec-out').value = '';
    meta.className = 'hint error';
    meta.textContent = error instanceof KBError && error.code === 'AUTH_FAILED'
      ? 'Authentication failed — wrong passphrase, wrong context label, or the ciphertext was altered.'
      : (error && error.message) || String(error);
  }
}

async function copyEnvelope() {
  const value = $('enc-out').value;
  if (!value) return;
  try {
    await navigator.clipboard.writeText(value);
    const meta = $('enc-meta');
    meta.className = 'hint ok';
    meta.textContent = 'Envelope copied to the clipboard.';
  } catch (error) {
    $('enc-out').select();
  }
}

/* ------------------------------------------------------------------ */
/* boot                                                                */
/* ------------------------------------------------------------------ */

function wireTabs() {
  for (const tab of document.querySelectorAll('.tab')) {
    tab.addEventListener('click', () => {
      for (const other of document.querySelectorAll('.tab')) other.classList.toggle('is-active', other === tab);
      for (const panel of document.querySelectorAll('.tabpanel')) {
        panel.hidden = panel.dataset.panel !== tab.dataset.tab;
      }
    });
  }
}

function wireHotkeyOptions(settings) {
  const select = $('set-hotkey');
  const known = new Set(KB_HOTKEY_PRESETS);
  if (!known.has(settings.hotkey)) {
    const option = document.createElement('option');
    option.value = settings.hotkey;
    option.textContent = settings.hotkey;
    select.appendChild(option);
  }
}

async function boot() {
  wireTabs();
  await store.load();
  const settings = store.get();
  wireHotkeyOptions(settings);
  fillForms(settings);

  for (const [id] of SETTING_FIELDS) {
    const el = $(id);
    if (el) el.addEventListener('change', onFieldChange);
  }
  // the iteration count is only meaningful while hardening is on
  $('set-hardenedKdf').addEventListener('change', () => {
    $('set-pbkdf2Iterations').disabled = $('set-hardenedKdf').checked !== true;
  });

  $('toggle').addEventListener('click', onToggle);
  $('clear-pass').addEventListener('click', onClearPassphrase);
  $('reset').addEventListener('click', resetSettings);
  $('enc-run').addEventListener('click', runEncrypt);
  $('dec-run').addEventListener('click', runDecrypt);
  $('enc-copy').addEventListener('click', copyEnvelope);

  const manifest = chrome.runtime.getManifest();
  $('version').textContent = `v${manifest.version} · ChaCha20-Poly1305 · HKDF-SHA256`;

  await refresh();
}

boot();
