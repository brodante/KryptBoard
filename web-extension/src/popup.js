/**
 * KryptBoard — popup.
 *
 * Runs as a native ES module inside the extension page (no build step), so
 * it imports the very same crypto core the content script uses. It talks to
 * the page through the content script's message API and never injects
 * anything itself.
 */

import {
  kbEncrypt,
  kbDecrypt,
  kbDescribeEnvelope,
  kbParseEnvelope,
  kbEncryptToDict,
  kbEncryptWithKey,
  kbDecryptFromDict,
  kbDecryptWithKey,
  kbLooksLikeDict,
  kbLooksLikeEnvelope,
  kbGenerateSessionKey,
  kbEncodeSessionKey,
  kbKeyFingerprint,
  kbNormalizeKeyBytes,
  kbLooksLikeSessionKey,
  KBError
} from './crypto.js';
import { kbCreateSettingsStore, kbCreateSessionKeyVault, KB_HOTKEY_PRESETS } from './settings.js';

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
  ['set-captureKeys', 'captureKeys', 'checked'],
  ['set-hardenedKdf', 'hardenedKdf', 'checked'],
  ['set-pbkdf2Iterations', 'pbkdf2Iterations', 'value'],
  ['set-aad', 'aad', 'value'],
  ['set-commitStyle', 'commitStyle', 'value'],
  ['set-keyModel', 'keyModel', 'value'],
  ['set-sessionFormat', 'sessionFormat', 'value']
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
    $('toggle').disabled = true;
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
        state.hasPassphrase ? 'Passphrase: in memory' : 'Passphrase: not set',
        state.capturingKeys ? '⌨ capturing your keyboard' : '⌨ capture off'
      ].join(' · ')
    );
    renderModeSwitch(state.mode || settings.startMode);
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
    window.setTimeout(() => refresh().catch(() => {}), 120);
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
    window.setTimeout(() => refresh().catch(() => {}), 120);
  } catch (error) {
    /* ignore */
  }
}

/* ------------------------------------------------------------------ */
/* session key (paper §III: single-session key model)                  */
/* ------------------------------------------------------------------ */

// Extension pages may use storage.session directly; the content script
// receives the key over the message API instead of reading storage itself.
const sessionVault = kbCreateSessionKeyVault({ sessionArea: chrome.storage && chrome.storage.session });

/* ------------------------------------------------------------------ */
/* the toolbar's Plain / Encrypt switch                                */
/* ------------------------------------------------------------------ */

function renderModeSwitch(mode) {
  const plain = $('mode-plain');
  const encrypt = $('mode-encrypt');
  if (!plain || !encrypt) return;
  plain.classList.toggle('is-active', mode === 'plain');
  encrypt.classList.toggle('is-active', mode !== 'plain');
  plain.setAttribute('aria-pressed', String(mode === 'plain'));
  encrypt.setAttribute('aria-pressed', String(mode !== 'plain'));
}

async function setMode(mode) {
  const tab = await activeTab();
  if (!tab || !tab.id) {
    setPageStatus('No active tab to switch.', 'blocked');
    return;
  }
  try {
    const result = await chrome.tabs.sendMessage(tab.id, { type: 'kryptboard:set-mode', mode });
    if (!result || !result.ok) throw new Error((result && result.error) || 'the page refused');
    // an older content script may not echo the mode back; trust the request then
    const applied = result.mode === 'plain' || result.mode === 'encrypted' ? result.mode : mode;
    renderModeSwitch(applied);
    setPageStatus(
      applied === 'plain'
        ? 'Plain mode — keystrokes go straight into the field.'
        : 'Encrypt mode — keystrokes are buffered until you seal them.',
      applied === 'plain' ? 'closed' : 'open'
    );
    // the choice also becomes the default for the next page
    const next = await store.save({ startMode: applied });
    fillForms(next);
  } catch (error) {
    setPageStatus(
      'This page does not allow extensions (browser pages, the Web Store, and local files cannot be extended).',
      'blocked'
    );
  }
}

function renderSessionKey() {
  const state = $('session-key-state');
  const hint = $('session-key-hint');
  const has = sessionVault.has();
  state.textContent = has ? `Session key ready (${sessionVault.fingerprint()})` : 'No session key';
  state.className = `status ${has ? 'open' : ''}`;
  hint.innerHTML = has
    ? 'Fingerprint: <span class="muted">' + sessionVault.fingerprint() + '</span> — compare it out of band with the other side.'
    : 'Fingerprint: <span class="muted">none yet</span>';
  const model = $('set-keyModel');
  if (model) $('session-format-field').hidden = model.value !== 'session';
}

function pushSessionKey() {
  const key = sessionVault.share();
  chrome.tabs.query({ active: true, currentWindow: true }).then(([tab]) => {
    if (!tab) return;
    chrome.tabs
      .sendMessage(tab.id, { type: 'kryptboard:set-session-key', key })
      .catch(() => {});
  });
}

async function generateSessionKey() {
  await sessionVault.set(kbGenerateSessionKey(), true);
  renderSessionKey();
  pushSessionKey();
  $('session-key-state').textContent = `Session key ready (${sessionVault.fingerprint()}) — share it with the other side.`;
}

async function importSessionKey() {
  const input = $('session-import');
  const value = input.value.trim();
  if (!value) return;
  if (!kbLooksLikeSessionKey(value)) {
    $('session-key-state').className = 'status blocked';
    $('session-key-state').textContent = 'That does not look like a KryptBoard key (expected kbk1.… or base64).';
    return;
  }
  await sessionVault.set(kbNormalizeKeyBytes(value), true);
  input.value = '';
  renderSessionKey();
  pushSessionKey();
}

async function forgetSessionKey() {
  await sessionVault.clear();
  renderSessionKey();
  chrome.tabs.query({ active: true, currentWindow: true }).then(([tab]) => {
    if (!tab) return;
    chrome.tabs.sendMessage(tab.id, { type: 'kryptboard:clear-session-key' }).catch(() => {});
  });
}

async function copySessionKey() {
  const shared = sessionVault.share();
  if (!shared) return;
  try {
    await navigator.clipboard.writeText(shared);
    $('session-key-state').textContent = 'Sharing string copied — send it to the other side over a different channel.';
  } catch (error) {
    $('session-import').value = shared;
    $('session-import').select();
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
  const settings = store.get();
  const useSessionKey = settings.keyModel === 'session';

  if (!plaintext) {
    meta.className = 'hint warn';
    meta.textContent = 'Enter a message to seal.';
    return;
  }
  if (useSessionKey && !sessionVault.has()) {
    meta.className = 'hint warn';
    meta.textContent = 'Generate or import a session key first.';
    return;
  }
  if (!useSessionKey && !passphrase) {
    meta.className = 'hint warn';
    meta.textContent = 'Enter a passphrase.';
    return;
  }

  try {
    const started = performance.now();
    let output;
    let label;
    if (useSessionKey) {
      // Algorithm 1 (dictionary) or the same thing as an envelope string.
      const key = sessionVault.get();
      if (settings.sessionFormat === 'json') {
        output = JSON.stringify(kbEncryptToDict(plaintext, key, currentOptions()));
        label = 'dictionary';
      } else {
        output = kbEncryptWithKey(plaintext, key, currentOptions());
        label = 'envelope';
      }
    } else {
      output = await kbEncrypt(plaintext, passphrase, currentOptions());
      label = 'envelope';
    }
    const elapsed = performance.now() - started;
    $('enc-out').value = output;
    meta.className = 'hint ok';
    meta.textContent = useSessionKey
      ? `${plaintext.length} characters → ${output.length} B session ${label} in ${elapsed.toFixed(1)} ms (${kbKeyFingerprint(sessionVault.get())}).`
      : `${kbDescribeEnvelope(kbParseEnvelope(output)).plaintextBytes} B plaintext → ${kbDescribeEnvelope(kbParseEnvelope(output)).envelopeBytes} B envelope in ${elapsed.toFixed(1)} ms (${kbParseEnvelope(output).alg}).`;
  } catch (error) {
    meta.className = 'hint error';
    meta.textContent = error instanceof KBError ? error.message : String(error);
  }
}

async function runDecrypt() {
  const meta = $('dec-meta');
  const envelope = $('dec-env').value.trim();
  const passphrase = $('dec-pass').value;
  const settings = store.get();
  if (!envelope) {
    meta.className = 'hint warn';
    meta.textContent = 'Paste an envelope or a {nonce, ciphertext, tag} dictionary first.';
    return;
  }
  const isDict = kbLooksLikeDict(envelope);
  if (!isDict && !kbLooksLikeEnvelope(envelope)) {
    meta.className = 'hint warn';
    meta.textContent = 'That is neither a v1 envelope nor an Algorithm-1 dictionary.';
    return;
  }
  const needsSessionKey = isDict || settings.keyModel === 'session';
  if (needsSessionKey && !sessionVault.has()) {
    meta.className = 'hint warn';
    meta.textContent = 'This message needs the session key — generate or import one above.';
    return;
  }
  if (!needsSessionKey && !passphrase) {
    meta.className = 'hint warn';
    meta.textContent = 'Enter the passphrase that sealed this message.';
    return;
  }
  try {
    const started = performance.now();
    const plaintext = needsSessionKey
      ? (isDict
          ? kbDecryptFromDict(envelope, sessionVault.get(), currentOptions())
          : kbDecryptWithKey(envelope, sessionVault.get(), currentOptions()))
      : await kbDecrypt(envelope, passphrase, currentOptions());
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

  await sessionVault.load();
  renderSessionKey();
  if (sessionVault.has()) pushSessionKey();

  $('session-generate').addEventListener('click', generateSessionKey);
  $('session-copy').addEventListener('click', copySessionKey);
  $('session-clear').addEventListener('click', forgetSessionKey);
  $('session-import').addEventListener('change', importSessionKey);
  $('set-keyModel').addEventListener('change', () => {
    renderSessionKey();
    if (store.get().keyModel === 'session' && sessionVault.has()) pushSessionKey();
  });

  $('mode-plain').addEventListener('click', () => setMode('plain'));
  $('mode-encrypt').addEventListener('click', () => setMode('encrypted'));
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

// A popup that fails to boot should leave a visible error, not a dead panel
// and an unhandled rejection in the extension's console.
boot().catch((error) => {
  const status = document.getElementById('page-status');
  if (status) {
    status.className = 'status blocked';
    status.textContent = `KryptBoard failed to start: ${(error && error.message) || error}`;
  }
});
