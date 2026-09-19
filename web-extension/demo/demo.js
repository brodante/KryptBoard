/**
 * Live demo wiring.
 *
 * Uses the real keyboard + wiring + crypto modules with a localStorage
 * adapter instead of chrome.storage, so the behaviour on this page is the
 * behaviour of the extension on any site.
 *
 * The demo deliberately keeps the passphrase in a module variable (never in
 * web storage) — exactly like the extension keeps it in chrome.storage.session.
 */

import { kbWireKeyboard } from '../src/wiring.js';
import { kbNormalizeSettings, KB_DEFAULT_SETTINGS } from '../src/settings.js';
import {
  kbEncrypt, kbDecrypt, kbParseEnvelope, kbDescribeEnvelope, KBError,
  kbGenerateSessionKey, kbEncodeSessionKey, kbDecodeSessionKey, kbKeyFingerprint, kbZeroizeBytes,
  kbEncryptToDict, kbDecryptFromDict, kbParseDict, kbLooksLikeDict,
  kbEncryptWithKey, kbDecryptWithKey, kbIsSessionKeyAlgorithm
} from '../src/crypto.js';

const SETTINGS_KEY = 'kryptboard.demo.settings';
let passphrase = ''; // memory only — page scripts are not trusted with it either
let sessionKey = null; // paper §III: one key, held for this page-view only

const $ = (id) => document.getElementById(id);

/* ---------------------------- settings ---------------------------- */

function loadSettings() {
  try {
    return kbNormalizeSettings(JSON.parse(localStorage.getItem(SETTINGS_KEY) || 'null'));
  } catch (error) {
    return { ...KB_DEFAULT_SETTINGS };
  }
}

let settings = loadSettings();
const subscribers = new Set();

const adapter = {
  getSettings: () => settings,
  saveSettings: async (patch) => {
    settings = kbNormalizeSettings({ ...settings, ...patch });
    localStorage.setItem(SETTINGS_KEY, JSON.stringify(settings));
    for (const fn of subscribers) fn(settings);
    return settings;
  },
  subscribeSettings: (fn) => subscribers.add(fn),
  getPassphrase: async () => passphrase,
  // The demo has no chrome.storage.session, so the "remember" flag only
  // documents the intent: the phrase stays in this module either way.
  savePassphrase: async (value) => {
    passphrase = typeof value === 'string' ? value : '';
  },
  // the paper's model: a locally generated key used directly, no KDF
  getSessionKey: () => sessionKey,
  getSessionKeyFingerprint: () => (sessionKey ? kbKeyFingerprint(sessionKey) : ''),
  cssHref: '../src/keyboard.css'
};

const wiring = kbWireKeyboard({ adapter });

/* ------------------------------ log ------------------------------- */

const logEl = $('log');

function log(kind, text) {
  if (logEl.querySelector('.empty')) logEl.textContent = '';
  const item = document.createElement('li');
  const time = new Date().toLocaleTimeString();
  item.className = `kind-${kind}`;
  item.textContent = `[${time}] ${kind.toUpperCase()} · ${text}`;
  logEl.prepend(item);
  while (logEl.children.length > 80) logEl.lastElementChild.remove();
}

function addLogging(field, label) {
  if (!field) return;
  for (const type of ['input', 'keydown', 'submit']) {
    field.addEventListener(type, (event) => {
      if (type === 'keydown' && event.key !== 'Enter') return;
      const detail = field.isContentEditable
        ? `textContent="${(field.textContent || '').slice(-60)}"`
        : `value="${String(field.value || '').slice(-60)}"`;
      log(field.value || field.textContent ? 'plain' : 'event', `${label} ${type}: ${detail}`);
    });
  }
}

addLogging($('msg'), 'textarea');
addLogging($('search'), 'input');
$('rich').addEventListener('input', () => {
  log('plain', `contenteditable input: textContent="${($('rich').textContent || '').slice(-60)}"`);
});
$('search-form').addEventListener('submit', (event) => {
  event.preventDefault();
  log('event', 'search form submitted (Enter accepted by the field)');
});
$('pw').addEventListener('input', () => log('plain', 'password field received input'));

logEl.innerHTML = '<li class="empty">No page-side events yet.</li>';

/* --------------------------- controls ----------------------------- */

$('open-kb').addEventListener('click', () => {
  wiring.open();
  log('event', `keyboard opened by button (hotkey ${settings.hotkey})`);
});

$('clear-log').addEventListener('click', () => {
  logEl.innerHTML = '<li class="empty">No page-side events yet.</li>';
});

$('demo-mode').addEventListener('change', (event) => {
  wiring.keyboard.setMode(event.target.value);
  adapter.saveSettings({ startMode: event.target.value });
});

$('demo-theme').addEventListener('change', (event) => {
  wiring.keyboard.setTheme(event.target.value);
  adapter.saveSettings({ theme: event.target.value });
});

$('demo-keymodel').addEventListener('change', (event) => {
  adapter.saveSettings({ keyModel: event.target.value });
  log('event', `key model: ${event.target.value === 'session' ? 'single-session key (paper §III)' : 'passphrase'}`);
});

$('demo-sessionformat').addEventListener('change', (event) => {
  adapter.saveSettings({ sessionFormat: event.target.value });
  log('event', `session output format: ${event.target.value}`);
});

$('session-generate').addEventListener('click', () => {
  if (sessionKey) kbZeroizeBytes(sessionKey); // wipe the key we are replacing
  sessionKey = kbGenerateSessionKey();
  renderSessionKey();
  log('key', `generated a 32-byte session key — fingerprint ${kbKeyFingerprint(sessionKey)}`);
});

$('session-copy').addEventListener('click', async () => {
  if (!sessionKey) {
    log('event', 'no session key to share — generate one first');
    return;
  }
  const sharing = kbEncodeSessionKey(sessionKey);
  try {
    await navigator.clipboard.writeText(sharing);
    log('key', 'sharing string copied to the clipboard');
  } catch (error) {
    $('session-fingerprint').textContent = sharing; // let the user copy it by hand
    log('event', 'clipboard blocked — the sharing string is shown next to the fingerprint');
  }
});

$('session-forget').addEventListener('click', () => {
  if (sessionKey) kbZeroizeBytes(sessionKey);
  sessionKey = null;
  renderSessionKey();
  log('key', 'session key wiped');
});

function renderSessionKey() {
  const settings = adapter.getSettings();
  $('session-fingerprint').textContent = sessionKey ? kbKeyFingerprint(sessionKey) : 'no session key';
  $('demo-keymodel').value = settings.keyModel;
  $('demo-sessionformat').value = settings.sessionFormat;
  $('session-note').dataset.hasKey = sessionKey ? 'yes' : 'no';
}

$('demo-hardened').addEventListener('change', (event) => {
  adapter.saveSettings({ hardenedKdf: event.target.checked });
  log('event', `PBKDF2 hardening ${event.target.checked ? 'enabled' : 'disabled'}`);
});

$('send-collect').addEventListener('click', () => {
  const buffer = wiring.keyboard.getBuffer();
  if (!buffer) {
    log('event', 'buffer is empty — nothing to commit');
    return;
  }
  const target = wiring.getTarget() || $('msg');
  target.focus();
  const ok = document.execCommand && document.execCommand('insertText', false, buffer);
  if (!ok) {
    target.value = String(target.value || '') + buffer;
    target.dispatchEvent(new Event('input', { bubbles: true }));
  }
  wiring.keyboard.clearBuffer();
  log('event', `buffer committed manually (${buffer.length} chars)`);
});

/* ------------------------ round trip panel ------------------------ */

$('roundtrip-run').addEventListener('click', async () => {
  const out = $('roundtrip-out');
  const meta = $('roundtrip-meta');
  const envelope = $('roundtrip-in').value.trim();
  const pass = $('roundtrip-pass').value;
  try {
    const started = performance.now();
    let plaintext;
    if (kbLooksLikeDict(envelope)) {
      // Algorithm 2: {nonce, ciphertext, tag}, base64, no passphrase involved
      if (!sessionKey) throw new KBError('NO_KEY', 'this dictionary needs the session key it was sealed with');
      plaintext = await kbDecryptFromDict(kbParseDict(envelope), sessionKey);
      log('key', 'decrypted a base64 dictionary with the session key (Algorithm 2)');
    } else if (kbIsSessionKeyAlgorithm(kbParseEnvelope(envelope).alg)) {
      if (!sessionKey) throw new KBError('NO_KEY', 'this envelope needs the session key it was sealed with');
      plaintext = await kbDecryptWithKey(envelope, sessionKey);
      log('key', 'decrypted a +SESSIONKEY envelope with the session key');
    } else {
      plaintext = await kbDecrypt(envelope, pass, {
        aad: settings.aad || '',
        hardened: settings.hardenedKdf === true,
        iterations: settings.pbkdf2Iterations
      });
    }
    out.textContent = plaintext;
    meta.textContent = `Tag verified ✓ — recovered ${plaintext.length} characters in ${(performance.now() - started).toFixed(1)} ms.`;
    log('envelope', `decrypted an envelope (${plaintext.length} chars) — page never saw the ciphertext before this`);
  } catch (error) {
    out.textContent = '';
    meta.textContent = error instanceof KBError && error.code === 'AUTH_FAILED'
      ? 'Authentication failed — wrong passphrase, wrong context label, or altered ciphertext.'
      : `Error: ${error && error.message ? error.message : error}`;
  }
});

$('roundtrip-send-to-kb').addEventListener('click', () => {
  const value = $('roundtrip-in').value.trim();
  if (!value) return;
  wiring.keyboard.setBuffer(value);
  wiring.open();
  wiring.keyboard.setMode('encrypted');
  log('event', 'envelope loaded into the keyboard buffer');
});

const SAMPLE_TEXT = 'Attack at dawn — demo vector';

$('gen-sample').addEventListener('click', async () => {
  if (adapter.getSettings().keyModel === 'session') {
    if (!sessionKey) {
      $('format-sample').textContent = 'Generate a session key first — the paper\'s model has no fallback passphrase.';
      log('key', 'no session key: the sample button has nothing to seal with');
      return;
    }
    const dict = await kbEncryptToDict(SAMPLE_TEXT, sessionKey);
    if (adapter.getSettings().sessionFormat === 'envelope') {
      const envelope = await kbEncryptWithKey(SAMPLE_TEXT, sessionKey);
      $('format-sample').textContent = [
        envelope,
        '',
        'algorithm      : ChaCha20-Poly1305 + single-session key',
        'key            : fingerprint ' + kbKeyFingerprint(sessionKey),
        `plaintext      : ${new TextEncoder().encode(SAMPLE_TEXT).length} bytes`,
        `envelope       : ${envelope.length} chars`,
        'nonce          : fresh per seal — this envelope differs from the dictionary above by design'
      ].join('\n');
      log('key', 'sealed a sample with the session key — v1 envelope output');
      return;
    }
    $('format-sample').textContent = [
      JSON.stringify(dict),
      '',
      'algorithm      : ChaCha20-Poly1305 (paper Algorithm 1)',
      'key            : single-session key, fingerprint ' + kbKeyFingerprint(sessionKey),
      `nonce          : ${dict.nonce} (12 random bytes)`,
      `plaintext      : ${new TextEncoder().encode(SAMPLE_TEXT).length} bytes`,
      `ciphertext     : ${dict.ciphertext.length} base64 chars, tag ${dict.tag.length} base64 chars`
    ].join('\n');
    log('key', 'sealed a sample with Algorithm 1 — base64 dictionary output');
    return; // the passphrase envelope below is the other model's shape
  }
  const nonce = new Uint8Array(12); // fixed: reproducibility, never do this in production
  const envelope = await kbEncrypt(SAMPLE_TEXT, 'demo-passphrase', {
    nonce,
    aad: settings.aad || '',
    hardened: settings.hardenedKdf === true,
    iterations: settings.pbkdf2Iterations
  });
  const info = kbDescribeEnvelope(kbParseEnvelope(envelope));
  $('format-sample').textContent = [
    envelope,
    '',
    `algorithm      : ${info.algorithm}`,
    `kdf            : ${info.hardened ? `PBKDF2-HMAC-SHA256 ×${info.iterations} → HKDF-SHA256` : 'HKDF-SHA256'}`,
    `plaintext      : ${info.plaintextBytes} bytes`,
    `envelope       : ${info.envelopeBytes} bytes`,
    `nonce          : fixed for this vector only`
  ].join('\n');
  log('envelope', `sealed a fixed-nonce sample vector (${info.envelopeBytes} B)`);
});

/* ------------------------------ boot ------------------------------ */

$('demo-mode').value = settings.startMode;
$('demo-theme').value = settings.theme;
$('demo-hardened').checked = settings.hardenedKdf === true;
renderSessionKey();
wiring.keyboard.setMode(settings.startMode);
log('event', `key model: ${settings.keyModel === 'session' ? 'single-session key' : 'passphrase'}`);
log('event', `demo ready · hotkey ${settings.hotkey} · ${settings.hardenedKdf ? 'PBKDF2-hardened' : 'HKDF-SHA256'} KDF`);
