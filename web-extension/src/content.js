/**
 * KryptBoard — content script.
 *
 * Bridges the shadow-DOM keyboard to chrome.storage and the popup. The page
 * itself never sees the passphrase (it lives in the content-script closure or
 * chrome.storage.session) and never sees plaintext it was not sent.
 */

import { kbCreateSettingsStore, kbCreatePassphraseVault, KB_SETTINGS_KEY } from './settings.js';
import { kbKeyFingerprint, kbNormalizeKeyBytes, kbZeroizeBytes } from './crypto.js';
import { kbWireKeyboard } from './wiring.js';

(function install() {
  const globalScope = typeof window !== 'undefined' ? window : globalThis;
  if (globalScope.__kryptboardInstalled) return;
  globalScope.__kryptboardInstalled = true;

  const hasChrome = typeof chrome !== 'undefined' && chrome.storage;
  const syncArea = hasChrome && chrome.storage.sync ? chrome.storage.sync : null;
  const sessionArea = hasChrome && chrome.storage.session ? chrome.storage.session : null;

  const store = kbCreateSettingsStore(syncArea);
  const vault = kbCreatePassphraseVault({ sessionArea });

  /**
   * The paper's single-session key (Algorithm 1's `key_bytes`).
   *
   * It is handed over by the popup over the message API and kept in this
   * content script's closure only — pages cannot reach it, and it is wiped
   * (overwritten with zeros) the moment it is replaced or cleared.
   */
  let sessionKey = null;

  const ready = (async () => {
    await store.load();
    await vault.load();
  })();

  const wired = kbWireKeyboard({
    adapter: {
      getSettings: () => store.get(),
      saveSettings: (patch) => store.save(patch),
      subscribeSettings: (cb) => store.subscribe(cb),
      getPassphrase: () => vault.get(),
      savePassphrase: (passphrase, remember) => vault.set(passphrase, remember),
      getSessionKey: () => (sessionKey ? sessionKey.slice() : null),
      getSessionKeyFingerprint: () => (sessionKey ? kbKeyFingerprint(sessionKey) : ''),
      cssHref: hasChrome && chrome.runtime && chrome.runtime.getURL
        ? chrome.runtime.getURL('src/keyboard.css')
        : null
    }
  });

  async function stateForPopup() {
    await ready;
    const kbState = wired.keyboard.getState();
    return {
      ok: true,
      open: kbState.open,
      mode: kbState.mode,
      bufferLength: kbState.buffer.length,
      hasTarget: !!wired.getTarget(),
      target: wired.getTarget() ? (wired.getTarget().tagName || '').toLowerCase() : null,
      hasPassphrase: vault.has(),
      passphraseRemembered: vault.isRemembered(),
      hasSessionKey: sessionKey !== null,
      sessionKeyFingerprint: sessionKey ? kbKeyFingerprint(sessionKey) : '',
      keyModel: store.get().keyModel,
      sessionFormat: store.get().sessionFormat,
      hotkey: store.get().hotkey,
      enabled: store.get().enabled,
      capturingKeys: wired.keyboard.isCapturingKeys()
    };
  }

  if (hasChrome && chrome.runtime && chrome.runtime.onMessage) {
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      const type = message && message.type;
      if (!type || !type.startsWith('kryptboard:')) return undefined;

      (async () => {
        await ready;
        switch (type) {
          case 'kryptboard:toggle':
            sendResponse({ ok: true, open: wired.toggle() });
            break;
          case 'kryptboard:open':
            wired.open();
            sendResponse({ ok: true, open: true });
            break;
          case 'kryptboard:close':
            wired.close('popup');
            sendResponse({ ok: true, open: false });
            break;
          case 'kryptboard:ping':
            sendResponse(await stateForPopup());
            break;
          case 'kryptboard:settings-changed': {
            await store.load();
            wired.keyboard.refreshSettings();
            sendResponse({ ok: true });
            break;
          }
          case 'kryptboard:set-mode': {
            // the toolbar's Plain/Encrypt switch drives the live overlay
            const mode = message.mode === 'plain' ? 'plain' : 'encrypted';
            wired.keyboard.setMode(mode);
            await store.save({ startMode: mode });
            sendResponse({ ok: true, mode, capturingKeys: wired.keyboard.isCapturingKeys() });
            break;
          }
          case 'kryptboard:clear-passphrase':
            await vault.clear();
            wired.keyboard.setPassphrase('');
            sendResponse({ ok: true });
            break;
          case 'kryptboard:set-session-key': {
            try {
              const next = kbNormalizeKeyBytes(message.key, 'session key');
              // wipe the previous key before replacing it
              kbZeroizeBytes(sessionKey);
              sessionKey = next;
              wired.keyboard.refreshSettings();
              sendResponse({ ok: true, fingerprint: kbKeyFingerprint(sessionKey) });
            } catch (error) {
              sendResponse({ ok: false, error: (error && error.message) || 'invalid session key' });
            }
            break;
          }
          case 'kryptboard:clear-session-key':
            kbZeroizeBytes(sessionKey);
            sessionKey = null;
            wired.keyboard.refreshSettings();
            sendResponse({ ok: true });
            break;
          default:
            sendResponse({ ok: false, error: `unknown message: ${type}` });
        }
      })();

      return true; // async response
    });
  }

  if (hasChrome && chrome.storage && chrome.storage.onChanged) {
    chrome.storage.onChanged.addListener((changes, areaName) => {
      if (areaName === 'sync' && changes[KB_SETTINGS_KEY]) {
        store.applyExternal(changes[KB_SETTINGS_KEY].newValue);
        wired.keyboard.refreshSettings();
      }
      if (areaName === 'session' && changes['kryptboard:passphrase']) {
        const value = changes['kryptboard:passphrase'].newValue;
        const incoming = typeof value === 'string' ? value : '';
        // Ignore the echo of this vault's own write. Without this, storing a
        // passphrase with "remember" off removes the session key, the echo
        // arrives as an empty value, and the overlay wipes the very field the
        // user is typing into.
        if (incoming !== vault.lastWritten()) wired.keyboard.setPassphrase(incoming);
      }
    });
  }
})();
