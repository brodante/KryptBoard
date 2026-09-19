/**
 * KryptBoard — content script.
 *
 * Bridges the shadow-DOM keyboard to chrome.storage and the popup. The page
 * itself never sees the passphrase (it lives in the content-script closure or
 * chrome.storage.session) and never sees plaintext it was not sent.
 */

import { kbCreateSettingsStore, kbCreatePassphraseVault, KB_SETTINGS_KEY } from './settings.js';
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
      hotkey: store.get().hotkey,
      enabled: store.get().enabled
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
          case 'kryptboard:clear-passphrase':
            await vault.clear();
            wired.keyboard.setPassphrase('');
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
        wired.keyboard.setPassphrase(typeof value === 'string' ? value : '');
      }
    });
  }
})();
