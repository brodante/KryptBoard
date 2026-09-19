/**
 * KryptBoard — page wiring.
 *
 * Turns the keyboard component into a page-level feature:
 *   • a global hotkey (default Ctrl+Shift+K) opens/closes the overlay
 *   • the overlay follows whatever editable the user focuses
 *   • password fields are never tracked as commit targets (defence in depth)
 *
 * The module is deliberately storage-agnostic: `content.js` passes a
 * chrome.* adapter, the demo page passes a localStorage adapter, and tests
 * pass a plain object.
 */

import { kbCreateKeyboard } from './keyboard.js';
import { kbHotkeyMatches, kbParseHotkey } from './settings.js';
import { kbIsEditable, kbIsPasswordField } from './keyboard.js';

/** document.activeElement, piercing open shadow roots. */
export function kbDeepActiveElement(doc) {
  let element = doc.activeElement;
  let guard = 0;
  while (element && element.shadowRoot && element.shadowRoot.activeElement && guard++ < 10) {
    element = element.shadowRoot.activeElement;
  }
  return element;
}

/**
 * @param {object} options
 * @param {object} options.adapter
 * @param {() => object} options.adapter.getSettings
 * @param {(patch: object) => Promise<any>} [options.adapter.saveSettings]
 * @param {(cb: (s: object) => void) => void} [options.adapter.subscribeSettings]
 * @param {() => Promise<string>} [options.adapter.getPassphrase]
 * @param {(p: string, remember: boolean) => Promise<void>} [options.adapter.savePassphrase]
 * @param {() => Uint8Array|null} [options.adapter.getSessionKey] single-session key (paper §III)
 * @param {() => string} [options.adapter.getSessionKeyFingerprint]
 * @param {string} [options.adapter.cssHref]
 * @param {string} [options.adapter.inlineCss]
 * @param {Document} [options.doc]
 * @param {Window} [options.window]
 */
export function kbWireKeyboard(options) {
  const adapter = options.adapter || {};
  const doc = options.doc || (typeof document !== 'undefined' ? document : null);
  const win = options.window || (typeof window !== 'undefined' ? window : null);
  if (!doc || !win) throw new Error('KryptBoard: wiring needs a document and window');

  const getSettings = () => (adapter.getSettings ? adapter.getSettings() : {});
  let lastEditable = null;

  const keyboard = kbCreateKeyboard({
    doc,
    cssHref: adapter.cssHref,
    inlineCss: adapter.inlineCss,
    className: options.className,
    target: null,
    getSettings,
    getPassphrase: adapter.getPassphrase,
    savePassphrase: adapter.savePassphrase,
    getSessionKey: adapter.getSessionKey,
    getSessionKeyFingerprint: adapter.getSessionKeyFingerprint,
    onThemeChange: (theme) => {
      if (adapter.saveSettings) Promise.resolve(adapter.saveSettings({ theme })).catch(() => {});
    },
    onClose: options.onClose
  });

  function isOurs(element) {
    return !!(element && keyboard.host && (element === keyboard.host || keyboard.host.contains(element)));
  }

  /**
   * Whether this element may receive committed text. Password fields are
   * excluded by default: the overlay is for messages, not credentials.
   */
  function isAllowedTarget(element) {
    if (!element || isOurs(element)) return false;
    if (!kbIsEditable(element)) return false;
    if (getSettings().ignorePasswordFields !== false && kbIsPasswordField(element)) return false;
    return true;
  }

  /** The editable that committed text should land in. */
  function currentTarget() {
    const active = kbDeepActiveElement(doc);
    if (isAllowedTarget(active)) return active;
    if (lastEditable && lastEditable.isConnected && isAllowedTarget(lastEditable)) return lastEditable;
    return null;
  }

  function rememberTarget(element) {
    if (!element || isOurs(element)) return;
    if (!kbIsEditable(element)) return;
    lastEditable = isAllowedTarget(element) ? element : null;
  }

  function onFocusIn(event) {
    // Events raised inside the overlay show up here retargeted to its host
    // (the shadow root is closed), so both tests are needed.
    if (isOurs(event.target)) return;
    const path = typeof event.composedPath === 'function' ? event.composedPath() : [];
    if (path.includes(keyboard.host)) return;
    rememberTarget(event.target);
    if (keyboard.isOpen()) keyboard.setTarget(currentTarget());
  }

  function onKeydown(event) {
    const settings = getSettings();
    if (settings.enabled === false) return;
    const combo = kbParseHotkey(settings.hotkey);
    if (!kbHotkeyMatches(combo, event)) return;
    if (event.repeat) {
      event.preventDefault();
      return;
    }
    event.preventDefault();
    event.stopPropagation();
    if (typeof event.stopImmediatePropagation === 'function') event.stopImmediatePropagation();
    toggle();
  }

  function open(target) {
    const resolved = target || currentTarget();
    rememberTarget(resolved);
    return keyboard.open(resolved || lastEditable);
  }

  function close(reason) {
    keyboard.close(reason || 'api');
  }

  function toggle() {
    if (keyboard.isOpen()) {
      close('toggled');
      return false;
    }
    open();
    return true;
  }

  win.addEventListener('keydown', onKeydown, true);
  doc.addEventListener('focusin', onFocusIn, true);

  if (adapter.subscribeSettings) {
    adapter.subscribeSettings(() => keyboard.refreshSettings());
  }

  function destroy() {
    win.removeEventListener('keydown', onKeydown, true);
    doc.removeEventListener('focusin', onFocusIn, true);
    keyboard.destroy();
  }

  return {
    keyboard,
    open,
    close,
    toggle,
    destroy,
    getTarget: currentTarget,
    isOpen: () => keyboard.isOpen(),
    isOurs,
    hotkeyDescription: () => getSettings().hotkey
  };
}
