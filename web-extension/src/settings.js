/**
 * KryptBoard — settings + passphrase vault.
 *
 * Settings live in chrome.storage.sync (they contain no secrets). The
 * passphrase is *never* written to sync/local storage: when the user opts
 * into "remember for this tab" it goes to chrome.storage.session, which is
 * extension-only storage that pages cannot read and that the browser wipes
 * when the session ends.
 */

export const KB_SETTINGS_KEY = 'kryptboard:settings';
export const KB_PASSPHRASE_KEY = 'kryptboard:passphrase';

/** The single source of truth for defaults, mirrored in the options UI. */
export const KB_DEFAULT_SETTINGS = Object.freeze({
  enabled: true,
  hotkey: 'Ctrl+Shift+K',
  startMode: 'encrypted', // 'plain' | 'encrypted'
  theme: 'dark', // 'dark' | 'light' | 'auto'
  closeAfterSend: true,
  clearBufferOnClose: true,
  keepOpenAfterCopy: true,
  autoDetectEnvelope: true,
  hardenedKdf: false,
  pbkdf2Iterations: 200000,
  aad: '',
  commitStyle: 'auto', // 'auto' | 'native' | 'execCommand'
  ignorePasswordFields: true,
  hideOnEscape: true,
  showHints: true
});

export const KB_SETTING_BOUNDS = Object.freeze({
  pbkdf2Iterations: { min: 1000, max: 5000000, step: 1000 }
});

export const KB_MODES = Object.freeze(['plain', 'encrypted']);
export const KB_THEMES = Object.freeze(['dark', 'light', 'auto']);
export const KB_COMMIT_STYLES = Object.freeze(['auto', 'native', 'execCommand']);
export const KB_HOTKEY_PRESETS = Object.freeze([
  'Ctrl+Shift+K',
  'Ctrl+Shift+Space',
  'Alt+Shift+K',
  'Ctrl+Shift+E'
]);

const KB_BOOL_KEYS = [
  'enabled',
  'closeAfterSend',
  'clearBufferOnClose',
  'keepOpenAfterCopy',
  'autoDetectEnvelope',
  'hardenedKdf',
  'ignorePasswordFields',
  'hideOnEscape',
  'showHints'
];

/**
 * Normalises untrusted input (storage may hold anything after a downgrade or
 * a manual edit) into a valid settings object. Unknown keys are dropped.
 */
export function kbNormalizeSettings(raw) {
  const input = raw && typeof raw === 'object' ? raw : {};
  const out = { ...KB_DEFAULT_SETTINGS };

  for (const key of KB_BOOL_KEYS) {
    if (typeof input[key] === 'boolean') out[key] = input[key];
  }

  if (KB_MODES.includes(input.startMode)) out.startMode = input.startMode;
  if (KB_THEMES.includes(input.theme)) out.theme = input.theme;
  if (KB_COMMIT_STYLES.includes(input.commitStyle)) out.commitStyle = input.commitStyle;
  if (typeof input.hotkey === 'string' && kbIsValidHotkey(input.hotkey)) out.hotkey = input.hotkey;

  const bounds = KB_SETTING_BOUNDS.pbkdf2Iterations;
  const iterations = Number.parseInt(input.pbkdf2Iterations, 10);
  if (Number.isFinite(iterations)) {
    out.pbkdf2Iterations = Math.min(bounds.max, Math.max(bounds.min, Math.round(iterations / bounds.step) * bounds.step));
  }

  if (typeof input.aad === 'string') out.aad = input.aad.slice(0, 256);
  return out;
}

/** "Ctrl+Shift+K" → { ctrl, shift, alt, meta, key } (or null when unusable). */
export function kbParseHotkey(spec) {
  if (typeof spec !== 'string') return null;
  const parts = spec.split('+').map((p) => p.trim()).filter(Boolean);
  if (!parts.length) return null;
  const combo = { ctrl: false, shift: false, alt: false, meta: false, key: null };
  for (const part of parts) {
    const low = part.toLowerCase();
    if (low === 'ctrl' || low === 'control') combo.ctrl = true;
    else if (low === 'shift') combo.shift = true;
    else if (low === 'alt' || low === 'option') combo.alt = true;
    else if (low === 'cmd' || low === 'meta' || low === 'command') combo.meta = true;
    else combo.key = part.length === 1 ? part.toLowerCase() : low;
  }
  if (!combo.key) return null;
  if (!combo.ctrl && !combo.alt && !combo.meta) return null; // modifiers are mandatory
  return combo;
}

export function kbIsValidHotkey(spec) {
  return kbParseHotkey(spec) !== null;
}

/** Does a KeyboardEvent match a parsed combo? */
export function kbHotkeyMatches(combo, event) {
  if (!combo || !event) return false;
  const key = typeof event.key === 'string' ? event.key.toLowerCase() : '';
  const code = typeof event.code === 'string' ? event.code.toLowerCase() : '';
  const codeFallback = code.startsWith('key') ? code.slice(3) : code;
  const wanted = combo.key;
  const keyMatches = key === wanted || codeFallback === wanted || (wanted === 'space' && (key === ' ' || code === 'space'));
  if (!keyMatches) return false;
  return (
    !!combo.ctrl === (event.ctrlKey === true) &&
    !!combo.shift === (event.shiftKey === true) &&
    !!combo.alt === (event.altKey === true) &&
    !!combo.meta === (event.metaKey === true)
  );
}

/**
 * Storage area adapter. Accepts anything shaped like chrome.storage
 * (promise-based get/set), or a plain in-memory object for tests.
 */
function kbStorageArea(area) {
  if (area && typeof area.get === 'function' && typeof area.set === 'function') return area;
  const memory = new Map();
  return {
    async get(key) {
      const out = {};
      const keys = typeof key === 'string' ? [key] : Array.isArray(key) ? key : Object.keys(key || {});
      for (const k of keys) if (memory.has(k)) out[k] = memory.get(k);
      return out;
    },
    async set(obj) {
      for (const [k, v] of Object.entries(obj)) memory.set(k, v);
    },
    async remove(key) {
      for (const k of [].concat(key)) memory.delete(k);
    }
  };
}

/**
 * Settings store.
 * @param {object} [area] chrome.storage.sync (or a memory area in tests)
 */
export function kbCreateSettingsStore(area, options = {}) {
  const storage = kbStorageArea(area);
  const key = options.key || KB_SETTINGS_KEY;
  let cache = { ...KB_DEFAULT_SETTINGS };
  let loaded = false;
  const listeners = new Set();
  // Bumped by every mutation so an in-flight load() cannot clobber a change
  // that arrived while it was waiting (e.g. the popup saving settings in
  // another tab while this page is still booting).
  let revision = 0;

  async function load() {
    const startedAt = revision;
    let raw = null;
    try {
      const got = await storage.get(key);
      raw = got ? got[key] : null;
    } catch (e) {
      raw = null; // storage unavailable → defaults, never throw into the page
    }
    if (revision !== startedAt) return { ...cache }; // newer state wins
    cache = kbNormalizeSettings(raw);
    loaded = true;
    return cache;
  }

  function get() {
    if (!loaded) cache = kbNormalizeSettings(cache);
    return { ...cache };
  }

  async function save(patch) {
    const next = kbNormalizeSettings({ ...cache, ...(patch || {}) });
    cache = next;
    loaded = true;
    revision++;
    try {
      await storage.set({ [key]: next });
    } catch (e) {
      /* keep the in-memory value; the UI surfaces the failure via the caller */
      throw e;
    }
    emit(next);
    return { ...next };
  }

  function reset() {
    return save({ ...KB_DEFAULT_SETTINGS });
  }

  function emit(value) {
    for (const fn of listeners) {
      try {
        fn({ ...value });
      } catch (e) {
        /* a bad listener must not break the store */
      }
    }
  }

  function subscribe(fn) {
    listeners.add(fn);
    return () => listeners.delete(fn);
  }

  function applyExternal(raw) {
    revision++;
    cache = kbNormalizeSettings(raw);
    emit(cache);
    return { ...cache };
  }

  return { key, load, get, save, reset, subscribe, applyExternal, isLoaded: () => loaded };
}

/**
 * Passphrase vault.
 *
 * - `remember === false` → the passphrase lives only in this closure
 *   (i.e. in the content-script instance for this tab).
 * - `remember === true`  → chrome.storage.session, which pages cannot read
 *   and which the browser clears when the session ends.
 * Nothing is ever written to disk.
 */
export function kbCreatePassphraseVault(options = {}) {
  const session = options.sessionArea ? kbStorageArea(options.sessionArea) : null;
  const key = options.key || KB_PASSPHRASE_KEY;
  let inMemory = '';
  let remembered = false;

  async function load() {
    if (!session) return inMemory;
    try {
      const got = await session.get(key);
      const value = got ? got[key] : '';
      if (typeof value === 'string' && value) {
        inMemory = value;
        remembered = true;
      }
    } catch (e) {
      /* treat as empty */
    }
    return inMemory;
  }

  async function get() {
    return inMemory;
  }

  async function set(passphrase, remember) {
    inMemory = typeof passphrase === 'string' ? passphrase : '';
    remembered = remember === true;
    if (!session) return;
    try {
      if (remembered && inMemory) await session.set({ [key]: inMemory });
      else await session.remove(key);
    } catch (e) {
      /* in-memory copy still works */
    }
  }

  async function clear() {
    inMemory = '';
    remembered = false;
    if (session) {
      try {
        await session.remove(key);
      } catch (e) {
        /* ignore */
      }
    }
  }

  return {
    load,
    get,
    set,
    clear,
    has: () => inMemory.length > 0,
    isRemembered: () => remembered
  };
}
