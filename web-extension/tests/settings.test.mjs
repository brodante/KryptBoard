/**
 * Settings + passphrase-vault tests.
 *
 * This layer holds the two things that must never be wrong: which fields are
 * excluded from targeting, and where the passphrase may be written. The tests
 * below are as much about the *negative* guarantees (the vault never touches
 * sync storage, normalisation never invents values) as about the happy path.
 */
import test from 'node:test';
import assert from 'node:assert/strict';

import {
  KB_DEFAULT_SETTINGS,
  KB_HOTKEY_PRESETS,
  KB_PASSPHRASE_KEY,
  KB_SETTINGS_KEY,
  KB_SETTING_BOUNDS,
  kbCreatePassphraseVault,
  kbCreateSettingsStore,
  kbHotkeyMatches,
  kbIsValidHotkey,
  kbNormalizeSettings,
  kbParseHotkey
} from '../src/settings.js';

/* ------------------------------------------------------------------ */
/* a chrome.storage-shaped double                                      */
/* ------------------------------------------------------------------ */

function fakeArea(seed = {}, options = {}) {
  const map = new Map(Object.entries(seed));
  const writes = [];
  return {
    map,
    writes,
    async get(keys) {
      if (options.getThrows) throw new Error('storage unavailable');
      const out = {};
      const list = typeof keys === 'string' ? [keys] : Array.isArray(keys) ? keys : Object.keys(keys || {});
      for (const key of list) if (map.has(key)) out[key] = map.get(key);
      return out;
    },
    async set(items) {
      if (options.setThrows) throw new Error('quota exceeded');
      writes.push({ ...items });
      for (const [key, value] of Object.entries(items)) map.set(key, value);
    },
    async remove(keys) {
      if (options.removeThrows) throw new Error('nope');
      writes.push({ removed: [].concat(keys) });
      for (const key of [].concat(keys)) map.delete(key);
    }
  };
}

const flatten = (value) => JSON.stringify(value ?? '');

/* ------------------------------------------------------------------ */
/* defaults + normalisation                                            */
/* ------------------------------------------------------------------ */

test('defaults are frozen and cover exactly the documented settings', () => {
  assert.equal(Object.isFrozen(KB_DEFAULT_SETTINGS), true);
  assert.deepEqual(Object.keys(KB_DEFAULT_SETTINGS).sort(), [
    'aad', 'autoDetectEnvelope', 'clearBufferOnClose', 'closeAfterSend', 'commitStyle',
    'enabled', 'hardenedKdf', 'hideOnEscape', 'hotkey', 'ignorePasswordFields',
    'keepOpenAfterCopy', 'keyModel', 'pbkdf2Iterations', 'sessionFormat', 'showHints',
    'startMode', 'theme'
  ]);
  // the security-relevant defaults must not silently flip
  assert.equal(KB_DEFAULT_SETTINGS.ignorePasswordFields, true);
  assert.equal(KB_DEFAULT_SETTINGS.autoDetectEnvelope, true);
  assert.equal(KB_DEFAULT_SETTINGS.hardenedKdf, false);
  assert.equal(KB_DEFAULT_SETTINGS.startMode, 'encrypted');
});

test('normalisation drops unknown keys and rejects values it cannot trust', () => {
  const result = kbNormalizeSettings({
    theme: 'neon',                     // not a known theme
    startMode: 'PLAIN',                // wrong case
    commitStyle: 'telepathy',          // not a known style
    hotkey: 'K',                       // no modifier → unusable
    pbkdf2Iterations: 'lots',          // not a number
    aad: 'x'.repeat(500),              // over-long
    enabled: 'yes',                    // not a boolean
    ignorePasswordFields: 0,           // not a boolean
    evil: { __proto__: { polluted: true } },
    __proto__: { polluted: true }
  });

  assert.equal(result.theme, KB_DEFAULT_SETTINGS.theme);
  assert.equal(result.startMode, KB_DEFAULT_SETTINGS.startMode);
  assert.equal(result.commitStyle, KB_DEFAULT_SETTINGS.commitStyle);
  assert.equal(result.hotkey, KB_DEFAULT_SETTINGS.hotkey);
  assert.equal(result.pbkdf2Iterations, KB_DEFAULT_SETTINGS.pbkdf2Iterations);
  assert.equal(result.enabled, KB_DEFAULT_SETTINGS.enabled, 'a string is not a boolean');
  assert.equal(result.ignorePasswordFields, KB_DEFAULT_SETTINGS.ignorePasswordFields);
  assert.equal(result.aad.length, 256);
  assert.equal(result.evil, undefined);
  assert.equal({}.polluted, undefined, 'prototype pollution must not happen');
  assert.equal(Object.keys(result).length, Object.keys(KB_DEFAULT_SETTINGS).length);
});

test('normalisation keeps valid input and clamps the work factor', () => {
  const bounds = KB_SETTING_BOUNDS.pbkdf2Iterations;
  assert.equal(kbNormalizeSettings({ theme: 'light' }).theme, 'light');
  assert.equal(kbNormalizeSettings({ startMode: 'plain' }).startMode, 'plain');
  assert.equal(kbNormalizeSettings({ hardenedKdf: true }).hardenedKdf, true);
  assert.equal(kbNormalizeSettings({ pbkdf2Iterations: 1 }).pbkdf2Iterations, bounds.min);
  assert.equal(kbNormalizeSettings({ pbkdf2Iterations: 1e12 }).pbkdf2Iterations, bounds.max);
  assert.equal(kbNormalizeSettings({ pbkdf2Iterations: 20449 }).pbkdf2Iterations, 20000, 'snapped to the step');
});

test('normalisation tolerates every kind of garbage input', () => {
  for (const input of [null, undefined, 'string', 42, [], true, () => {}, Symbol('x')]) {
    const result = kbNormalizeSettings(input);
    assert.deepEqual(result, { ...KB_DEFAULT_SETTINGS }, `failed for ${String(input)}`);
  }
});

/* ------------------------------------------------------------------ */
/* hotkeys                                                             */
/* ------------------------------------------------------------------ */

test('hotkey presets parse, and unusable specs are rejected', () => {
  for (const preset of KB_HOTKEY_PRESETS) {
    assert.equal(kbIsValidHotkey(preset), true, preset);
  }
  for (const bad of ['', 'K', 'Shift', 'Ctrl', 'Ctrl+Shift', '+', null, undefined, 42, {}]) {
    assert.equal(kbIsValidHotkey(bad), false, String(bad));
  }
  assert.equal(kbParseHotkey('ctrl + shift + k').ctrl, true);
  assert.equal(kbParseHotkey('ctrl + shift + k').key, 'k');
  assert.equal(kbParseHotkey('Alt+Shift+K').alt, true);
});

test('hotkey matching requires the modifiers to match exactly', () => {
  const combo = kbParseHotkey('Ctrl+Shift+K');
  const event = (overrides) => ({
    key: 'k', code: 'KeyK', ctrlKey: false, shiftKey: false, altKey: false, metaKey: false, ...overrides
  });

  assert.equal(kbHotkeyMatches(combo, event({ ctrlKey: true, shiftKey: true })), true, 'exact match');
  assert.equal(kbHotkeyMatches(combo, event({ ctrlKey: true })), false, 'shift missing');
  assert.equal(kbHotkeyMatches(combo, event({ ctrlKey: true, shiftKey: true, altKey: true })), false, 'extra modifier');
  assert.equal(kbHotkeyMatches(combo, event({ ctrlKey: true, shiftKey: true, metaKey: true })), false, 'extra meta');
  assert.equal(kbHotkeyMatches(combo, event({ ctrlKey: true, shiftKey: true, key: 'j', code: 'KeyJ' })), false, 'other key');
  assert.equal(kbHotkeyMatches(null, event({ ctrlKey: true, shiftKey: true })), false, 'no combo');
  assert.equal(kbHotkeyMatches(combo, null), false, 'no event');

  // "Space" arrives as " " with code "Space"
  const space = kbParseHotkey('Ctrl+Shift+Space');
  assert.equal(kbHotkeyMatches(space, event({ ctrlKey: true, shiftKey: true, key: ' ', code: 'Space' })), true);
  assert.equal(kbHotkeyMatches(space, event({ ctrlKey: true, shiftKey: true, key: 'Space', code: 'Space' })), true);

  // keys are case-insensitive and work when only `code` is reliable
  assert.equal(kbHotkeyMatches(combo, event({ ctrlKey: true, shiftKey: true, key: 'K' })), true);
  assert.equal(kbHotkeyMatches(combo, event({ ctrlKey: true, shiftKey: true, key: 'Unidentified', code: 'KeyK' })), true);
});

/* ------------------------------------------------------------------ */
/* settings store                                                      */
/* ------------------------------------------------------------------ */

test('the store loads defaults, merges patches, resets and notifies subscribers', async () => {
  const area = fakeArea();
  const store = kbCreateSettingsStore(area);
  const seen = [];
  const unsubscribe = store.subscribe((value) => seen.push(value.theme));

  assert.deepEqual(store.get(), { ...KB_DEFAULT_SETTINGS }, 'defaults before load');
  await store.load();
  assert.equal(store.isLoaded(), true);

  await store.save({ theme: 'light' });
  assert.equal(store.get().theme, 'light');
  assert.equal(store.get().startMode, KB_DEFAULT_SETTINGS.startMode, 'other settings are untouched');
  assert.deepEqual(area.map.get(KB_SETTINGS_KEY).theme, 'light', 'written under the documented key');

  await store.save({ theme: 'auto', aad: 'room-42' });
  assert.equal(store.get().theme, 'auto');
  assert.equal(store.get().aad, 'room-42');

  await store.reset();
  assert.deepEqual(store.get(), { ...KB_DEFAULT_SETTINGS });

  assert.deepEqual(seen, ['light', 'auto', 'dark']);
  unsubscribe();
  await store.save({ theme: 'light' });
  assert.deepEqual(seen, ['light', 'auto', 'dark'], 'unsubscribed listeners stop receiving updates');
});

test('the store hands out copies, so callers cannot mutate stored state', async () => {
  const store = kbCreateSettingsStore(fakeArea());
  await store.load();
  const first = store.get();
  first.theme = 'hacked';
  first.ignorePasswordFields = false;
  assert.equal(store.get().theme, KB_DEFAULT_SETTINGS.theme);
  assert.equal(store.get().ignorePasswordFields, true, 'a mutated copy must not disable the password guard');
});

test('the store tolerates storage that is broken in either direction', async () => {
  const unreadable = kbCreateSettingsStore(fakeArea({}, { getThrows: true }));
  assert.deepEqual(await unreadable.load(), { ...KB_DEFAULT_SETTINGS }, 'unreadable storage falls back to defaults');

  const unwritable = kbCreateSettingsStore(fakeArea({}, { setThrows: true }));
  await unwritable.load();
  await assert.rejects(() => unwritable.save({ theme: 'light' }), /quota/);
  assert.equal(unwritable.get().theme, 'light', 'the in-memory value survives a failed write');
});

test('external changes (another tab writing settings) are applied', async () => {
  const store = kbCreateSettingsStore(fakeArea());
  await store.load();
  const applied = store.applyExternal({ theme: 'light', pbkdf2Iterations: 999999999 });
  assert.equal(applied.theme, 'light');
  assert.equal(applied.pbkdf2Iterations, KB_SETTING_BOUNDS.pbkdf2Iterations.max, 'external input is normalised too');
  assert.equal(store.get().theme, 'light');
});

/* ------------------------------------------------------------------ */
/* passphrase vault                                                    */
/* ------------------------------------------------------------------ */

test('the vault keeps the passphrase in memory unless it is told to remember', async () => {
  const session = fakeArea();
  const vault = kbCreatePassphraseVault({ sessionArea: session });
  await vault.load();
  assert.equal(vault.has(), false);

  await vault.set('correct horse', false);
  assert.equal(await vault.get(), 'correct horse');
  assert.equal(vault.has(), true);
  assert.equal(vault.isRemembered(), false);
  assert.equal(flatten([...session.map.entries()]).includes('correct horse'), false,
    'without "remember" the passphrase must not be written anywhere');

  await vault.set('correct horse', true);
  assert.equal(vault.isRemembered(), true);
  assert.equal(session.map.get(KB_PASSPHRASE_KEY), 'correct horse');

  await vault.clear();
  assert.equal(vault.has(), false);
  assert.equal(await vault.get(), '');
  assert.equal(session.map.has(KB_PASSPHRASE_KEY), false, 'clearing must remove the session copy');
});

test('the vault restores a remembered passphrase, but never writes it to sync settings', async () => {
  const session = fakeArea({ [KB_PASSPHRASE_KEY]: 'remembered-secret' });
  const sync = fakeArea();
  const vault = kbCreatePassphraseVault({ sessionArea: session });
  await vault.load();
  assert.equal(await vault.get(), 'remembered-secret');
  assert.equal(vault.isRemembered(), true);

  // the settings store is the only thing allowed near sync storage
  const store = kbCreateSettingsStore(sync);
  await store.load();
  await store.save({ theme: 'light' });
  const synced = flatten([...sync.map.entries()]);
  assert.equal(synced.includes('remembered-secret'), false, 'the passphrase must never reach sync storage');
  // No secret material may live in settings: no passphrase/secret field, and
  // no value that looks like key material (the key *model* is just a name).
  const settings = JSON.parse(JSON.stringify(sync.map.get(KB_SETTINGS_KEY)));
  for (const name of Object.keys(settings)) {
    assert.equal(/passphrase|secret|keybytes|sessionkey/i.test(name), false, `settings must not carry "${name}"`);
  }
  for (const value of Object.values(settings)) {
    assert.equal(typeof value === 'string' && /^kbk1\./.test(value), false, 'a session key must never reach sync storage');
  }
});

test('a vault with no session storage still works in memory only', async () => {
  const vault = kbCreatePassphraseVault();
  await vault.set('memory-only', true);
  assert.equal(await vault.get(), 'memory-only');
  assert.equal(vault.isRemembered(), true);
  await vault.clear();
  assert.equal(await vault.get(), '');
});

test('a vault whose session storage throws degrades to memory', async () => {
  const vault = kbCreatePassphraseVault({ sessionArea: fakeArea({}, { setThrows: true, removeThrows: true, getThrows: true }) });
  await vault.load();
  await vault.set('still-works', true);
  assert.equal(await vault.get(), 'still-works');
  await vault.clear();
  assert.equal(await vault.get(), '');
});

test('a change that lands mid-load is not clobbered by the initial load', async () => {
  // storage answers slowly, exactly like a real page booting while another tab
  // (or the popup) writes settings
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const area = {
    async get() {
      await gate;
      return { 'kryptboard:settings': { enabled: true, hotkey: 'Ctrl+Shift+K' } };
    },
    async set() {}
  };

  const store = kbCreateSettingsStore(area);
  const pending = store.load();
  const pushed = store.applyExternal({ enabled: false, hotkey: 'Alt+Shift+K' });
  assert.equal(pushed.enabled, false);

  release();
  const loaded = await pending;
  assert.equal(loaded.enabled, false, 'the newer value must win');
  assert.equal(store.get().enabled, false);
  assert.equal(store.get().hotkey, 'Alt+Shift+K');
});

test('a save during a pending load also wins', async () => {
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const stored = {};
  const area = {
    async get() {
      await gate;
      return { 'kryptboard:settings': { theme: 'light' } };
    },
    async set(items) {
      Object.assign(stored, items);
    }
  };

  const store = kbCreateSettingsStore(area);
  const pending = store.load();
  await store.save({ theme: 'dark' });
  release();
  await pending;
  assert.equal(store.get().theme, 'dark', 'local intent beats stale storage');
  assert.equal(stored['kryptboard:settings'].theme, 'dark');
});
