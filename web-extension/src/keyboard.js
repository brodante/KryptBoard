/**
 * KryptBoard — keyboard overlay (browser port of KeyboardRoot.kt)
 * =====================================================================
 * Behaviour parity with the Android IME:
 *
 *   Plain mode      keys are committed straight to the focused editable.
 *   Encrypted mode  keys accumulate in an on-screen buffer; "Encrypt & Send"
 *                   seals the buffer with ChaCha20-Poly1305 and commits the
 *                   envelope "v1|alg|nonce|ct|tag" instead of the plaintext.
 *                   The buffer is wiped the moment it has been sealed.
 *
 * The overlay lives in a closed-off shadow root so host-page CSS cannot
 * style it and cannot read its DOM. It is position:fixed, bottom-centred and
 * only ever mounted in the page it is invoked from — it makes no network
 * requests of any kind.
 */

import {
  KBError,
  kbEncrypt,
  kbDecrypt,
  kbEncryptWithKey,
  kbDecryptWithKey,
  kbEncryptToDict,
  kbDecryptFromDict,
  kbParseEnvelope,
  kbDescribeEnvelope,
  kbLooksLikeEnvelope,
  kbLooksLikeDict,
  kbIsSessionKeyAlgorithm,
  KB_ALGORITHM_SESSION,
  kbRandomBytes,
  kbUtf8,
  kbZeroizeBytes
} from './crypto.js';

/* ------------------------------------------------------------------ */
/* Layout                                                              */
/* ------------------------------------------------------------------ */

const L = (v) => ({ act: 'char', v, label: v });

export const KB_LAYOUTS = {
  letters: [
    '1234567890'.split('').map(L),
    'qwertyuiop'.split('').map(L),
    'asdfghjkl'.split('').map(L),
    [
      { act: 'shift', label: '⇧', cls: 'mod', title: 'Shift' },
      ...'zxcvbnm'.split('').map(L),
      { act: 'backspace', label: '⌫', cls: 'mod', title: 'Backspace' }
    ],
    [
      { act: 'layer', v: 'symbols', label: '?123', cls: 'mod', title: 'Numbers and symbols' },
      L(','),
      { act: 'space', label: 'space', cls: 'wide', title: 'Space' },
      L('.'),
      { act: 'enter', label: '⏎', cls: 'mod', title: 'Enter' }
    ]
  ],
  symbols: [
    '1234567890'.split('').map(L),
    ['@', '#', '$', '%', '&', '*', '-', '+', '(', ')'].map(L),
    ['/', '\\', ':', ';', '"', "'", '<', '>', '[', ']'].map(L),
    ['.', ',', '?', '!', '=', '_', '~', '^', '{', '}'].map(L),
    [
      { act: 'layer', v: 'letters', label: 'ABC', cls: 'mod', title: 'Letters' },
      L('€'),
      L('£'),
      { act: 'space', label: 'space', cls: 'wide', title: 'Space' },
      { act: 'backspace', label: '⌫', cls: 'mod', title: 'Backspace' },
      { act: 'enter', label: '⏎', cls: 'mod', title: 'Enter' }
    ]
  ]
};

/**
 * Resolves a layer into renderable key specs (pure — used by tests too).
 * @param {'letters'|'symbols'} layer
 * @param {{shift?: boolean, shiftLocked?: boolean}} [state]
 */
export function kbBuildKeyRows(layer, state = {}) {
  const rows = KB_LAYOUTS[layer] || KB_LAYOUTS.letters;
  const shifted = !!state.shift || !!state.shiftLocked;
  return rows.map((row) =>
    row.map((key) => {
      if (key.act === 'char') {
        const label = shifted && /[a-z]/.test(key.v) ? key.v.toUpperCase() : key.v;
        return { ...key, label };
      }
      if (key.act === 'shift') {
        return { ...key, label: state.shiftLocked ? '⇪' : '⇧', active: shifted };
      }
      return { ...key };
    })
  );
}

/* ------------------------------------------------------------------ */
/* Target editing primitives (plain-mode commits)                      */
/* ------------------------------------------------------------------ */

const KB_FIELD_SELECTOR = [
  'input:not([type])',
  'input[type="text"]', 'input[type="search"]', 'input[type="url"]', 'input[type="tel"]',
  'input[type="email"]', 'input[type="password"]', 'input[type="number"]',
  'textarea',
  '[contenteditable=""]', '[contenteditable="true"]', '[contenteditable="plaintext-only"]'
].join(', ');

/**
 * Rich-text detection. `isContentEditable` is the browser's own answer and
 * covers elements nested inside a contenteditable host, but some environments
 * do not implement it, so the attribute is checked as well.
 */
export function kbIsContentEditable(el) {
  if (!el || el.nodeType !== 1) return false;
  if (el.isContentEditable === true) return true;
  if (typeof el.matches !== 'function') return false;
  return el.matches('[contenteditable=""], [contenteditable="true"], [contenteditable="plaintext-only"]');
}

export function kbIsEditable(el) {
  if (!el || el.nodeType !== 1) return false;
  if (typeof el.matches !== 'function') return false;
  if (!el.isConnected) return false;
  if (el.matches('input, textarea') && (el.disabled || el.readOnly)) return false;
  if (el.matches('input, textarea') && el.matches(KB_FIELD_SELECTOR)) return true;
  return kbIsContentEditable(el);
}

export function kbIsPasswordField(el) {
  return !!(el && el.nodeType === 1 && el.matches && el.matches('input[type="password"]'));
}

export function kbDescribeTarget(el) {
  if (!el) return 'no field selected';
  const tag = el.tagName ? el.tagName.toLowerCase() : 'element';
  const id = el.id ? `#${el.id}` : '';
  const name = el.getAttribute && el.getAttribute('name') ? `[name="${el.getAttribute('name')}"]` : '';
  const placeholder = el.getAttribute && el.getAttribute('placeholder');
  return `${tag}${id}${name}${placeholder ? ` (“${placeholder.slice(0, 24)}”)` : ''}`;
}

function kbSetNativeValue(el, value) {
  // Walk the element's own prototype chain for the native value setter rather
  // than reaching for the script realm's globals: an element can belong to an
  // iframe (or any other realm) that owns different constructors. This also
  // bypasses framework value-tracker shims installed on the instance, which is
  // the entire point of the native-setter path.
  let proto = Object.getPrototypeOf(el);
  while (proto) {
    const descriptor = Object.getOwnPropertyDescriptor(proto, 'value');
    if (descriptor && descriptor.set) {
      descriptor.set.call(el, value);
      return;
    }
    proto = Object.getPrototypeOf(proto);
  }
  el.value = value;
}

function kbCreateInputEvent(doc, type, data, inputType) {
  const view = (doc && doc.defaultView) || null;
  const InputEventCtor = (view && view.InputEvent) || (typeof InputEvent !== 'undefined' ? InputEvent : null);
  try {
    if (!InputEventCtor) throw new Error('no InputEvent constructor');
    return new InputEventCtor(type, { bubbles: true, cancelable: type === 'beforeinput', composed: true, data, inputType });
  } catch (e) {
    const event = doc.createEvent('Event');
    event.initEvent(type, true, true);
    return event;
  }
}

/**
 * Inserts text into an <input>, <textarea> or contenteditable element the way
 * a user would: through the native value setter plus an InputEvent, so
 * framework-controlled fields (React, Vue, …) observe the change.
 */
export function kbInsertText(el, text, options = {}) {
  const doc = (el && el.ownerDocument) || document;
  if (!kbIsEditable(el)) return { ok: false, reason: 'not-editable' };

  const before = kbCreateInputEvent(doc, 'beforeinput', text, 'insertText');
  if (el.dispatchEvent && !el.dispatchEvent(before)) {
    return { ok: false, reason: 'cancelled' };
  }

  if (kbIsContentEditable(el)) {
    const selection = doc.getSelection();
    if (!selection || selection.rangeCount === 0) {
      el.focus();
      const range = doc.createRange();
      range.selectNodeContents(el);
      range.collapse(false);
      selection?.removeAllRanges();
      selection?.addRange(range);
    }
    const sel = doc.getSelection();
    const range = sel.getRangeAt(0);
    range.deleteContents();
    const node = doc.createTextNode(text);
    range.insertNode(node);
    range.setStartAfter(node);
    range.collapse(true);
    sel.removeAllRanges();
    sel.addRange(range);
    el.dispatchEvent(kbCreateInputEvent(doc, 'input', text, 'insertText'));
    return { ok: true };
  }

  const value = typeof el.value === 'string' ? el.value : '';
  let start = typeof el.selectionStart === 'number' ? el.selectionStart : value.length;
  let end = typeof el.selectionEnd === 'number' ? el.selectionEnd : start;
  if (start === null || end === null) {
    start = value.length;
    end = value.length;
  }
  let next = value.slice(0, start) + text + value.slice(end);
  let inserted = text;
  const maxLength = typeof el.maxLength === 'number' ? el.maxLength : -1;
  if (maxLength >= 0 && next.length > maxLength) {
    // Honour the field's own maxlength instead of bypassing it, but keep the
    // text that already sits after the caret — dropping it would silently
    // destroy the user's existing input.
    const room = Math.max(0, maxLength - (value.length - (end - start)));
    inserted = text.slice(0, room);
    next = (value.slice(0, start) + inserted + value.slice(end)).slice(0, maxLength);
  }
  kbSetNativeValue(el, next);
  const caret = Math.min(next.length, start + inserted.length);
  try {
    el.setSelectionRange(caret, caret);
  } catch (e) {
    /* some input types (number, email) refuse selections */
  }
  el.dispatchEvent(kbCreateInputEvent(doc, 'input', text, 'insertText'));
  return { ok: true, caret };
}

/** Deletes one character (or the selection) backwards from the target. */
export function kbDeleteBackward(el) {
  const doc = (el && el.ownerDocument) || document;
  if (!kbIsEditable(el)) return { ok: false, reason: 'not-editable' };
  if (kbIsContentEditable(el)) {
    const selection = doc.getSelection();
    if (!selection || selection.rangeCount === 0) return { ok: false, reason: 'no-selection' };
    const range = selection.getRangeAt(0);
    if (range.collapsed) {
      if (range.startOffset === 0) return { ok: false, reason: 'at-start' };
      range.setStart(range.startContainer, range.startOffset - 1);
    }
    range.deleteContents();
    el.dispatchEvent(kbCreateInputEvent(doc, 'input', null, 'deleteContentBackward'));
    return { ok: true };
  }
  const value = typeof el.value === 'string' ? el.value : '';
  let start = typeof el.selectionStart === 'number' ? el.selectionStart : value.length;
  let end = typeof el.selectionEnd === 'number' ? el.selectionEnd : start;
  if (start === end) {
    if (start === 0) return { ok: false, reason: 'at-start' };
    start -= 1;
  }
  const next = value.slice(0, start) + value.slice(end);
  kbSetNativeValue(el, next);
  try {
    el.setSelectionRange(start, start);
  } catch (e) {
    /* ignore */
  }
  el.dispatchEvent(kbCreateInputEvent(doc, 'input', null, 'deleteContentBackward'));
  return { ok: true };
}

/**
 * Enter in plain mode: newline for multiline targets, otherwise let the page
 * run its own submit/action logic (search boxes, message boxes, …).
 */
export function kbCommitEnter(el, commitText) {
  if (!kbIsEditable(el)) return { ok: false, reason: 'not-editable' };
  const multiline = el.tagName === 'TEXTAREA' || kbIsContentEditable(el);
  if (multiline) return commitText('\n');
  const doc = el.ownerDocument || document;
  // Build the event with the target's own realm so it is a real KeyboardEvent
  // of that document, not of whichever realm this script runs in.
  const view = doc.defaultView || null;
  const KeyboardEventCtor = (view && view.KeyboardEvent) || (typeof KeyboardEvent !== 'undefined' ? KeyboardEvent : null);
  const event = KeyboardEventCtor
    ? new KeyboardEventCtor('keydown', {
        key: 'Enter', code: 'Enter', keyCode: 13, which: 13, bubbles: true, cancelable: true, composed: true
      })
    : new Event('keydown', { bubbles: true, cancelable: true });
  const notCancelled = el.dispatchEvent(event);
  if (notCancelled && el.form && typeof el.form.requestSubmit === 'function') {
    try {
      el.form.requestSubmit();
      return { ok: true, submitted: true };
    } catch (e) {
      /* fall through */
    }
  }
  return { ok: true, submitted: !notCancelled };
}

/**
 * Plain-mode text commit. `auto` prefers execCommand('insertText') *when the
 * target already owns focus* (it keeps the page's undo stack and framework
 * bindings intact) and falls back to the native-setter path otherwise.
 */
export function kbCommitToTarget(el, text, style = 'auto') {
  if (!kbIsEditable(el)) return { ok: false, reason: 'not-editable' };
  const doc = el.ownerDocument || document;
  if (style === 'execCommand') return kbCommitViaExecCommand(el, text);
  if (style === 'native') return kbInsertText(el, text);
  const ownsFocus = doc.activeElement === el || (el.getRootNode && el.getRootNode().activeElement === el);
  if (ownsFocus) {
    const viaCommand = kbCommitViaExecCommand(el, text);
    if (viaCommand.ok) return viaCommand;
  }
  return kbInsertText(el, text);
}

function kbCommitViaExecCommand(el, text) {
  // Use the element's own document: with all_frames the script runs once per
  // frame, but a same-origin iframe target can still belong to another one.
  const targetDocument = (el && el.ownerDocument) || document;
  try {
    if (typeof targetDocument.execCommand !== 'function') return { ok: false, reason: 'unsupported' };
    if (!targetDocument.execCommand('insertText', false, text)) return { ok: false, reason: 'refused' };
    return { ok: true, via: 'execCommand' };
  } catch (e) {
    return { ok: false, reason: 'threw' };
  }
}

/* ------------------------------------------------------------------ */
/* Keyboard component                                                  */
/* ------------------------------------------------------------------ */

/** 'envelope' | 'dict' | null — what the buffer appears to hold. */
export function kbDetectPayload(text) {
  const candidate = String(text || '').trim();
  if (!candidate) return null;
  if (kbLooksLikeDict(candidate)) return 'dict';
  if (kbLooksLikeEnvelope(candidate)) return 'envelope';
  return null;
}

const KB_HTML = `
<div class="kb" part="kb" hidden>
  <div class="kb-bar">
    <span class="kb-brand"><span class="kb-dot" aria-hidden="true"></span>KryptBoard</span>
    <span class="kb-target" title="Where committed text goes"></span>
    <span class="kb-bar-actions">
      <button type="button" class="kb-ghost kb-theme-btn" data-act="theme" title="Switch theme">◐</button>
      <button type="button" class="kb-ghost" data-act="hide" title="Hide the keyboard (Esc)">Hide ⎋</button>
    </span>
  </div>

  <div class="kb-panel">
    <div class="kb-row-top">
      <span class="kb-label">Plaintext buffer</span>
      <span class="kb-chips">
        <span class="kb-chip kb-chip-enc" data-role="enc-chip">🔒 ENCRYPTED</span>
        <span class="kb-chip kb-chip-env" data-role="env-chip" hidden>envelope detected</span>
        <span class="kb-count" data-role="count">0</span>
      </span>
    </div>

    <textarea class="kb-buffer" data-role="buffer" spellcheck="false" autocapitalize="off"
      autocomplete="off" autocorrect="off" placeholder="Keys land here…" rows="2"></textarea>

    <div class="kb-status" data-role="status" role="status" aria-live="polite"></div>

    <div class="kb-actions">
      <span class="kb-modes" role="group" aria-label="Input mode">
        <button type="button" class="kb-mode" data-act="mode" data-v="plain">Plain</button>
        <button type="button" class="kb-mode" data-act="mode" data-v="encrypted">Encrypted</button>
      </span>
      <span class="kb-spacer"></span>
      <button type="button" class="kb-act kb-ghost" data-act="copy" title="Copy buffer (or last envelope) to the clipboard">Copy</button>
      <button type="button" class="kb-act kb-ghost" data-act="decrypt" data-role="decrypt" title="Decrypt the envelope in the buffer" hidden>Decrypt</button>
      <button type="button" class="kb-act kb-ghost" data-act="paste" title="Paste from the clipboard">Paste</button>
      <button type="button" class="kb-act kb-ghost" data-act="clear" title="Wipe the buffer">Clear</button>
      <button type="button" class="kb-act kb-send" data-act="send" data-role="send">Encrypt &amp; Send</button>
    </div>

    <div class="kb-pass-row" data-role="pass-row" hidden>
      <input type="password" class="kb-pass" data-role="pass" placeholder="passphrase — kept in memory, never on disk"
        autocomplete="off" spellcheck="false" aria-label="Passphrase" />
      <label class="kb-remember" title="Kept in extension session storage; the page cannot read it">
        <input type="checkbox" data-role="remember" /> remember for this tab
      </label>
      <button type="button" class="kb-ghost" data-act="passphrase">Passphrase ⌃</button>
    </div>

    <div class="kb-hint" data-role="hint"></div>
  </div>

  <div class="kb-keys" data-role="keys"></div>
</div>`;

/**
 * @param {object} [options]
 * @param {Document} [options.doc]
 * @param {string} [options.cssHref]   URL of keyboard.css, injected as a <link> in the shadow root.
 * @param {string} [options.inlineCss] Raw CSS (used when there is no chrome.runtime URL).
 * @param {() => object} [options.getSettings] Current settings snapshot.
 * @param {() => Promise<string>} [options.getPassphrase]
 * @param {(p: string, remember: boolean) => Promise<void>} [options.savePassphrase]
 * @param {() => Uint8Array|null} [options.getSessionKey] paper §III single-session key
 * @param {() => string} [options.getSessionKeyFingerprint]
 * @param {(text: string, meta: object) => void} [options.onCommit] committed to the page
 * @param {(state: object) => void} [options.onStateChange]
 * @param {() => void} [options.onClose]
 */
export function kbCreateKeyboard(options = {}) {
  const doc = options.doc || (typeof document !== 'undefined' ? document : null);
  if (!doc) throw new Error('KryptBoard: no document available');

  const settings = () => (options.getSettings ? options.getSettings() : {});

  const host = doc.createElement('div');
  host.className = options.className || 'kryptboard-host';
  host.setAttribute('data-kryptboard', 'root');
  // Closed on purpose: page scripts must not be able to reach into the overlay
  // and read the plaintext buffer or the passphrase field. Everything that
  // needs to talk to the overlay holds a reference to this object instead.
  const shadow = host.attachShadow({ mode: 'closed' });

  if (options.inlineCss) {
    const style = doc.createElement('style');
    style.textContent = options.inlineCss;
    shadow.appendChild(style);
  } else if (options.cssHref) {
    const link = doc.createElement('link');
    link.rel = 'stylesheet';
    link.href = options.cssHref;
    shadow.appendChild(link);
  }

  const wrapper = doc.createElement('div');
  wrapper.innerHTML = KB_HTML;
  const root = wrapper.firstElementChild;
  shadow.appendChild(root);

  const refs = {
    host,
    shadow,
    root,
    buffer: shadow.querySelector('[data-role="buffer"]'),
    status: shadow.querySelector('[data-role="status"]'),
    count: shadow.querySelector('[data-role="count"]'),
    encChip: shadow.querySelector('[data-role="enc-chip"]'),
    envChip: shadow.querySelector('[data-role="env-chip"]'),
    send: shadow.querySelector('[data-role="send"]'),
    decrypt: shadow.querySelector('[data-role="decrypt"]'),
    keys: shadow.querySelector('[data-role="keys"]'),
    target: shadow.querySelector('.kb-target'),
    passRow: shadow.querySelector('[data-role="pass-row"]'),
    pass: shadow.querySelector('[data-role="pass"]'),
    remember: shadow.querySelector('[data-role="remember"]'),
    themeBtn: shadow.querySelector('.kb-theme-btn'),
    hint: shadow.querySelector('[data-role="hint"]')
  };

  const state = {
    open: false,
    mode: 'encrypted',
    layer: 'letters',
    shift: false,
    shiftLocked: false,
    buffer: '',
    status: '',
    statusKind: 'info',
    target: options.target || null,
    busy: false,
    passLoaded: false,
    lastEnvelope: '',
    theme: 'dark'
  };

  /* -------------------------- rendering -------------------------- */

  function renderKeys() {
    const rows = kbBuildKeyRows(state.layer, { shift: state.shift, shiftLocked: state.shiftLocked });
    refs.keys.textContent = '';
    for (const row of rows) {
      const rowEl = doc.createElement('div');
      rowEl.className = 'kb-keyrow';
      for (const spec of row) {
        const button = doc.createElement('button');
        button.type = 'button';
        button.className = `kb-key${spec.cls ? ` kb-key-${spec.cls}` : ''}${spec.active ? ' is-active' : ''}`;
        button.dataset.act = spec.act;
        if (spec.v !== undefined) button.dataset.v = spec.v;
        button.textContent = spec.label;
        button.title = spec.title || spec.label;
        button.tabIndex = -1;
        rowEl.appendChild(button);
      }
      refs.keys.appendChild(rowEl);
    }
  }

  function renderStatus() {
    refs.status.textContent = state.status;
    refs.status.dataset.kind = state.statusKind;
  }

  function renderMode() {
    for (const button of refs.root.querySelectorAll('.kb-mode')) {
      const active = button.dataset.v === state.mode;
      button.classList.toggle('is-active', active);
      button.setAttribute('aria-pressed', String(active));
    }
    const encrypted = state.mode === 'encrypted';
    refs.encChip.hidden = !encrypted;
    refs.encChip.textContent = encrypted
      ? (isHardened() ? '🔒 ENCRYPTED · PBKDF2' : '🔒 ENCRYPTED')
      : '';
    refs.send.textContent = encrypted ? 'Encrypt & Send' : 'Send';
    // Decrypt is offered whenever the buffer holds an envelope, in either
    // mode: pasting one in to read it is a normal thing to do.
    const detected = settings().autoDetectEnvelope ? kbDetectPayload(state.buffer.trim()) : null;
    refs.decrypt.hidden = !detected;
    refs.envChip.hidden = !detected;
    if (detected && refs.envChip) refs.envChip.textContent = detected === 'dict' ? 'kryptboard dictionary detected' : 'envelope detected';
    refs.root.dataset.mode = state.mode;
    refs.buffer.readOnly = !encrypted;
    refs.buffer.placeholder = encrypted
      ? 'Keys land here — nothing is committed until you seal it…'
      : 'Plain mode: keys are committed straight to the field.';
    // the send button is only usable when there is something to send
    const canSend = state.buffer.length > 0 && !state.busy;
    refs.send.disabled = !canSend;
    refs.send.title = encrypted
      ? 'Seal the buffer and commit the ciphertext (Ctrl+Enter)'
      : 'Commit the buffer as plaintext (Ctrl+Enter)';
  }

  function renderHints() {
    const parts = [];
    parts.push('Ctrl+Shift+K toggle');
    parts.push('Esc hide');
    parts.push('Ctrl+Enter send');
    parts.push('Shift+←/→ select');
    refs.hint.textContent = settings().showHints === false ? '' : parts.join(' · ');
    refs.hint.hidden = settings().showHints === false;
  }

  function renderTarget() {
    refs.target.textContent = state.target ? `→ ${kbDescribeTarget(state.target)}` : '→ pick a text field';
    refs.target.classList.toggle('is-empty', !state.target);
  }

  function renderPassphrase() {
    const has = refs.pass.value.length > 0;
    refs.passRow.hidden = !(state.mode === 'encrypted' && (!has || passRowForced));
    refs.root.classList.toggle('kb-needs-pass', state.mode === 'encrypted' && !has);
    refs.remember.checked = state.rememberPassphrase === true;
  }

  let passRowForced = false;

  function isHardened() {
    return settings().hardenedKdf === true;
  }

  function renderAll() {
    renderKeys();
    renderMode();
    renderStatus();
    renderHints();
    renderTarget();
    renderPassphrase();
  }

  function updateCount() {
    const text = state.buffer;
    const bytes = kbUtf8(text).length;
    refs.count.textContent = text.length ? `${text.length} ch · ${bytes} B` : '0';
  }

  function syncBufferFromDom() {
    state.buffer = refs.buffer.value;
    updateCount();
    renderMode();
    notify();
  }

  function setStatus(text, kind = 'info') {
    state.status = text;
    state.statusKind = kind;
    renderStatus();
  }

  function notify() {
    if (typeof options.onStateChange === 'function') {
      try {
        options.onStateChange(getState());
      } catch (e) {
        /* ignore listener errors */
      }
    }
  }

  function getState() {
    return {
      open: state.open,
      mode: state.mode,
      layer: state.layer,
      shift: state.shift,
      shiftLocked: state.shiftLocked,
      buffer: state.buffer,
      status: state.status,
      statusKind: state.statusKind,
      busy: state.busy,
      target: state.target,
      lastEnvelope: state.lastEnvelope,
      theme: state.theme
    };
  }

  /* --------------------------- actions --------------------------- */

  function insertIntoBuffer(text) {
    if (state.mode !== 'encrypted') return false;
    const el = refs.buffer;
    const start = typeof el.selectionStart === 'number' ? el.selectionStart : el.value.length;
    const end = typeof el.selectionEnd === 'number' ? el.selectionEnd : start;
    el.setRangeText(text, start, end, 'end');
    syncBufferFromDom();
    return true;
  }

  function deleteFromBuffer() {
    const el = refs.buffer;
    const start = typeof el.selectionStart === 'number' ? el.selectionStart : el.value.length;
    const end = typeof el.selectionEnd === 'number' ? el.selectionEnd : start;
    if (start === end && start === 0) return;
    el.setRangeText('', start === end ? Math.max(0, start - 1) : start, end, 'end');
    syncBufferFromDom();
  }

  function commitToPage(text) {
    if (!state.target || !kbIsEditable(state.target)) {
      setStatus('No text field selected — click one, or use Copy to take the text with you.', 'warn');
      return false;
    }
    const result = kbCommitToTarget(state.target, text, settings().commitStyle);
    if (!result.ok) {
      setStatus(`Could not write into the field (${result.reason}). Try Copy instead.`, 'error');
      return false;
    }
    return true;
  }

  function applyMode(mode, announce = true) {
    if (mode !== 'plain' && mode !== 'encrypted') return;
    state.mode = mode;
    if (mode === 'encrypted') {
      refs.buffer.readOnly = false;
      focusBuffer();
      if (announce) {
        setStatus(
          'Encrypted mode — keystrokes are buffered here and sealed into a v1|CHACHA20-POLY1305 envelope on send.',
          'crypto'
        );
      }
    } else {
      passRowForced = false;
      if (announce) setStatus('Plain mode — keys are committed straight to the field.', 'info');
      focusTarget();
    }
    renderAll();
    notify();
  }

  function focusBuffer() {
    if (state.mode !== 'encrypted') return;
    try {
      refs.buffer.focus({ preventScroll: true });
    } catch (e) {
      /* ignore */
    }
  }

  function focusTarget() {
    if (state.target && kbIsEditable(state.target)) {
      try {
        state.target.focus({ preventScroll: true });
      } catch (e) {
        /* ignore */
      }
    }
  }

  /**
   * Types one character. The caller passes exactly what the key shows: for
   * character keys that is the rendered label (which already accounts for
   * shift and for the active layer), for the space key a literal space.
   */
  function handleChar(text) {
    const value = text == null ? '' : String(text);
    if (state.mode === 'encrypted') {
      insertIntoBuffer(value);
    } else {
      commitToPage(value);
      focusTarget(); // keep physical typing flowing into the field in plain mode
    }
    if (state.shift && !state.shiftLocked) {
      state.shift = false; // one-shot shift
      renderKeys();
    }
  }

  function handleBackspace() {
    if (state.mode === 'encrypted') deleteFromBuffer();
    else kbDeleteBackward(state.target);
  }

  function handleEnter() {
    if (state.mode === 'encrypted') {
      insertIntoBuffer('\n');
      return;
    }
    if (!state.target || !kbIsEditable(state.target)) {
      setStatus('No text field selected.', 'warn');
      return;
    }
    const result = kbCommitEnter(state.target, (text) => ({
      ok: kbCommitToTarget(state.target, text, settings().commitStyle).ok
    }));
    if (!result.ok) setStatus('Enter was not accepted by the field.', 'warn');
  }

  /** Copy of the tab's in-memory session key (paper §III), or null. */
  function sessionKey() {
    try {
      const key = options.getSessionKey ? options.getSessionKey() : null;
      return key && key.length ? key : null;
    } catch (e) {
      return null;
    }
  }

  function sessionFingerprint() {
    try {
      return options.getSessionKeyFingerprint ? options.getSessionKeyFingerprint() : '';
    } catch (e) {
      return '';
    }
  }

  /**
   * Seals the buffer and returns the payload to commit.
   *
   * Two key models are supported:
   *   passphrase  HKDF(/PBKDF2) from the passphrase → "v1|CHACHA20-POLY1305|…"
   *   session     the raw single-session key (paper Algorithm 1) → either the
   *               base64 dictionary or the equivalent envelope string.
   *
   * The plaintext is handed to the crypto layer in a scratch buffer that is
   * overwritten with zeros before this function returns.
   */
  async function sealBuffer(text, config, passphrase) {
    const scratch = new Uint8Array(text.length * 3);
    try {
      if (config.keyModel === 'session') {
        const key = sessionKey();
        if (config.sessionFormat === 'envelope') {
          const envelope = kbEncryptWithKey(text, key, { aad: config.aad || '', scratch });
          return { envelope, described: kbDescribeEnvelope(kbParseEnvelope(envelope)), label: 'session envelope', kind: 'envelope' };
        }
        // Algorithm 1's return value, as JSON — what the paper injects.
        const dict = kbEncryptToDict(text, key, { aad: config.aad || '', scratch });
        const envelope = JSON.stringify(dict);
        return {
          envelope,
          described: {
            plaintextBytes: text.length,
            envelopeBytes: envelope.length,
            algorithm: KB_ALGORITHM_SESSION,
            hardened: false,
            iterations: 0
          },
          label: 'session dictionary',
          kind: 'dict'
        };
      }
      const envelope = await kbEncrypt(text, passphrase, {
        aad: config.aad || '',
        hardened: config.hardenedKdf === true,
        iterations: config.pbkdf2Iterations,
        nonce: kbRandomBytes(12),
        scratch
      });
      return { envelope, described: kbDescribeEnvelope(kbParseEnvelope(envelope)), label: 'envelope', kind: 'envelope' };
    } finally {
      kbZeroizeBytes(scratch);
    }
  }

  async function handleSend() {
    const text = state.buffer;
    if (!text.length) {
      setStatus('Nothing to send yet.', 'warn');
      return;
    }
    const config = settings();

    if (state.mode === 'plain') {
      if (commitToPage(text)) {
        state.buffer = '';
        refs.buffer.value = '';
        updateCount();
        renderMode();
        setStatus('Plaintext committed.', 'ok');
        if (config.closeAfterSend !== false) close('sent');
      }
      return;
    }

    const useSessionKey = config.keyModel === 'session';
    let passphrase = '';
    if (!useSessionKey) {
      passphrase = refs.pass.value || (await resolvePassphrase());
      if (!passphrase) {
        passRowForced = true;
        renderPassphrase();
        setStatus('Set a passphrase first — it never leaves this machine and is never written to disk.', 'warn');
        refs.pass.focus();
        return;
      }
    } else if (!sessionKey()) {
      passRowForced = true;
      renderPassphrase();
      setStatus('This session has no key yet — generate one in the KryptBoard popup, then try again.', 'warn');
      return;
    }

    state.busy = true;
    renderMode();
    setStatus(useSessionKey ? 'Sealing with the session key…' : isHardened() ? 'Deriving key (PBKDF2)…' : 'Sealing…', 'info');

    try {
      const payload = await sealBuffer(text, config, passphrase);
      const envelope = payload.envelope;

      state.lastEnvelope = envelope;
      state.buffer = '';
      refs.buffer.value = '';
      updateCount();
      state.busy = false;

      const described = payload.described;
      let committed = false;
      if (config.closeAfterSend !== false) {
        // commit first, then close, so the field is still tracked
        committed = commitToPage(envelope);
      } else {
        committed = commitToPage(envelope);
      }

      if (committed) {
        setStatus(
          `Sealed ${described.plaintextBytes} B → ${described.envelopeBytes} B ${payload.label} and committed it. Buffer wiped.`,
          'ok'
        );
        // If we stay open, keep focus in the buffer so the next physical
        // keystrokes are buffered rather than leaking into the page field.
        focusBuffer();
      } else {
        await copyToClipboard(envelope);
        setStatus(
          `Sealed ${described.plaintextBytes} B → ${described.envelopeBytes} B. No field to write into, so the ${payload.label} is on your clipboard.`,
          'warn'
        );
      }

      if (config.closeAfterSend !== false) {
        close('sent');
        return;
      }
      renderAll();
      notify();
    } catch (error) {
      state.busy = false;
      renderMode();
      if (error instanceof KBError && error.code === 'NO_PASSPHRASE') {
        passRowForced = true;
        renderPassphrase();
        setStatus(error.message, 'warn');
        refs.pass.focus();
        return;
      }
      setStatus(`Encryption failed: ${error && error.message ? error.message : error}`, 'error');
    }
  }

  async function handleDecrypt() {
    const candidate = state.buffer.trim();
    const isDict = kbLooksLikeDict(candidate);
    const isEnvelope = !isDict && kbLooksLikeEnvelope(candidate);
    if (!isDict && !isEnvelope) {
      setStatus('The buffer does not hold a KryptBoard envelope or dictionary.', 'warn');
      return;
    }

    // Algorithm 1's dictionary is raw-key by construction, so it always needs
    // the session key; an envelope can need either model.
    let needsSessionKey = isDict;
    if (isEnvelope) {
      try {
        needsSessionKey = kbIsSessionKeyAlgorithm(kbParseEnvelope(candidate).alg);
      } catch (e) {
        needsSessionKey = false;
      }
    }

    let passphrase = '';
    if (needsSessionKey) {
      if (!sessionKey()) {
        setStatus('This message needs the session key — generate or import one in the KryptBoard popup.', 'warn');
        return;
      }
    } else {
      passphrase = refs.pass.value || (await resolvePassphrase());
      if (!passphrase) {
        passRowForced = true;
        renderPassphrase();
        setStatus('A passphrase is required to open the envelope.', 'warn');
        refs.pass.focus();
        return;
      }
    }

    setStatus(needsSessionKey ? 'Verifying tag with the session key…' : isHardened() ? 'Deriving key (PBKDF2)…' : 'Verifying tag and decrypting…', 'info');
    try {
      const aad = settings().aad || '';
      const plaintext = needsSessionKey
        ? (isDict ? kbDecryptFromDict(candidate, sessionKey(), { aad }) : kbDecryptWithKey(candidate, sessionKey(), { aad }))
        : await kbDecrypt(candidate, passphrase, { aad });
      const ciphertextBytes = isDict
        ? (candidate.match(/"ciphertext":"([^"]*)"/) ? Math.floor((candidate.match(/"ciphertext":"([^"]*)"/)[1].length * 3) / 4) : 0)
        : kbParseEnvelope(candidate).ct.length;
      state.buffer = plaintext;
      refs.buffer.value = plaintext;
      updateCount();
      setStatus(
        `AEAD tag verified ✓ — ${plaintext.length} characters recovered from a ${ciphertextBytes} B ciphertext${needsSessionKey ? ` (session key ${sessionFingerprint() || 'unknown'})` : ''}.`,
        'ok'
      );
      renderMode();
      notify();
    } catch (error) {
      const message = error instanceof KBError && error.code === 'AUTH_FAILED'
        ? 'Tag verification failed — wrong key, wrong context label, or the ciphertext was altered.'
        : (error && error.message) || String(error);
      setStatus(message, 'error');
    }
  }

  async function resolvePassphrase() {
    if (!options.getPassphrase) return '';
    try {
      const found = await options.getPassphrase();
      if (found) {
        refs.pass.value = found;
        state.passLoaded = true;
        return found;
      }
    } catch (e) {
      /* ignore */
    }
    return '';
  }

  async function persistPassphrase() {
    if (!options.savePassphrase) return;
    try {
      await options.savePassphrase(refs.pass.value, refs.remember.checked === true);
    } catch (e) {
      /* ignore */
    }
  }

  // The clipboard lives on the window that owns the document, not necessarily
  // on this script's realm (iframes and test harnesses differ).
  function clipboardApi() {
    const view = doc && doc.defaultView;
    return (view && view.navigator && view.navigator.clipboard) || (typeof navigator !== 'undefined' ? navigator.clipboard : null);
  }

  async function copyToClipboard(text) {
    const clipboard = clipboardApi();
    try {
      if (clipboard && clipboard.writeText) {
        await clipboard.writeText(text);
        return true;
      }
    } catch (e) {
      /* fall through to the legacy path */
    }
    try {
      const scratch = doc.createElement('textarea');
      scratch.value = text;
      scratch.setAttribute('aria-hidden', 'true');
      scratch.style.cssText = 'position:fixed;top:-1000px;left:-1000px;opacity:0;';
      doc.body.appendChild(scratch);
      scratch.select();
      const ok = doc.execCommand('copy');
      scratch.remove();
      return !!ok;
    } catch (e) {
      return false;
    }
  }

  async function handleCopy() {
    const text = state.buffer || state.lastEnvelope;
    if (!text) {
      setStatus('Nothing to copy.', 'warn');
      return;
    }
    const ok = await copyToClipboard(text);
    if (ok && settings().keepOpenAfterCopy === false) {
      close('copied');
      return;
    }
    setStatus(
      ok
        ? `Copied ${text.length} characters to the clipboard${state.buffer ? '' : ' (last envelope)'}.`
        : 'Could not reach the clipboard — select the text and copy manually.',
      ok ? 'ok' : 'error'
    );
  }

  async function handlePaste() {
    let text = '';
    const clipboard = clipboardApi();
    try {
      if (clipboard && clipboard.readText) text = await clipboard.readText();
    } catch (e) {
      text = '';
    }
    if (!text) {
      setStatus('Clipboard read was blocked — paste with the keyboard shortcut instead.', 'warn');
      return;
    }
    if (state.mode === 'encrypted') {
      insertIntoBuffer(text);
      setStatus(`Pasted ${text.length} characters into the buffer.`, 'ok');
    } else if (commitToPage(text)) {
      setStatus(`Pasted ${text.length} characters into the field.`, 'ok');
    }
  }

  function handleTheme() {
    const order = ['dark', 'light', 'auto'];
    const next = order[(order.indexOf(state.theme) + 1) % order.length];
    setTheme(next);
    if (options.onThemeChange) options.onThemeChange(next);
    setStatus(`Theme: ${next}.`, 'info');
  }

  function setTheme(theme) {
    state.theme = ['dark', 'light', 'auto'].includes(theme) ? theme : 'dark';
    refs.root.dataset.theme = state.theme;
    refs.themeBtn.textContent = state.theme === 'light' ? '☀' : state.theme === 'auto' ? '◐' : '☾';
    refs.themeBtn.title = `Theme: ${state.theme} (click to cycle)`;
  }

  function applyAction(act, value, element) {
    switch (act) {
      case 'char': {
        const label = element && typeof element.textContent === 'string' ? element.textContent : '';
        handleChar(label || value || '');
        break;
      }
      case 'space':
        handleChar(' ');
        break;
      case 'backspace':
        handleBackspace();
        break;
      case 'enter':
        handleEnter();
        break;
      case 'shift':
        if (state.shiftLocked) {
          state.shiftLocked = false;
          state.shift = false;
        } else if (state.shift) {
          state.shiftLocked = true;
        } else {
          state.shift = true;
        }
        renderKeys();
        break;
      case 'layer':
        state.layer = value === 'symbols' ? 'symbols' : 'letters';
        if (state.layer === 'letters') {
          state.shift = false;
          state.shiftLocked = false;
        }
        renderKeys();
        break;
      case 'mode':
        applyMode(value);
        break;
      case 'send':
        handleSend();
        break;
      case 'clear':
        state.buffer = '';
        refs.buffer.value = '';
        updateCount();
        setStatus('Buffer wiped.', 'info');
        renderMode();
        break;
      case 'copy':
        handleCopy();
        break;
      case 'paste':
        handlePaste();
        break;
      case 'decrypt':
        handleDecrypt();
        break;
      case 'passphrase':
        passRowForced = !passRowForced || refs.passRow.hidden;
        renderPassphrase();
        if (!refs.passRow.hidden) refs.pass.focus();
        break;
      case 'theme':
        handleTheme();
        break;
      case 'hide':
        close('hidden');
        break;
      default:
        setStatus(`Unknown key action “${act}”.`, 'error');
        break;
    }
    void element;
  }

  /* --------------------------- events ---------------------------- */

  function onClick(event) {
    const trigger = event.target && event.target.closest ? event.target.closest('[data-act]') : null;
    if (!trigger) return;
    if (trigger.disabled) return;
    event.preventDefault();
    event.stopPropagation();
    applyAction(trigger.dataset.act, trigger.dataset.v, trigger);
  }

  function onBufferInput() {
    syncBufferFromDom(); // also re-renders mode-dependent affordances (env chip, Decrypt)
    const text = state.buffer.trim();
    if (settings().autoDetectEnvelope && kbLooksLikeEnvelope(text)) {
      setStatus('Envelope detected — Decrypt is available.', 'crypto');
    } else if (state.mode === 'encrypted' && state.statusKind === 'crypto') {
      setStatus('', 'info');
    }
  }

  function onBufferKeydown(event) {
    if (event.key === 'Escape' && settings().hideOnEscape !== false) {
      event.preventDefault();
      close('esc');
      return;
    }
    if (event.key === 'Enter' && (event.ctrlKey || event.metaKey || event.shiftKey)) {
      event.preventDefault();
      handleSend();
      return;
    }
    if (event.key === 'Enter' && !event.shiftKey && !event.ctrlKey && !event.metaKey && !event.altKey) {
      event.preventDefault();
      if (state.mode === 'encrypted') insertIntoBuffer('\n');
      else handleEnter();
    }
  }

  /** Keeps page-level handlers from reacting to keystrokes made in the overlay. */
  /**
   * Everything typed into the overlay stays in the overlay. The buffer holds
   * plaintext, so its key/input/composition events must not reach the page's
   * listeners — they bubble out of the shadow root and would otherwise be
   * observable (retargeted to the host, but with `event.data` intact).
   */
  function onHostKeyEvent(event) {
    if (event.type === 'keydown' && event.key === 'Escape' && settings().hideOnEscape !== false) {
      close('esc');
    }
    event.stopPropagation();
  }

  // Attached in the *bubble* phase on purpose: a capture-phase listener here
  // would stopPropagation() before the buffer's own keydown handler ran, which
  // silently killed the Ctrl+Enter seal shortcut.
  const PRIVATE_EVENTS = [
    'keydown', 'keyup', 'keypress',
    'beforeinput', 'input',
    'compositionstart', 'compositionupdate', 'compositionend',
    'paste'
  ];

  function onHostMouseDown(event) {
    // Keep focus where it belongs: on the field (plain) or on the buffer (encrypted).
    const interactive = event.target && event.target.closest
      ? event.target.closest('input, textarea')
      : null;
    if (!interactive) event.preventDefault();
  }

  function onPassInput() {
    persistPassphrase();
    renderPassphrase();
    if (refs.pass.value) passRowForced = false;
  }

  function onRememberChange() {
    state.rememberPassphrase = refs.remember.checked === true;
    persistPassphrase();
  }

  root.addEventListener('mousedown', onHostMouseDown);
  root.addEventListener('click', onClick);
  for (const type of PRIVATE_EVENTS) root.addEventListener(type, onHostKeyEvent, false);
  refs.buffer.addEventListener('input', onBufferInput);
  refs.buffer.addEventListener('keydown', onBufferKeydown);
  refs.pass.addEventListener('input', onPassInput);
  refs.remember.addEventListener('change', onRememberChange);

  /* ------------------------- open / close ------------------------ */

  function mount() {
    if (!host.isConnected) doc.body.appendChild(host);
  }

  function open(target) {
    if (target) state.target = target;
    mount();
    const config = settings();
    if (!state.open) {
      state.mode = config.startMode === 'plain' ? 'plain' : 'encrypted';
      state.layer = 'letters';
      state.shift = false;
      state.shiftLocked = false;
    }
    setTheme(config.theme || 'dark');
    state.open = true;
    refs.root.hidden = false;
    renderAll();
    updateCount();
    if (state.mode === 'encrypted') {
      focusBuffer();
      if (refs.pass.value) setStatus('Encrypted mode — buffer is sealed on send.', 'crypto');
      else setStatus('Encrypted mode — set a passphrase, then type; nothing is committed until you seal it.', 'crypto');
    } else {
      focusTarget();
      setStatus('Plain mode — keys are committed straight to the field.', 'info');
    }
    if (typeof options.onOpen === 'function') options.onOpen(getState());
    notify();
    return getState();
  }

  function close(reason = 'closed') {
    if (!state.open) return;
    mount();
    state.open = false;
    refs.root.hidden = true;
    if (settings().clearBufferOnClose !== false && state.buffer && state.mode === 'encrypted') {
      state.buffer = '';
      refs.buffer.value = '';
      updateCount();
    }
    passRowForced = false;
    focusTarget();
    if (typeof options.onClose === 'function') options.onClose(reason, getState());
    notify();
  }

  function toggle(target) {
    if (state.open) {
      close('toggled');
      return false;
    }
    open(target);
    return true;
  }

  function setTarget(target) {
    state.target = target || null;
    renderTarget();
    if (!state.open) return;
    if (state.mode === 'plain') renderMode();
    notify();
  }

  function setBuffer(text) {
    state.buffer = String(text ?? '');
    refs.buffer.value = state.buffer;
    updateCount();
    renderMode();
    notify();
  }

  function setPassphrase(value) {
    refs.pass.value = String(value ?? '');
    state.passLoaded = refs.pass.value.length > 0;
    renderPassphrase();
  }

  function refreshSettings() {
    const config = settings();
    setTheme(config.theme || 'dark');
    if (config.startMode === 'plain' || config.startMode === 'encrypted') {
      // applies to the next open; an open keyboard keeps the user's choice
    }
    renderAll();
  }

  function destroy() {
    if (host.parentNode) host.parentNode.removeChild(host);
  }

  renderAll();
  setTheme((options.getSettings && options.getSettings().theme) || options.theme || 'dark');
  state.mode = options.mode || 'encrypted';
  state.rememberPassphrase = false;
  renderAll();
  updateCount();

  return {
    host,
    shadow,
    element: root,
    refs,
    open,
    close,
    toggle,
    isOpen: () => state.open,
    setTarget,
    getTarget: () => state.target,
    setMode: (mode) => applyMode(mode),
    getMode: () => state.mode,
    getBuffer: () => state.buffer,
    setBuffer,
    clearBuffer: () => setBuffer(''),
    getLastEnvelope: () => state.lastEnvelope,
    setPassphrase,
    getPassphraseInput: () => refs.pass.value,
    refreshSettings,
    setTheme,
    setStatus,
    getState,
    applyAction,
    handleSend,
    handleDecrypt,
    insertIntoBuffer,
    destroy
  };
}
