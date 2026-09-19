/**
 * Test helper: make a jsdom event look like one a real keyboard produced.
 *
 * jsdom marks every event it dispatches as `isTrusted === false`, and exposes
 * that as a non-configurable accessor on the event wrapper, so the only place
 * that can change it is the internal implementation object (whose own
 * `isTrusted` property is configurable and gets reset on every dispatch, hence
 * a getter rather than a value).
 *
 * The capture feature deliberately ignores untrusted events — a page script
 * must not be able to type plaintext into the buffer on the user's behalf — so
 * tests that exercise the physical-keyboard path have to simulate trust here.
 */
import { createRequire } from 'node:module';

let implSymbol = null;
try {
  const require = createRequire(import.meta.url);
  implSymbol = require('jsdom/lib/jsdom/living/generated/utils.js').implSymbol || null;
} catch (error) {
  implSymbol = null;
}

/** Whether this jsdom build lets the helper reach the internal event object. */
export function canSimulateTrustedEvent() {
  return !!implSymbol;
}

/**
 * Marks `event` as trusted for the duration of its dispatch.
 * @returns {boolean} true when the event could be marked.
 */
export function markTrusted(event) {
  if (!implSymbol) return false;
  const impl = event && event[implSymbol];
  if (!impl) return false;
  try {
    Object.defineProperty(impl, 'isTrusted', { configurable: true, get: () => true, set() {} });
    return true;
  } catch (error) {
    return false;
  }
}

/** Builds a keyboard event that looks like a physical keystroke. */
export function physicalKey(window, key, overrides = {}) {
  const event = new window.KeyboardEvent('keydown', {
    key, bubbles: true, cancelable: true, ...overrides
  });
  markTrusted(event);
  return event;
}
