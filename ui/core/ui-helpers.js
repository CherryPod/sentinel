/**
 * UI helper utilities — DOM manipulation, escaping, toasts, timestamps, UUIDs.
 *
 * These are pure functions with no dependencies on app state,
 * making them safe to import from any module.
 */

import {
  MAX_HISTORY_ENTRIES,
  MAX_VISIBLE_TOASTS,
  SESSION_KEY,
  STORAGE_KEY,
  TOAST_ANIMATION_DELAY_MS,
  TOAST_AUTO_DISMISS_MS,
} from './constants.js';
import { capture } from './errors.js';
// escapeHtml moved to ./text.js (node-testable, DOM-compatible). Imported (so
// showToast below keeps a local binding) and re-exported so all existing
// consumers keep importing it from ui-helpers unchanged.
import { escapeHtml, escapeAttr, isSafeUrl } from './text.js';

export { escapeHtml, escapeAttr, isSafeUrl };

// ── Toast notifications ──────────────────────────────────────

let toastContainer = null;
let toastDelegationBound = false;

/** Lazily resolve the toast container — called after DOM is ready. */
function getToastContainer() {
  if (!toastContainer) {
    toastContainer = document.getElementById('toast-container');
  }
  // Bind delegation once on the long-lived container
  if (toastContainer && !toastDelegationBound) {
    toastContainer.addEventListener('click', (e) => {
      const closeBtn = e.target.closest('.toast-close');
      if (closeBtn) {
        const toast = closeBtn.closest('.toast');
        if (toast) dismissToast(toast);
      }
    });
    toastDelegationBound = true;
  }
  return toastContainer;
}

export function showToast(message, type) {
  type = type || 'info';
  const container = getToastContainer();
  if (!container) return;

  // Cap at MAX_VISIBLE_TOASTS visible toasts
  const toasts = container.querySelectorAll('.toast:not(.removing)');
  if (toasts.length >= MAX_VISIBLE_TOASTS) {
    dismissToast(toasts[0]);
  }

  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.innerHTML =
    '<span class="toast-message">' +
    escapeHtml(message) +
    '</span>' +
    '<button class="toast-close" aria-label="Dismiss">&times;</button>';

  container.appendChild(toast);
  setTimeout(() => {
    dismissToast(toast);
  }, TOAST_AUTO_DISMISS_MS);
}

export function dismissToast(toast) {
  if (!toast || toast.classList.contains('removing')) return;
  toast.classList.add('removing');
  setTimeout(() => {
    toast.remove();
  }, TOAST_ANIMATION_DELAY_MS);
}

// ── DOM utilities ────────────────────────────────────────────

export function scrollToBottom(el) {
  el.scrollTop = el.scrollHeight;
}

export function removeElement(id) {
  const el = document.getElementById(id);
  if (el) el.remove();
}

// ── Timestamps ───────────────────────────────────────────────

export function formatTimestamp() {
  const d = new Date();
  return d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
}

export function formatTime(isoStr) {
  if (!isoStr) return 'N/A';
  try {
    const d = new Date(isoStr);
    return d.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
  } catch (e) {
    capture({
      component: 'ui-helpers',
      action: 'formatTime',
      error: e,
      context: { inputLength: isoStr ? isoStr.length : 0 },
    });
    return isoStr;
  }
}

// ── UUID + Session ───────────────────────────────────────────

export function makeUUID() {
  return crypto.randomUUID();
}

export function getSessionId() {
  let sid = sessionStorage.getItem(SESSION_KEY);
  if (!sid) {
    sid = makeUUID();
    sessionStorage.setItem(SESSION_KEY, sid);
  }
  return sid;
}

export function resetSessionId() {
  const sid = makeUUID();
  sessionStorage.setItem(SESSION_KEY, sid);
  return sid;
}

// ── localStorage history ─────────────────────────────────────
// Q-002: History is stored as plaintext JSON. localStorage is same-origin
// protected; encrypting it client-side wouldn't add real security since the
// key would also be accessible to the same origin.

export function loadHistory() {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY)) || [];
  } catch (e) {
    capture({
      component: 'ui-helpers',
      action: 'loadHistory',
      error: e,
      context: { detail: 'corrupt localStorage JSON, resetting' },
    });
    return [];
  }
}

export function saveHistory(history) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(history));
  } catch (e) {
    capture({
      component: 'ui-helpers',
      action: 'saveHistory',
      error: e,
      context: { detail: 'localStorage quota exceeded' },
    });
    showToast('Chat history storage full — oldest entries may be lost', 'warning');
  }
}

export function appendToHistory(entry) {
  entry.ts = Date.now();
  const history = loadHistory();
  history.push(entry);
  if (history.length > MAX_HISTORY_ENTRIES) history.splice(0, history.length - MAX_HISTORY_ENTRIES);
  saveHistory(history);
}

export function clearHistory() {
  localStorage.removeItem(STORAGE_KEY);
}
