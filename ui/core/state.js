/**
 * Centralised state store with event subscriptions.
 *
 * Replaces scattered mutable globals with a single observable store.
 * Subscribers are notified synchronously on change (value !== previous).
 *
 * Usage:
 *   import { get, set, subscribe } from './core/state.js';
 *   const unsub = subscribe('isProcessing', (val, prev) => { ... });
 *   set('isProcessing', true);
 *   get('isProcessing');  // true
 *   unsub();
 *
 * Keys migrated in Phase 1b:
 *   - transportType: 'ws' | 'sse' | 'http' | null
 *   - isProcessing: boolean (task in flight)
 *   - currentView: string (active view name)
 *   - lastHealthData: object | null (cached health response)
 *
 * Additional keys will migrate as views are extracted (Phase 2a/2b).
 */

const store = {
  transportType: null,
  isProcessing: false,
  currentView: 'chat',
  lastHealthData: null,
  // Single source of truth for the connection status indicator.
  // Values: 'offline' | 'ws' | 'sse' | 'http' | 'unhealthy'
  // Updated by both transport layer and health check — subscribers
  // render the status dot/text, avoiding two independent writers.
  connectionStatus: 'offline',
  // User role from /api/auth/me — set by settings.js fetchAuthMe().
  // Used by router to filter nav and gate navigation to role-restricted views.
  userRole: null,
};

const listeners = new Map();

/**
 * Get a state value.
 * @param {string} key
 * @returns {*}
 */
export function get(key) {
  return store[key];
}

/**
 * Set a state value. Notifies subscribers only if the value changed.
 * @param {string} key
 * @param {*} value
 */
export function set(key, value) {
  const prev = store[key];
  store[key] = value;
  if (prev !== value) {
    notify(key, value, prev);
  }
}

/**
 * Subscribe to changes on a specific key.
 * @param {string} key - State key to watch
 * @param {Function} fn - Called with (newValue, previousValue)
 * @returns {Function} Unsubscribe function
 */
export function subscribe(key, fn) {
  if (!listeners.has(key)) listeners.set(key, new Set());
  listeners.get(key).add(fn);
  return () => {
    listeners.get(key).delete(fn);
  };
}

/**
 * Notify all subscribers for a key.
 * @param {string} key
 * @param {*} value
 * @param {*} prev
 */
function notify(key, value, prev) {
  const subs = listeners.get(key);
  if (subs) {
    subs.forEach((fn) => {
      try {
        fn(value, prev);
      } catch (err) {
        console.error(`[state] subscriber error for ${key}:`, err);
      }
    });
  }
}
