/**
 * Typed event bus for cross-component communication.
 *
 * Decouples producers (transport, state) from consumers (views, components).
 * Handlers are called synchronously in registration order.
 *
 * Usage:
 *   import { on, emit, off } from './core/events.js';
 *   const unsub = on('task:completed', (data) => { ... });
 *   emit('task:completed', { taskId, status: 'success' });
 *   unsub();  // or: off('task:completed', handler);
 */

const handlers = new Map();

/**
 * Subscribe to an event.
 * @param {string} event - Event name (e.g. 'transport:connected', 'task:completed')
 * @param {Function} fn - Handler function, receives event data
 * @returns {Function} Unsubscribe function
 */
export function on(event, fn) {
  if (!handlers.has(event)) handlers.set(event, new Set());
  handlers.get(event).add(fn);
  return () => {
    handlers.get(event).delete(fn);
  };
}

/**
 * Emit an event to all subscribers.
 * @param {string} event - Event name
 * @param {*} [data] - Event payload
 */
export function emit(event, data) {
  const subs = handlers.get(event);
  if (subs) {
    subs.forEach((fn) => {
      try {
        fn(data);
      } catch (err) {
        console.error(`[events] handler error for ${event}:`, err);
      }
    });
  }
}

/**
 * Remove a specific handler for an event.
 * @param {string} event - Event name
 * @param {Function} fn - Handler to remove
 */
export function off(event, fn) {
  const subs = handlers.get(event);
  if (subs) subs.delete(fn);
}

/**
 * Remove all handlers for an event (or all events if no name given).
 * Primarily for testing and cleanup.
 * @param {string} [event] - Event name, or omit to clear all
 */
export function clear(event) {
  if (event) {
    handlers.delete(event);
  } else {
    handlers.clear();
  }
}
