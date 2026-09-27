/**
 * Transport layer — WebSocket → SSE → HTTP polling fallback.
 *
 * Manages WS connection lifecycle (connect, auth, reconnect) and
 * emits parsed messages through the event bus. UI code subscribes
 * to events instead of handling raw WS frames.
 *
 * Events emitted:
 *   transport:connected     — WS auth succeeded
 *   transport:disconnected  — WS closed (reconnecting or fallen back)
 *   transport:status        — { type: 'ws'|'sse'|'http' } — transport changed
 *   ws:message              — { type, data } — raw parsed WS message
 *   ws:error                — { reason } — server error message
 *   task:event              — { taskId, event, data } — task.*.* events
 *   approval:result         — { data } — approval_result message
 *   routine:event           — { data } — routine_event message
 */

import { isAuthenticated } from './auth.js';
import { TRANSPORT_INIT_DELAY_MS, WS_AUTH_TIMEOUT_MS, WS_MAX_RECONNECT, WS_RECONNECT_BASE_MS } from './constants.js';
import { capture } from './errors.js';
import { emit } from './events.js';
import { get, set } from './state.js';

// ── Internal state ───────────────────────────────────────────

let ws = null;
let wsReconnectAttempts = 0;

// ── WebSocket URL ────────────────────────────────────────────

function getWsUrl() {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${proto}//${location.host}/ws`;
}

// ── Connection ───────────────────────────────────────────────

/**
 * Attempt a WebSocket connection with auth handshake.
 * Resolves true if connected, false if failed.
 * @returns {Promise<boolean>}
 */
function connectWs() {
  return new Promise((resolve) => {
    try {
      // Browser sends HttpOnly session cookie automatically on same-origin WS upgrade.
      // Server authenticates from the cookie, accepts, and sends { type: 'auth_ok' }.
      const socket = new WebSocket(getWsUrl());
      const authTimeout = setTimeout(() => {
        socket.close();
        resolve(false);
      }, WS_AUTH_TIMEOUT_MS);

      socket.onmessage = (event) => {
        let msg;
        try {
          msg = JSON.parse(event.data);
        } catch (e) {
          capture({
            component: 'transport',
            action: 'wsAuthParse',
            error: e,
            context: { dataLength: event.data ? event.data.length : 0 },
          });
          return;
        }
        if (msg.type === 'auth_ok') {
          clearTimeout(authTimeout);
          ws = socket;
          wsReconnectAttempts = 0;
          setTransportType('ws');
          socket.onmessage = onWsMessage;
          socket.onclose = onWsClose;
          emit('transport:connected', {});
          resolve(true);
        } else if (msg.type === 'auth_error') {
          clearTimeout(authTimeout);
          socket.close();
          resolve(false);
        }
      };

      socket.onerror = () => {
        clearTimeout(authTimeout);
        resolve(false);
      };
      socket.onclose = () => {
        clearTimeout(authTimeout);
        resolve(false);
      };
    } catch (e) {
      capture({ component: 'transport', action: 'connectWs', error: e });
      resolve(false);
    }
  });
}

// ── WS message handler registry ─────────────────────────────
// Map of message type → handler function. New server message types
// register a handler instead of adding an if/else branch.

const wsHandlers = new Map();

/**
 * Register a handler for a WS message type.
 * @param {string} type - Message type key (e.g. 'approval_result')
 * @param {function(Object, Object): void} fn - Handler receiving (msg, data)
 */
export function registerWsHandler(type, fn) {
  wsHandlers.set(type, fn);
}

// ── Built-in handlers ───────────────────────────────────────

registerWsHandler('error', (msg, data) => {
  emit('ws:error', { reason: msg.reason || data.reason || 'Unknown WebSocket error' });
});

registerWsHandler('approval_result', (_msg, data) => {
  emit('approval:result', { data: data });
});

registerWsHandler('routine_event', (_msg, data) => {
  emit('routine:event', { data: data });
});

// ── Message dispatch ────────────────────────────────────────

/**
 * Parse and route incoming WS messages through the handler registry.
 * Task events use dotted types ("task.<id>.<event>") and are routed
 * via prefix match before the registry lookup.
 * Unrecognised types fall through to the ws:message event.
 */
function onWsMessage(event) {
  let msg;
  try {
    msg = JSON.parse(event.data);
  } catch (e) {
    capture({
      component: 'transport',
      action: 'wsMessageParse',
      error: e,
      context: { dataLength: event.data ? event.data.length : 0 },
    });
    return;
  }
  const type = msg.type || '';
  const data = msg.data || {};

  // Task events use dotted types: "task.<id>.<event>"
  const parts = type.split('.');
  if (parts.length >= 3 && parts[0] === 'task') {
    emit('task:event', { taskId: parts[1], event: parts[2], data: data });
    return;
  }

  // Dispatch via handler registry; fall through for unrecognised types
  const handler = wsHandlers.get(type);
  if (handler) {
    handler(msg, data);
  } else {
    emit('ws:message', { type: type, data: data });
  }
}

// ── Close + reconnect ────────────────────────────────────────

function onWsClose() {
  ws = null;
  set('connectionStatus', 'offline');
  emit('transport:disconnected', {});

  if (wsReconnectAttempts < WS_MAX_RECONNECT) {
    wsReconnectAttempts++;
    const delay = WS_RECONNECT_BASE_MS * 2 ** (wsReconnectAttempts - 1);
    setTimeout(() => {
      // Don't attempt reconnect if user logged out during the delay
      if (!isAuthenticated()) return;
      connectWs().then((ok) => {
        if (!ok) {
          wsReconnectAttempts = 0;
          setTransportType('http');
        }
      });
    }, delay);
  } else {
    wsReconnectAttempts = 0;
    setTransportType('http');
  }
}

// ── Transport type management ────────────────────────────────

function setTransportType(type) {
  // Reset reconnect counter on HTTP fallback so future WS attempts
  // start from zero instead of immediately exhausting retries.
  if (type === 'http') wsReconnectAttempts = 0;
  set('transportType', type);
  // Update connectionStatus — the single source of truth for the UI
  // status indicator. Health check may override with 'unhealthy'/'offline',
  // but transport always reports the active transport type.
  if (type) set('connectionStatus', type);
  emit('transport:status', { type: type });
}

// ── Public API ───────────────────────────────────────────────

/**
 * Initialise the transport layer. Tries WS first, falls back to HTTP.
 */
export function initTransport() {
  if (isAuthenticated()) {
    connectWs().then((ok) => {
      if (!ok) setTransportType('http');
    });
  } else {
    setTransportType('http');
  }
}

/**
 * Send a JSON message over the WebSocket.
 * @param {Object} msg - Message to send
 * @throws {Error} If WS is not connected
 */
export function sendWs(msg) {
  if (!ws || ws.readyState !== WebSocket.OPEN) {
    throw new Error('WebSocket not connected');
  }
  ws.send(JSON.stringify(msg));
}

/**
 * Check if WebSocket is currently connected and authenticated.
 * @returns {boolean}
 */
export function isWsConnected() {
  return ws !== null && ws.readyState === WebSocket.OPEN;
}

/**
 * Get the current transport type.
 * @returns {'ws'|'sse'|'http'|null}
 */
export function getTransportType() {
  return get('transportType');
}

/**
 * Schedule transport init after a delay (used at app startup).
 */
export function scheduleInit() {
  setTimeout(initTransport, TRANSPORT_INIT_DELAY_MS);
}
