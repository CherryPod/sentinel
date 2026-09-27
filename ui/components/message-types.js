/**
 * Message type registry — extensible renderer dispatch for chat messages.
 *
 * Each message type (text, markdown, error, status, approval) registers
 * a renderer function.  New types (image, video, gallery) can be added
 * without modifying existing renderers.
 *
 * NOTE: Not yet wired into the main chat rendering path (Phase 2b).
 * Chat.js uses its own addMessage/addUserMessage/etc. inline functions.
 * This registry is forward-looking infrastructure — new message types
 * (image, video, gallery) should use registerRenderer rather than
 * adding more inline functions to chat.js.  Wiring existing types
 * through the registry is a future cleanup task.
 *
 * Usage:
 *   import { registerRenderer, renderMessage } from './message-types.js';
 *   registerRenderer('custom', function (data, container) { ... });
 *   renderMessage('custom', data, container);
 */

import { cherrySvg } from '../assets/cherry.js';
import { escapeHtml, formatTimestamp } from '../core/ui-helpers.js';
import { renderMarkdown } from './markdown.js';

const renderers = new Map();

/** Sentinel message head: Cherry avatar + timestamp (mirrors chat/messages.js). */
function sentinelHead() {
  return `<div class="msg-head">${cherrySvg('idle', 22)}<span class="msg-time">${formatTimestamp()}</span></div>`;
}

/**
 * Register a renderer for a message type.
 * @param {string} type - Message type key (e.g. 'text', 'markdown')
 * @param {function(Object, HTMLElement): void} fn - Renderer function
 */
export function registerRenderer(type, fn) {
  renderers.set(type, fn);
}

/**
 * Render a message using the registered renderer for its type.
 * Falls back to 'text' renderer if type is unknown.
 * @param {string} type - Message type key
 * @param {Object} data - Message data (shape varies by type)
 * @param {HTMLElement} container - Parent element to append into
 * @returns {HTMLElement} The created message element
 */
export function renderMessage(type, data, container) {
  const renderer = renderers.get(type) || renderers.get('text');
  return renderer(data, container);
}

// ── Built-in renderers ──────────────────────────────────────

/**
 * Create a message div with the given class and optional id.
 * Appends to container and returns the element.
 */
function createMessageEl(className, html, container, id) {
  const div = document.createElement('div');
  div.className = `message ${className}`;
  if (id) div.id = id;
  div.innerHTML = html;
  container.appendChild(div);
  return div;
}

registerRenderer('text', (data, container) =>
  createMessageEl('system', sentinelHead() + escapeHtml(data.text || ''), container),
);

registerRenderer('user', (data, container) => createMessageEl('user', escapeHtml(data.text || ''), container));

registerRenderer('markdown', (data, container) =>
  createMessageEl(
    'system',
    `${sentinelHead()}<div class="md-content">${renderMarkdown(data.text || '')}</div>`,
    container,
  ),
);

registerRenderer('error', (data, container) => createMessageEl('error', escapeHtml(data.text || ''), container));

registerRenderer('status', (data, container) =>
  createMessageEl('status', `<span class="spinner"></span>${escapeHtml(data.text || '')}`, container, data.id),
);

registerRenderer('warning', (data, container) => {
  let html = sentinelHead();
  html += '<div class="conversation-warnings">';
  const warnings = data.warnings || [];
  for (let i = 0; i < warnings.length; i++) {
    html += `<div class="conv-warning">\u26a0 ${escapeHtml(warnings[i])}</div>`;
  }
  html += '</div>';
  return createMessageEl('system', html, container);
});
