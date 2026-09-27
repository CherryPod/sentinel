// @ts-check
/**
 * Chat transcript surface — owns the message DOM, welcome state, and the
 * chatApi capability object handed to plan-gate components. No transport
 * or task-state knowledge lives here (guardrail: leaf UI module).
 */

import { cherrySvg } from '../../assets/cherry.js';
import { renderMarkdown } from '../../components/markdown.js';
import { appendToHistory, escapeHtml, formatTimestamp, removeElement, scrollToBottom } from '../../core/ui-helpers.js';

/** Sentinel message head: Cherry avatar + timestamp (replaces the caps label). */
export function sentinelHead() {
  return `<div class="msg-head">${cherrySvg('idle', 22)}<span class="msg-time">${formatTimestamp()}</span></div>`;
}

/**
 * Guardian-moment body (also used by history restore in chat.js).
 * @param {string} reason
 * @returns {string}
 */
export function guardianHtml(reason) {
  return (
    `<div class="guardian-head">${cherrySvg('alert', 26)}<span class="guardian-title">I stopped this task</span></div>` +
    `<div class="guardian-reason">${escapeHtml(reason)}</div>`
  );
}

/**
 * @param {{ messagesEl: HTMLElement, welcomeEl: HTMLElement|null, setInputEnabled: (on: boolean) => void }} deps
 */
export function createMessageSurface({ messagesEl, welcomeEl, setInputEnabled }) {
  function scrollMessages() {
    scrollToBottom(messagesEl);
  }

  function dismissWelcome() {
    if (welcomeEl) welcomeEl.style.display = 'none';
  }

  function showWelcome() {
    if (welcomeEl) welcomeEl.style.display = '';
  }

  /**
   * @param {string} type
   * @param {string} html
   * @param {string} [id]
   * @returns {HTMLElement}
   */
  function addMessage(type, html, id) {
    const div = document.createElement('div');
    div.className = `message ${type}`;
    if (id) div.id = id;
    div.innerHTML = html;
    messagesEl.appendChild(div);
    scrollMessages();
    return div;
  }

  /** @param {string} text */
  function addUserMessage(text) {
    dismissWelcome();
    addMessage('user', escapeHtml(text));
    appendToHistory({ role: 'user', text: text });
  }

  /** @param {string} text */
  function addSystemMessage(text) {
    addMessage('system', `${sentinelHead()}<div class="md-content">${renderMarkdown(text)}</div>`);
    appendToHistory({ role: 'system', text: text });
  }

  /**
   * @param {string} text
   * @param {string} [id]
   * @returns {HTMLElement}
   */
  function addStatusMessage(text, id) {
    return addMessage('status', `<span class="spinner"></span>${escapeHtml(text)}`, id);
  }

  /**
   * @param {string} id
   * @param {string} text
   */
  function updateStatusMessage(id, text) {
    const el = document.getElementById(id);
    if (el) el.innerHTML = `<span class="spinner"></span>${escapeHtml(text)}`;
  }

  /** @param {string} text */
  function addErrorMessage(text) {
    addMessage('error', escapeHtml(text));
    appendToHistory({ role: 'error', text: text });
  }

  /** @param {string} reason */
  function addGuardianMessage(reason) {
    addMessage('guardian', guardianHtml(reason));
    appendToHistory({ role: 'guardian', text: reason });
  }

  /** @param {string[]} warnings */
  function renderWarnings(warnings) {
    let html = sentinelHead();
    html += '<div class="conversation-warnings">';
    for (let i = 0; i < warnings.length; i++) {
      html += `<div class="conv-warning">⚠ ${escapeHtml(warnings[i])}</div>`;
    }
    html += '</div>';
    addMessage('system', html);
  }

  return {
    addMessage,
    addUserMessage,
    addSystemMessage,
    addStatusMessage,
    updateStatusMessage,
    addErrorMessage,
    addGuardianMessage,
    renderWarnings,
    dismissWelcome,
    showWelcome,
    scrollMessages,
    sentinelHead,
    setInputEnabled,
    appendToHistory,
    removeElement,
  };
}
