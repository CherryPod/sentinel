// @ts-check
/**
 * Activity view — a friendly, user-meaningful timeline.
 *
 * v1 sources (client-side only, by design — the raw log stream is
 * admin-gated server-side and must not be consumed here):
 *   - chat history (localStorage): tasks asked, completions, guardian stops
 *   - routines API: recent executions
 */

import '../../components/lit/cherry-empty-state.js';
import { apiGet, ENDPOINTS } from '../../core/api.js';
import { capture } from '../../core/errors.js';
import { registerView } from '../../core/router.js';
import { escapeHtml, loadHistory } from '../../core/ui-helpers.js';

const MAX_ITEMS = 50;

/**
 * @param {number|undefined} ts
 * @returns {string}
 */
function timeLabel(ts) {
  if (!ts) return '';
  const d = new Date(ts);
  const today = new Date();
  const sameDay = d.toDateString() === today.toDateString();
  const hm = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  return sameDay ? hm : `${d.toLocaleDateString([], { day: 'numeric', month: 'short' })} ${hm}`;
}

function historyItems() {
  const items = [];
  const history = loadHistory();
  for (const entry of history) {
    if (entry.role === 'user') {
      items.push({ ts: entry.ts, icon: '💬', cls: 'ask', text: `You asked: ${entry.text}` });
    } else if (entry.role === 'guardian') {
      items.push({ ts: entry.ts, icon: '🛡', cls: 'stop', text: `Stopped for safety: ${entry.text}` });
    } else if (entry.role === 'error') {
      items.push({ ts: entry.ts, icon: '⚠', cls: 'error', text: entry.text });
    } else if (entry.role === 'results') {
      items.push({ ts: entry.ts, icon: '✓', cls: 'done', text: 'Task completed' });
    }
  }
  return items;
}

/** @param {HTMLElement} container */
function render(container) {
  container.innerHTML =
    '<div class="view-header"><h2>Activity</h2></div>' +
    '<div class="view-content activity-content">' +
    '<div id="activity-list" class="activity-list"></div>' +
    '</div>';
}

/** @param {Array<{ts?: number, icon: string, cls: string, text: string}>} items */
function renderList(items) {
  const el = document.getElementById('activity-list');
  if (!el) return;
  if (items.length === 0) {
    el.innerHTML =
      '<cherry-empty-state pose="sleeping" ' +
      'message="Nothing here yet — when we get things done together, you’ll see it here."></cherry-empty-state>';
    return;
  }
  let html = '';
  for (const item of items.slice(0, MAX_ITEMS)) {
    html += `<div class="activity-row ${escapeHtml(item.cls)}">`;
    html += `<span class="activity-icon">${escapeHtml(item.icon)}</span>`;
    html += `<span class="activity-text">${escapeHtml(item.text)}</span>`;
    html += `<span class="activity-time">${escapeHtml(timeLabel(item.ts))}</span>`;
    html += '</div>';
  }
  el.innerHTML = html;
}

function load() {
  const items = historyItems();
  apiGet(ENDPOINTS.routine)
    .then((data) => {
      const routines = data.routines || data || [];
      for (const r of routines) {
        // The routines API serialises `last_run_at`; tolerate `last_run` too
        // (defensive against schema drift). The routines VIEW reads the bare
        // name and has the same latent mismatch — flagged for Phase 6.
        const lastRun = r.last_run_at || r.last_run;
        if (lastRun) {
          items.push({
            ts: Date.parse(lastRun) || undefined,
            icon: '⏰',
            cls: 'routine',
            text: `Routine ran: ${r.name}`,
          });
        }
      }
      items.sort((a, b) => (b.ts || 0) - (a.ts || 0));
      renderList(items);
    })
    .catch((err) => {
      capture({ component: 'activity', action: 'load', error: err });
      items.sort((a, b) => (b.ts || 0) - (a.ts || 0));
      renderList(items);
    });
}

registerView({
  id: 'activity',
  label: 'Activity',
  icon:
    '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2">' +
    '<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>' +
    '</svg>',
  navOrder: 5,
  render: render,
  load: load,
  unload: () => {},
});
