// @ts-check

import { describeTrigger } from '../../assets/cron-describe.js';
import { escapeHtml, formatTime } from '../../core/ui-helpers.js';

export const TRIGGER_HINTS = {
  cron: '5-field cron expression (e.g. 0 9 * * *)',
  event: 'Event topic pattern (e.g. task.*.completed)',
  interval: 'Number of seconds between runs',
};

export const TRIGGER_PLACEHOLDERS = {
  cron: '0 9 * * *',
  event: 'task.*.completed',
  interval: '3600',
};

/**
 * Build the HTML for a single routine card (header, details, history toggle).
 *
 * @param {{
 *   id?: string,
 *   enabled?: boolean,
 *   name?: string,
 *   trigger_config?: string,
 *   trigger_type?: string,
 *   next_run_at?: string,
 *   next_run?: string,
 *   last_run_at?: string,
 *   last_run?: string,
 *   cooldown_s?: number,
 * }} r
 * @returns {string}
 */
export function buildRoutineCardHtml(r) {
  const enabledClass = r.enabled ? 'enabled' : 'disabled';
  const safeId = escapeHtml(r.id);
  const schedule = escapeHtml(describeTrigger(r));
  const lastRunAt = r.last_run_at || r.last_run;
  const nextRunAt = r.next_run_at || r.next_run;

  let html = `<div class="routine-card ${enabledClass}" data-routine-id="${safeId}">`;
  html += '<div class="routine-header">';
  html += '<div class="routine-title">';
  html += `<h4>${escapeHtml(r.name)}</h4>`;
  html += `<div class="routine-schedule">${schedule}</div>`;
  html += '</div>';
  html += '<div class="routine-actions">';
  html += '<label class="toggle">';
  html += `<input type="checkbox" class="routine-toggle" data-id="${safeId}"${r.enabled ? ' checked' : ''} aria-label="Enable routine">`;
  html += '<span class="toggle-slider"></span>';
  html += '</label>';
  html += '</div>';
  html += '</div>';

  html += '<div class="routine-details">';
  if (lastRunAt) {
    html += `<span class="pill ${r.enabled ? 'ok' : 'off'}">Last ran ${escapeHtml(formatTime(lastRunAt))}</span>`;
  } else {
    html += '<span class="pill off">Never run yet</span>';
  }
  if (nextRunAt && r.enabled) {
    html += `<span class="routine-detail">Next: ${escapeHtml(formatTime(nextRunAt))}</span>`;
  }
  if (r.cooldown_s != null && r.cooldown_s > 0) {
    html += `<span class="routine-detail precise-only">Cooldown: ${escapeHtml(String(r.cooldown_s))}s</span>`;
  }
  // trigger_config is a dict from the API ({"cron": "..."} etc.) — render it
  // readably for the precise-mode operator line, not as "[object Object]".
  const triggerConfigText =
    r.trigger_config && typeof r.trigger_config === 'object'
      ? JSON.stringify(r.trigger_config)
      : String(r.trigger_config || '');
  html += `<span class="routine-detail precise-only">${escapeHtml(r.trigger_type || '')}: ${escapeHtml(triggerConfigText)}</span>`;
  html += '</div>';

  html += '<div class="routine-footer">';
  html += `<button class="btn btn-sm btn-run" data-id="${safeId}">Run now</button>`;
  html += `<button class="btn btn-sm btn-history" data-id="${safeId}">Show history</button>`;
  html += `<button class="btn btn-sm danger btn-delete" data-id="${safeId}">Delete</button>`;
  html += '</div>';

  // exec-history is a SIBLING of the footer, not inside the flex button row —
  // otherwise the expanded table renders crammed in among the buttons.
  html += `<div class="exec-history" id="exec-history-${safeId}" style="display:none;"></div>`;

  html += '</div>';
  return html;
}

/**
 * @param {Array<{
 *   duration_s?: number | null,
 *   error?: string,
 *   started_at?: string,
 *   status?: string,
 * }>} executions
 * @returns {string}
 */
export function buildExecHistoryTableHtml(executions) {
  let html =
    '<table class="exec-table"><thead><tr>' +
    '<th>Status</th><th>Started</th><th>Duration</th><th>Error</th>' +
    '</tr></thead><tbody>';

  for (let i = 0; i < executions.length; i++) {
    const ex = executions[i];
    const duration = ex.duration_s != null ? `${ex.duration_s}s` : '--';
    const statusClass = ex.status === 'success' ? 'ok' : ex.status === 'error' ? 'fail' : 'warn';
    html +=
      '<tr>' +
      '<td><span class="exec-status ' +
      statusClass +
      '">' +
      escapeHtml(ex.status || 'unknown') +
      '</span></td>' +
      '<td>' +
      escapeHtml(formatTime(ex.started_at)) +
      '</td>' +
      '<td>' +
      escapeHtml(duration) +
      '</td>' +
      '<td>' +
      escapeHtml(ex.error || '--') +
      '</td>' +
      '</tr>';
  }

  html += '</tbody></table>';
  return html;
}

/**
 * @returns {string}
 */
export function buildCreateFormHtml() {
  return (
    '<div class="routine-create-form" id="routine-create-form" style="display:none;">' +
    '<h3>Create Routine</h3>' +
    '<div class="form-group">' +
    '<label for="routine-name">Name</label>' +
    '<input type="text" id="routine-name" class="form-input" placeholder="My routine">' +
    '</div>' +
    '<div class="form-group">' +
    '<label for="routine-trigger-type">Trigger Type</label>' +
    '<select id="routine-trigger-type" class="form-input">' +
    '<option value="cron">Cron</option>' +
    '<option value="event">Event</option>' +
    '<option value="interval">Interval</option>' +
    '</select>' +
    '</div>' +
    '<div class="form-group">' +
    '<label for="routine-trigger-config">Trigger Config</label>' +
    '<input type="text" id="routine-trigger-config" class="form-input" placeholder="' +
    TRIGGER_PLACEHOLDERS.cron +
    '">' +
    '<small class="form-hint" id="trigger-hint">' +
    TRIGGER_HINTS.cron +
    '</small>' +
    '</div>' +
    '<div class="form-group">' +
    '<label for="routine-prompt">Prompt</label>' +
    '<textarea id="routine-prompt" class="form-input" rows="3" placeholder="What should this routine do?"></textarea>' +
    '</div>' +
    '<div class="form-group">' +
    '<label for="routine-cooldown">Cooldown (seconds)</label>' +
    '<input type="number" id="routine-cooldown" class="form-input" value="0" min="0">' +
    '</div>' +
    '<div class="form-actions">' +
    '<button class="btn btn-primary" id="btn-create-routine">Create</button>' +
    '<button class="btn" id="btn-cancel-create">Cancel</button>' +
    '</div>' +
    '</div>'
  );
}
