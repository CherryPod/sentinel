// @ts-check
/**
 * Overview metrics panel — leaf UI module.
 *
 * Owns the Session (operator) card, the Metrics section (trust meter,
 * story strip, and the precise-only funnel/outcomes/scanner/routine/
 * response-time grids), and their DOM updaters. Builders and updaters
 * are co-located (guardrail #1): the shell renders via
 * `buildSessionHtml`/`buildMetricsHtml` and refreshes via
 * `renderMetrics(resp)`.
 *
 * No transport/state knowledge here — the shell fetches and captures.
 */

import { escapeHtml } from '../../core/ui-helpers.js';

// Friendly trust-level names — the bare TLn code is operator detail
// (precise-only); this is what everyone else sees.
const TRUST_NAMES = [
  'New',
  'Getting started',
  'Building trust',
  'Known',
  'Trusted',
  'Trusted',
  'Well trusted',
  'Well trusted',
  'Inner circle',
  'Inner circle',
];

// ── Template ─────────────────────────────────────────────────

/**
 * Build the Session (operator) card. Precise-only: raw session
 * internals are operator detail, hidden until precise mode is on.
 * @returns {string}
 */
export function buildSessionHtml() {
  return (
    '<div class="dashboard-section precise-only">' +
    '<h3>Session (operator)</h3>' +
    '<div id="session-info" class="session-card">' +
    '<div class="session-detail"><span class="session-label">Session ID</span><span id="session-id-display">--</span></div>' +
    '<div class="session-detail"><span class="session-label">Turns</span><span id="session-turns">0</span></div>' +
    '<div class="session-detail"><span class="session-label">Risk Score</span><span id="session-risk">0.0</span></div>' +
    '<div class="session-detail"><span class="session-label">Violations</span><span id="session-violations">0</span></div>' +
    '<div class="session-detail"><span class="session-label">Status</span><span id="session-lock-status">Active</span></div>' +
    '</div>' +
    '</div>'
  );
}

/**
 * Build the Metrics section: the trust meter + time-window selector and
 * the story strip stay visible; the detailed metric grids are wrapped
 * precise-only (operator data).
 * @returns {string}
 */
export function buildMetricsHtml() {
  return (
    '<div class="dashboard-section metrics-section">' +
    '<div class="metrics-header">' +
    '<h3>Metrics</h3>' +
    '<span class="trust-meter"><span class="trust-name" id="trust-name">New</span>' +
    '<span class="trust-badge precise-only" id="trust-badge">TL0</span></span>' +
    '<div class="time-window-selector" id="time-window-selector">' +
    '<button class="tw-btn active" data-window="24h">24h</button>' +
    '<button class="tw-btn" data-window="7d">7d</button>' +
    '<button class="tw-btn" data-window="30d">30d</button>' +
    '<button class="tw-btn" data-window="all">All</button>' +
    '</div>' +
    '</div>' +
    '<div class="story-strip" id="story-strip">' +
    '<span class="story-chip" id="story-tasks">No tasks yet — ask me something!</span>' +
    '</div>' +
    '<div class="precise-only">' +
    '<h4 class="metrics-sub">Approval Funnel</h4>' +
    '<div class="metric-grid">' +
    '<div class="metric-card"><div class="metric-value" id="m-auto-approved">0</div><div class="metric-label">Auto-Approved</div></div>' +
    '<div class="metric-card"><div class="metric-value" id="m-manually-approved">0</div><div class="metric-label">Manually Approved</div></div>' +
    '<div class="metric-card"><div class="metric-value" id="m-denied">0</div><div class="metric-label">Denied</div></div>' +
    '<div class="metric-card"><div class="metric-value" id="m-expired">0</div><div class="metric-label">Expired</div></div>' +
    '</div>' +
    '<h4 class="metrics-sub">Task Outcomes</h4>' +
    '<div class="metric-grid">' +
    '<div class="metric-card"><div class="metric-value" id="m-success">0</div><div class="metric-label">Success</div></div>' +
    '<div class="metric-card"><div class="metric-value" id="m-blocked">0</div><div class="metric-label">Blocked</div></div>' +
    '<div class="metric-card"><div class="metric-value" id="m-error">0</div><div class="metric-label">Error</div></div>' +
    '<div class="metric-card"><div class="metric-value" id="m-refused">0</div><div class="metric-label">Refused</div></div>' +
    '</div>' +
    '<h4 class="metrics-sub">Scanner Blocks</h4>' +
    '<div class="scanner-list" id="scanner-blocks"><div class="empty-state">No scanner blocks</div></div>' +
    '<h4 class="metrics-sub">Routine Health</h4>' +
    '<div class="metric-grid">' +
    '<div class="metric-card"><div class="metric-value" id="m-routine-total">0</div><div class="metric-label">Executions</div></div>' +
    '<div class="metric-card"><div class="metric-value" id="m-routine-success-rate">--</div><div class="metric-label">Success Rate</div></div>' +
    '<div class="metric-card"><div class="metric-value" id="m-routine-avg-dur">--</div><div class="metric-label">Avg Duration</div></div>' +
    '<div class="metric-card"><div class="metric-value" id="m-routine-errors">0</div><div class="metric-label">Errors</div></div>' +
    '</div>' +
    '<h4 class="metrics-sub">Response Times</h4>' +
    '<div class="metric-grid metric-grid-2">' +
    '<div class="metric-card"><div class="metric-value" id="m-rt-avg">--</div><div class="metric-label">Avg</div></div>' +
    '<div class="metric-card"><div class="metric-value" id="m-rt-p95">--</div><div class="metric-label">P95</div></div>' +
    '</div>' +
    '</div>' +
    '</div>'
  );
}

// ── Metrics rendering ────────────────────────────────────────

/**
 * @param {string} id
 * @param {*} val
 * @param {string} [cls]
 */
function setMetricVal(id, val, cls) {
  const el = document.getElementById(id);
  if (el) {
    el.textContent = val;
    el.className = `metric-value${cls ? ` ${cls}` : ''}`;
  }
}

/**
 * Populate the scanner blocks list from metrics data.
 * @param {*} scannerBlocks
 */
function renderScannerBlocks(scannerBlocks) {
  const scannerEl = document.getElementById('scanner-blocks');
  if (!scannerEl) return;
  if (scannerBlocks.length === 0) {
    scannerEl.innerHTML = '<div class="empty-state">No scanner blocks</div>';
    return;
  }
  let html = '';
  for (let i = 0; i < scannerBlocks.length; i++) {
    const s = scannerBlocks[i];
    html += '<div class="scanner-item">';
    html += `<span class="scanner-name">${escapeHtml(s.scanner)}</span>`;
    html += `<span class="scanner-count">${escapeHtml(String(s.count))}</span>`;
    html += '</div>';
  }
  scannerEl.innerHTML = html;
}

/**
 * Populate routine health metric cards with computed values.
 * @param {*} health
 */
function renderRoutineHealth(health) {
  setMetricVal('m-routine-total', health.total, '');
  const successRate = health.total > 0 ? `${Math.round((health.success / health.total) * 100)}%` : '--';
  const rateClass = health.total > 0 ? (health.success / health.total >= 0.9 ? 'ok' : 'warn') : '';
  setMetricVal('m-routine-success-rate', successRate, rateClass);
  setMetricVal('m-routine-avg-dur', health.avg_duration_s > 0 ? `${health.avg_duration_s}s` : '--', '');
  setMetricVal('m-routine-errors', health.error, health.error > 0 ? 'fail' : '');
}

/**
 * Refresh the metrics panel from a /api/metrics response: the friendly
 * trust name + story chip (always visible) and the precise-only grids.
 * @param {*} resp
 */
export function renderMetrics(resp) {
  const d = resp.data;
  if (!d?.approval_funnel) return;

  // Trust meter — friendly name always; TLn code is precise-only.
  const tl = resp.trust_level || 0;
  const nameEl = document.getElementById('trust-name');
  if (nameEl) nameEl.textContent = TRUST_NAMES[tl] || `Level ${tl}`;
  const badge = document.getElementById('trust-badge');
  if (badge) {
    badge.textContent = `TL${tl}`;
    badge.className = `trust-badge precise-only tl-${tl}`;
  }

  // Story strip — the one-line plain-English summary (always visible).
  const story = document.getElementById('story-tasks');
  if (story) {
    const done = d.task_outcomes.success;
    const stopped = d.task_outcomes.blocked + d.task_outcomes.refused;
    story.textContent =
      done === 0 && stopped === 0
        ? 'No tasks yet — ask me something!'
        : `${done} task${done === 1 ? '' : 's'} completed${stopped ? ` · ${stopped} stopped for safety` : ''}`;
  }

  // Approval funnel
  setMetricVal('m-auto-approved', d.approval_funnel.auto_approved, 'ok');
  setMetricVal('m-manually-approved', d.approval_funnel.manually_approved, 'ok');
  setMetricVal('m-denied', d.approval_funnel.denied, d.approval_funnel.denied > 0 ? 'warn' : '');
  setMetricVal('m-expired', d.approval_funnel.expired, d.approval_funnel.expired > 0 ? 'warn' : '');

  // Task outcomes
  setMetricVal('m-success', d.task_outcomes.success, 'ok');
  setMetricVal('m-blocked', d.task_outcomes.blocked, d.task_outcomes.blocked > 0 ? 'warn' : '');
  setMetricVal('m-error', d.task_outcomes.error, d.task_outcomes.error > 0 ? 'fail' : '');
  setMetricVal('m-refused', d.task_outcomes.refused, d.task_outcomes.refused > 0 ? 'warn' : '');

  renderScannerBlocks(d.scanner_blocks);
  renderRoutineHealth(d.routine_health);

  // Response times
  setMetricVal('m-rt-avg', d.response_times.count > 0 ? `${d.response_times.avg_s}s` : '--', '');
  setMetricVal(
    'm-rt-p95',
    d.response_times.count > 0 ? `${d.response_times.p95_s}s` : '--',
    d.response_times.p95_s > 30 ? 'warn' : '',
  );
}
