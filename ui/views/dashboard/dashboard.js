// @ts-check
/**
 * Overview view shell — system health, session info, metrics.
 *
 * Self-registers with the view registry. Owns lifecycle, data fetching,
 * polling, the `lastHealthData` subscription, and template assembly. The
 * UI surfaces live in co-located leaf modules:
 *   - health-clusters.js — health cards/clusters/headline (build + update)
 *   - metrics-panel.js    — session/metrics/story-strip/trust (build + update)
 */

import { apiGet, ENDPOINTS } from '../../core/api.js';
import { METRICS_POLL_INTERVAL_MS, UUID_DISPLAY_LENGTH } from '../../core/constants.js';
import { capture } from '../../core/errors.js';
import { registerView } from '../../core/router.js';
import { get as getState, subscribe } from '../../core/state.js';
import { getSessionId } from '../../core/ui-helpers.js';
import { buildHeadlineHtml, buildHealthGridHtml, updateDashboardHealth } from './health-clusters.js';
import { buildMetricsHtml, buildSessionHtml, renderMetrics } from './metrics-panel.js';

// ── State ────────────────────────────────────────────────────

let metricsWindow = '24h';
/** @type {ReturnType<typeof setInterval> | null} */
let metricsInterval = null;
// Guards against interval callbacks firing after view unload —
// prevents DOM updates on detached elements and stale API calls.
let dashboardUnloaded = true;

// ── Session info ─────────────────────────────────────────────

function loadSessionInfo() {
  const sid = getSessionId();
  const display = document.getElementById('session-id-display');
  if (display) display.textContent = `${sid.substring(0, UUID_DISPLAY_LENGTH)}...`;

  apiGet(`${ENDPOINTS.session}/${sid}`)
    .then((data) => {
      if (data.error) return;
      const turnsEl = document.getElementById('session-turns');
      if (turnsEl) turnsEl.textContent = data.turn_count || 0;
      const risk = data.cumulative_risk || 0;
      const riskEl = document.getElementById('session-risk');
      if (riskEl) {
        riskEl.textContent = risk.toFixed(2);
        riskEl.style.color = risk < 0.3 ? 'var(--green)' : risk < 0.7 ? 'var(--yellow)' : 'var(--red)';
      }
      const violationsEl = document.getElementById('session-violations');
      if (violationsEl) violationsEl.textContent = data.violation_count || 0;
      const lockEl = document.getElementById('session-lock-status');
      if (lockEl) lockEl.textContent = data.is_locked ? 'Locked' : 'Active';
    })
    .catch((err) => {
      capture({ component: 'dashboard', action: 'loadSessionInfo', error: err });
    });
}

// ── Metrics ──────────────────────────────────────────────────

function loadMetrics() {
  if (dashboardUnloaded) return;
  apiGet(`${ENDPOINTS.metrics}?window=${metricsWindow}`)
    .then((data) => {
      if (dashboardUnloaded) return;
      renderMetrics(data);
    })
    .catch((err) => {
      if (dashboardUnloaded) return;
      capture({ component: 'dashboard', action: 'loadMetrics', error: err });
    });
}

/** @param {string} w */
function setMetricsWindow(w) {
  metricsWindow = w;
  const btns = document.querySelectorAll('.tw-btn');
  btns.forEach((b) => {
    b.classList.toggle('active', b.getAttribute('data-window') === w);
  });
  // Reload metrics immediately for the new window — don't restart the
  // interval, it's already running from onLoad and will pick up the
  // new metricsWindow value on its next tick.
  loadMetrics();
}

function startMetricsPolling() {
  stopMetricsPolling();
  dashboardUnloaded = false;
  metricsInterval = setInterval(loadMetrics, METRICS_POLL_INTERVAL_MS);
}

function stopMetricsPolling() {
  dashboardUnloaded = true;
  if (metricsInterval) {
    clearInterval(metricsInterval);
    metricsInterval = null;
  }
}

// ── Template ─────────────────────────────────────────────────

function buildDashboardHtml() {
  return (
    '<div class="view-header"><h2>Overview</h2></div>' +
    '<div class="view-content dashboard-content">' +
    buildHeadlineHtml() +
    buildHealthGridHtml() +
    buildSessionHtml() +
    buildMetricsHtml() +
    '</div>'
  );
}

/** @param {HTMLElement} container */
function renderTemplate(container) {
  container.innerHTML = buildDashboardHtml();

  // Bind time window selector (event delegation)
  const twSelector = document.getElementById('time-window-selector');
  if (twSelector) {
    twSelector.addEventListener('click', (e) => {
      if (!(e.target instanceof Element)) return;
      const btn = e.target.closest('.tw-btn');
      const win = btn?.getAttribute('data-window');
      if (win) setMetricsWindow(win);
    });
  }
}

// ── Lifecycle ────────────────────────────────────────────────

function onLoad() {
  const cachedHealth = getState('lastHealthData');
  if (cachedHealth) updateDashboardHealth(cachedHealth);
  loadSessionInfo();
  loadMetrics();
  startMetricsPolling();
}

function onUnload() {
  stopMetricsPolling();
}

// Subscribe to health data changes (checkHealth() runs in app.js shell).
// Guard with dashboardUnloaded to avoid updating detached DOM elements.
subscribe('lastHealthData', (/** @type {*} */ data) => {
  if (!dashboardUnloaded && data) {
    updateDashboardHealth(data);
  }
});

// ── Registration ─────────────────────────────────────────────

registerView({
  id: 'dashboard',
  label: 'Overview',
  icon:
    '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2">' +
    '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/>' +
    '<rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>' +
    '</svg>',
  navOrder: 1,
  render: renderTemplate,
  load: onLoad,
  unload: onUnload,
});
