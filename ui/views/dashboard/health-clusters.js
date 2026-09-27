// @ts-check
/**
 * Overview health clusters — leaf UI module.
 *
 * Owns the health-card definitions, their clustering into Protection /
 * Connections / Engine groups, and the status-headline. Builders and
 * their DOM updaters are co-located here (guardrail #1): the shell calls
 * `buildHealthGridHtml`/`buildHeadlineHtml` to render and
 * `updateDashboardHealth(data)` to refresh — which internally drives the
 * per-card values, the cluster roll-up pills, and the headline.
 *
 * No transport/state knowledge here — fetch errors are captured in the
 * shell. This module only reads/writes the DOM it builds.
 */

import { cherrySvg } from '../../assets/cherry.js';
import {
  ICON_CALENDAR,
  ICON_CONVERSATION,
  ICON_EMAIL,
  ICON_PLANNER,
  ICON_POLICY,
  ICON_PROMPT_GUARD,
  ICON_SANDBOX,
  ICON_SEMGREP,
  ICON_SIDECAR,
  ICON_SIGNAL,
  ICON_SYSTEM,
  ICON_TELEGRAM,
} from '../../assets/icons.js';
import '../../components/lit/sentinel-pill.js';

// ── Health card definitions ──────────────────────────────────

const HEALTH_CARDS = [
  { component: 'status', label: 'System', id: 'health-status', group: 'engine', icon: ICON_SYSTEM },
  { component: 'policy_loaded', label: 'Policy Engine', id: 'health-policy', group: 'protection', icon: ICON_POLICY },
  {
    component: 'prompt_guard_loaded',
    label: 'Prompt Guard',
    id: 'health-pg',
    group: 'protection',
    icon: ICON_PROMPT_GUARD,
  },
  { component: 'semgrep_loaded', label: 'Semgrep', id: 'health-cs', group: 'protection', icon: ICON_SEMGREP },
  {
    component: 'planner_available',
    label: 'Claude Planner',
    id: 'health-planner',
    group: 'engine',
    icon: ICON_PLANNER,
  },
  {
    component: 'conversation_tracking',
    label: 'Conversation',
    id: 'health-conv',
    group: 'engine',
    icon: ICON_CONVERSATION,
  },
  { component: 'sidecar', label: 'WASM Sidecar', id: 'health-sidecar', group: 'engine', icon: ICON_SIDECAR },
  { component: 'signal', label: 'Signal', id: 'health-signal', group: 'connections', icon: ICON_SIGNAL },
  { component: 'telegram', label: 'Telegram', id: 'health-telegram', group: 'connections', icon: ICON_TELEGRAM },
  { component: 'email', label: 'Email', id: 'health-email', group: 'connections', icon: ICON_EMAIL },
  { component: 'calendar', label: 'Calendar', id: 'health-calendar', group: 'connections', icon: ICON_CALENDAR },
  { component: 'sandbox', label: 'Sandbox', id: 'health-sandbox', group: 'protection', icon: ICON_SANDBOX },
];

const CLUSTERS = [
  { key: 'protection', title: 'Protection', blurb: 'The layers that check everything before I act' },
  { key: 'connections', title: 'Connections', blurb: 'Channels and services I can reach' },
  { key: 'engine', title: 'Engine', blurb: 'Planning and execution machinery' },
];

// ── Template ─────────────────────────────────────────────────

/**
 * Build the clustered health grid: one collapsible card per cluster,
 * each with a roll-up pill and its member rows.
 * @returns {string}
 */
export function buildHealthGridHtml() {
  let html = '<div class="cluster-grid">';
  for (const cluster of CLUSTERS) {
    const members = HEALTH_CARDS.filter((c) => c.group === cluster.key);
    html += `<details class="cluster-card" data-cluster="${cluster.key}">`;
    html += '<summary class="cluster-summary">';
    html += `<span class="cluster-title">${cluster.title}</span>`;
    html += `<sentinel-pill status="off" id="cluster-pill-${cluster.key}">checking…</sentinel-pill>`;
    html += '</summary>';
    html += `<div class="cluster-blurb">${cluster.blurb}</div>`;
    html += '<div class="cluster-members">';
    for (const c of members) {
      html += `<div class="cluster-member"><span class="cluster-member-icon">${c.icon}</span>`;
      html += `<span class="cluster-member-label">${c.label}</span>`;
      html += `<span class="health-card-value" id="${c.id}">--</span></div>`;
    }
    html += '</div></details>';
  }
  html += '</div>';
  return html;
}

/**
 * Build the status headline strip (Cherry + one-line summary).
 * @returns {string}
 */
export function buildHeadlineHtml() {
  return (
    '<div class="overview-headline" id="overview-headline">' +
    '<span class="overview-cherry" id="overview-cherry"></span>' +
    '<span class="overview-headline-text" id="overview-headline-text">Checking on everything…</span>' +
    '</div>'
  );
}

// ── Health rendering ─────────────────────────────────────────

/**
 * @param {string} id
 * @param {*} val
 * @param {string} cls
 */
function setVal(id, val, cls) {
  const el = document.getElementById(id);
  if (el) {
    el.textContent = val;
    el.className = `health-card-value ${cls}`;
  }
}

/**
 * Refresh all health-card values, cluster roll-up pills, and the
 * headline from a /api/health payload.
 * @param {*} data
 */
export function updateDashboardHealth(data) {
  if (!data) return;

  setVal('health-status', data.status === 'ok' ? 'Healthy' : 'Unhealthy', data.status === 'ok' ? 'ok' : 'fail');
  setVal('health-policy', data.policy_loaded ? 'Loaded' : 'Missing', data.policy_loaded ? 'ok' : 'fail');
  setVal('health-pg', data.prompt_guard_loaded ? 'Loaded' : 'Disabled', data.prompt_guard_loaded ? 'ok' : 'off');
  setVal('health-cs', data.semgrep_loaded ? 'Loaded' : 'Disabled', data.semgrep_loaded ? 'ok' : 'off');
  setVal(
    'health-planner',
    data.planner_available ? 'Available' : 'Unavailable',
    data.planner_available ? 'ok' : 'fail',
  );
  setVal('health-conv', data.conversation_tracking ? 'Enabled' : 'Disabled', data.conversation_tracking ? 'ok' : 'off');

  /** @param {*} s */
  function statusVal(s) {
    if (s === 'running') return ['Running', 'ok'];
    if (s === 'stopped') return ['Stopped', 'warn'];
    return ['Disabled', 'off'];
  }
  const sc = statusVal(data.sidecar);
  setVal('health-sidecar', sc[0], sc[1]);
  const sig = statusVal(data.signal);
  setVal('health-signal', sig[0], sig[1]);
  const tg = statusVal(data.telegram);
  setVal('health-telegram', tg[0], tg[1]);

  /** @param {*} s */
  function configVal(s) {
    if (s && s.indexOf('enabled') === 0) return [s.charAt(0).toUpperCase() + s.slice(1), 'ok'];
    return ['Disabled', 'off'];
  }
  const em = configVal(data.email);
  setVal('health-email', em[0], em[1]);
  const cal = configVal(data.calendar);
  setVal('health-calendar', cal[0], cal[1]);

  setVal(
    'health-sandbox',
    data.sandbox === 'enabled' ? 'Enabled' : 'Disabled',
    data.sandbox === 'enabled' ? 'ok' : 'off',
  );

  updateClusterPills();
  updateHeadline(data);
}

/** Roll up each cluster's member statuses into its summary pill. */
function updateClusterPills() {
  for (const cluster of CLUSTERS) {
    const members = HEALTH_CARDS.filter((c) => c.group === cluster.key);
    let ok = 0;
    let bad = 0;
    for (const c of members) {
      const el = document.getElementById(c.id);
      if (!el) continue;
      if (el.classList.contains('ok')) ok++;
      if (el.classList.contains('fail') || el.classList.contains('warn')) bad++;
    }
    const pill = document.getElementById(`cluster-pill-${cluster.key}`);
    if (pill) {
      pill.textContent = bad === 0 ? 'All good' : `${ok} of ${members.length} healthy`;
      pill.setAttribute('status', bad === 0 ? 'ok' : 'warn');
    }
  }
}

/**
 * Set the headline Cherry pose + summary text from the overall health.
 * @param {*} data
 */
function updateHeadline(data) {
  const values = HEALTH_CARDS.map((c) => document.getElementById(c.id)).filter(
    /** @returns {el is HTMLElement} */ (el) => el !== null,
  );
  const total = values.length;
  const healthy = values.filter((el) => el.classList.contains('ok')).length;
  const cherryEl = document.getElementById('overview-cherry');
  const textEl = document.getElementById('overview-headline-text');
  const headline = document.getElementById('overview-headline');
  if (!textEl || !headline) return;
  const allGood = data.status === 'ok' && healthy === total;
  if (cherryEl) cherryEl.innerHTML = cherrySvg(allGood ? 'idle' : 'alert', 44);
  textEl.textContent = allGood
    ? 'All good — everything is healthy and nothing needs your attention.'
    : `${healthy} of ${total} services healthy — open the clusters below for details.`;
  headline.className = `overview-headline ${allGood ? 'ok' : 'warn'}`;
}
