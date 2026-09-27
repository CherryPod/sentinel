/**
 * Admin view — system administration dashboard.
 *
 * Lazy-loaded by the router on first navigation. Only accessible to
 * admin/owner roles (router filters nav by userRole state key).
 *
 * Shows: system health summary, user overview, session health,
 * scanner pipeline status, and approval configuration.
 *
 * Exports render/load/unload for the router's lazy loading protocol.
 */

import { apiGet, ENDPOINTS } from '../../core/api.js';
import { capture } from '../../core/errors.js';
import { get as getState, subscribe } from '../../core/state.js';
import { escapeHtml } from '../../core/ui-helpers.js';

// ── Constants ───────────────────────────────────────────────

const ADMIN_POLL_INTERVAL_MS = 30000;

// ── State ───────────────────────────────────────────────────

let pollInterval = null;
let adminUnloaded = true;
let healthUnsub = null;

// ── Template ────────────────────────────────────────────────

function buildAdminHtml() {
  return (
    '<div class="view-header"><h2>Administration</h2></div>' +
    '<div class="view-content admin-content">' +
    // System status bar
    '<div class="admin-status-bar" id="admin-status-bar">' +
    '<span class="admin-status-item" id="admin-sys-status">--</span>' +
    '<span class="admin-status-item" id="admin-approval-mode">--</span>' +
    '<span class="admin-status-item" id="admin-user-count">--</span>' +
    '</div>' +
    // Grid: two columns on desktop
    '<div class="admin-grid">' +
    // Scanner pipeline
    '<div class="admin-card">' +
    '<h3 class="admin-card-title">Scanner Pipeline</h3>' +
    '<div class="admin-card-body" id="admin-scanners">' +
    '<div class="empty-state">Loading...</div>' +
    '</div>' +
    '</div>' +
    // Users overview
    '<div class="admin-card">' +
    '<h3 class="admin-card-title">Users</h3>' +
    '<div class="admin-card-body" id="admin-users">' +
    '<div class="empty-state">Loading...</div>' +
    '</div>' +
    '</div>' +
    // Session health (from metrics)
    '<div class="admin-card">' +
    '<h3 class="admin-card-title">Session Health</h3>' +
    '<div class="admin-card-body" id="admin-sessions">' +
    '<div class="empty-state">Loading...</div>' +
    '</div>' +
    '</div>' +
    // Scanner blocks (from metrics)
    '<div class="admin-card">' +
    '<h3 class="admin-card-title">Scanner Blocks (24h)</h3>' +
    '<div class="admin-card-body" id="admin-scanner-blocks">' +
    '<div class="empty-state">Loading...</div>' +
    '</div>' +
    '</div>' +
    '</div>' +
    '</div>'
  );
}

export function render(container) {
  container.innerHTML = buildAdminHtml();
}

// ── Data loading ────────────────────────────────────────────

function loadAll() {
  if (adminUnloaded) return;
  loadHealth();
  loadUsers();
  loadMetrics();
}

function loadHealth() {
  const cached = getState('lastHealthData');
  if (cached) renderHealth(cached);
}

function renderHealth(data) {
  if (!data) return;

  // Status bar
  const statusEl = document.getElementById('admin-sys-status');
  if (statusEl) {
    const degraded = data.degraded;
    statusEl.textContent = degraded ? 'Degraded' : 'Healthy';
    statusEl.className = `admin-status-item ${degraded ? 'admin-warn' : 'admin-ok'}`;
  }

  const approvalEl = document.getElementById('admin-approval-mode');
  if (approvalEl) {
    const mode = data.approval_mode || 'unknown';
    approvalEl.textContent = `Approval: ${mode}`;
  }

  // Scanner pipeline detail
  const scannersEl = document.getElementById('admin-scanners');
  if (scannersEl) {
    const items = [
      { label: 'Policy Engine', ok: data.policy_loaded },
      { label: 'Prompt Guard', ok: data.prompt_guard_loaded },
      { label: 'Semgrep', ok: data.semgrep_loaded },
      { label: 'Claude Planner', ok: data.planner_available },
      { label: 'WASM Sidecar', ok: data.sidecar === 'running' },
      { label: 'Sandbox', ok: data.sandbox === 'enabled' },
    ];

    let html = '<div class="admin-list">';
    for (let i = 0; i < items.length; i++) {
      const item = items[i];
      const statusClass = item.ok ? 'admin-ok' : 'admin-off';
      const statusLabel = item.ok ? 'Active' : 'Inactive';
      html +=
        '<div class="admin-list-item">' +
        '<span class="admin-list-label">' +
        escapeHtml(item.label) +
        '</span>' +
        '<span class="admin-list-value ' +
        statusClass +
        '">' +
        statusLabel +
        '</span>' +
        '</div>';
    }
    html += '</div>';
    scannersEl.innerHTML = html;
  }
}

function loadUsers() {
  if (adminUnloaded) return;

  apiGet(`${ENDPOINTS.users}?active_only=false`)
    .then((users) => {
      if (adminUnloaded) return;
      renderUsers(users);
    })
    .catch((err) => {
      if (adminUnloaded) return;
      const el = document.getElementById('admin-users');
      if (el) el.innerHTML = '<div class="empty-state">Failed to load users</div>';
      capture({ component: 'admin', action: 'loadUsers', error: err });
    });
}

/**
 * Build HTML for the role summary section (e.g. "Admins: 2, Users: 5").
 * Expects a { role: count } object.
 */
function buildRoleSummaryHtml(roles) {
  let html = '';
  const roleKeys = Object.keys(roles).sort();
  for (let j = 0; j < roleKeys.length; j++) {
    html +=
      '<div class="admin-list-item">' +
      '<span class="admin-list-label">' +
      escapeHtml(roleKeys[j].charAt(0).toUpperCase() + roleKeys[j].slice(1)) +
      's</span>' +
      '<span class="admin-list-value">' +
      roles[roleKeys[j]] +
      '</span>' +
      '</div>';
  }
  return html;
}

/**
 * Build HTML for individual user rows (name, role, trust level, status).
 */
function buildUserRowsHtml(users) {
  let html = '';
  for (let k = 0; k < users.length; k++) {
    const u = users[k];
    const statusClass = u.is_active ? 'admin-ok' : 'admin-off';
    const trust = u.trust_level != null ? `TL${u.trust_level}` : '--';
    html +=
      '<div class="admin-user-row">' +
      '<span class="admin-user-name">' +
      escapeHtml(u.display_name) +
      '</span>' +
      '<span class="admin-user-role">' +
      escapeHtml(u.role || 'user') +
      '</span>' +
      '<span class="admin-user-trust">' +
      trust +
      '</span>' +
      '<span class="admin-user-status ' +
      statusClass +
      '">' +
      (u.is_active ? 'Active' : 'Inactive') +
      '</span>' +
      '</div>';
  }
  return html;
}

function renderUsers(users) {
  const el = document.getElementById('admin-users');
  if (!el) return;

  // Update user count in status bar
  const countEl = document.getElementById('admin-user-count');
  if (countEl) {
    const active = users.filter((u) => u.is_active).length;
    countEl.textContent = `${active}/${users.length} users active`;
  }

  // Role breakdown
  const roles = {};
  for (let i = 0; i < users.length; i++) {
    const role = users[i].role || 'user';
    roles[role] = (roles[role] || 0) + 1;
  }

  el.innerHTML =
    '<div class="admin-list">' +
    buildRoleSummaryHtml(roles) +
    '</div><div class="admin-user-list">' +
    buildUserRowsHtml(users) +
    '</div>';
}

function loadMetrics() {
  if (adminUnloaded) return;

  apiGet(`${ENDPOINTS.metrics}?window=24h`)
    .then((resp) => {
      if (adminUnloaded) return;
      renderSessionHealth(resp.data);
      renderScannerBlocks(resp.data);
    })
    .catch((err) => {
      if (adminUnloaded) return;
      // Metrics may 403 if role check is strict — show graceful fallback
      const sessEl = document.getElementById('admin-sessions');
      if (sessEl) sessEl.innerHTML = '<div class="empty-state">Metrics unavailable</div>';
      const blocksEl = document.getElementById('admin-scanner-blocks');
      if (blocksEl) blocksEl.innerHTML = '<div class="empty-state">Metrics unavailable</div>';
      capture({ component: 'admin', action: 'loadMetrics', error: err });
    });
}

function renderSessionHealth(data) {
  const el = document.getElementById('admin-sessions');
  if (!el || !data) return;

  const sh = data.session_health || {};
  const html =
    '<div class="admin-list">' +
    '<div class="admin-list-item">' +
    '<span class="admin-list-label">Active Sessions</span>' +
    '<span class="admin-list-value">' +
    (sh.active || 0) +
    '</span>' +
    '</div>' +
    '<div class="admin-list-item">' +
    '<span class="admin-list-label">Locked Sessions</span>' +
    '<span class="admin-list-value ' +
    (sh.locked > 0 ? 'admin-warn' : '') +
    '">' +
    (sh.locked || 0) +
    '</span>' +
    '</div>' +
    '<div class="admin-list-item">' +
    '<span class="admin-list-label">Avg Risk Score</span>' +
    '<span class="admin-list-value">' +
    (sh.avg_risk != null ? sh.avg_risk.toFixed(2) : '--') +
    '</span>' +
    '</div>' +
    '<div class="admin-list-item">' +
    '<span class="admin-list-label">Total Violations</span>' +
    '<span class="admin-list-value ' +
    (sh.total_violations > 0 ? 'admin-warn' : '') +
    '">' +
    (sh.total_violations || 0) +
    '</span>' +
    '</div>' +
    '</div>';

  el.innerHTML = html;
}

function renderScannerBlocks(data) {
  const el = document.getElementById('admin-scanner-blocks');
  if (!el || !data) return;

  const blocks = data.scanner_blocks || [];
  if (blocks.length === 0) {
    el.innerHTML = '<div class="empty-state">No scanner blocks in last 24h</div>';
    return;
  }

  let html = '<div class="admin-list">';
  for (let i = 0; i < blocks.length; i++) {
    const b = blocks[i];
    html +=
      '<div class="admin-list-item">' +
      '<span class="admin-list-label">' +
      escapeHtml(b.scanner) +
      '</span>' +
      '<span class="admin-list-value admin-warn">' +
      b.count +
      '</span>' +
      '</div>';
  }
  html += '</div>';
  el.innerHTML = html;
}

// ── Lifecycle ───────────────────────────────────────────────

export function load() {
  // Defensive cleanup — prevents leaks if load() is called without prior unload()
  if (pollInterval) clearInterval(pollInterval);
  if (healthUnsub) healthUnsub();

  adminUnloaded = false;
  loadAll();

  // Poll for updates
  pollInterval = setInterval(loadAll, ADMIN_POLL_INTERVAL_MS);

  // Subscribe to health data changes from the app shell
  healthUnsub = subscribe('lastHealthData', (data) => {
    if (!adminUnloaded && data) renderHealth(data);
  });
}

export function unload() {
  adminUnloaded = true;
  if (pollInterval) {
    clearInterval(pollInterval);
    pollInterval = null;
  }
  if (healthUnsub) {
    healthUnsub();
    healthUnsub = null;
  }
}
