/**
 * Routines view — list, create, toggle, run, and delete scheduled routines.
 *
 * Self-registers with the view registry. All routines DOM is created
 * in render() — no markup needed in index.html.
 */

import { describeTrigger } from '../../assets/cron-describe.js';
import '../../components/lit/cherry-empty-state.js';
import { confirmDialog } from '../../components/confirm-dialog.js';
import { apiDelete, apiGet, apiPatch, apiPost, ENDPOINTS } from '../../core/api.js';
import { BUTTON_RESET_DELAY_MS } from '../../core/constants.js';
import { capture } from '../../core/errors.js';
import { on as onEvent } from '../../core/events.js';
import { registerView } from '../../core/router.js';
import { get as getState } from '../../core/state.js';
import { showToast } from '../../core/ui-helpers.js';
import {
  buildCreateFormHtml,
  buildExecHistoryTableHtml,
  buildRoutineCardHtml,
  TRIGGER_HINTS,
  TRIGGER_PLACEHOLDERS,
} from './routines-render.js';

// ── Data loading ────────────────────────────────────────────

function loadRoutines() {
  apiGet(ENDPOINTS.routine)
    .then((data) => {
      const list = data.routines || data || [];
      renderRoutineList(list);
      renderSummaryBar(list);
    })
    .catch((err) => {
      capture({ component: 'routines', action: 'loadRoutines', error: err });
      showToast('Failed to load routines', 'error');
    });
}

function loadExecutionHistory(routineId) {
  const container = document.getElementById(`exec-history-${routineId}`);
  if (!container) return;

  apiGet(`${ENDPOINTS.routine}/${routineId}/executions?limit=10`)
    .then((data) => {
      const executions = data.executions || data || [];
      if (executions.length === 0) {
        container.innerHTML = '<div class="empty-state">No execution history</div>';
        return;
      }
      container.innerHTML = buildExecHistoryTableHtml(executions);
    })
    .catch((err) => {
      capture({ component: 'routines', action: 'loadExecutionHistory', error: err });
      container.innerHTML = '<div class="empty-state">Failed to load history</div>';
    });
}

// ── Summary bar ─────────────────────────────────────────────

function renderSummaryBar(routines) {
  const total = routines.length;
  let enabled = 0;
  for (let i = 0; i < routines.length; i++) {
    if (routines[i].enabled) enabled++;
  }
  const disabled = total - enabled;

  const el = document.getElementById('routines-summary');
  if (el) {
    el.innerHTML =
      '<span class="summary-stat"><strong>' +
      total +
      '</strong> Total</span>' +
      '<span class="summary-stat ok"><strong>' +
      enabled +
      '</strong> Enabled</span>' +
      '<span class="summary-stat off"><strong>' +
      disabled +
      '</strong> Disabled</span>';
  }
}

// ── Routine list rendering ──────────────────────────────────

function renderRoutineList(routines) {
  const container = document.getElementById('routine-list');
  if (!container) return;

  if (routines.length === 0) {
    container.innerHTML =
      '<cherry-empty-state pose="sleeping" ' +
      'message="No routines yet — I can do things on a schedule for you. Try a morning briefing."></cherry-empty-state>';
    return;
  }

  let html = '';
  for (let i = 0; i < routines.length; i++) {
    html += buildRoutineCardHtml(routines[i]);
  }
  container.innerHTML = html;
}

// ── Actions ─────────────────────────────────────────────────

function toggleRoutine(id, enabled) {
  apiPatch(`${ENDPOINTS.routine}/${id}`, { enabled: enabled })
    .then(() => {
      showToast(`Routine ${enabled ? 'enabled' : 'disabled'}`, 'success');
      loadRoutines();
    })
    .catch((err) => {
      capture({ component: 'routines', action: 'toggleRoutine', error: err });
      showToast('Failed to toggle routine', 'error');
      loadRoutines();
    });
}

function runNow(id, btn) {
  const origText = btn.textContent;
  btn.textContent = 'Running...';
  btn.disabled = true;

  apiPost(`${ENDPOINTS.routine}/${id}/run`, {})
    .then(() => {
      showToast('Routine triggered', 'success');
    })
    .catch((err) => {
      capture({ component: 'routines', action: 'runNow', error: err });
      showToast('Failed to run routine', 'error');
    })
    .then(() => {
      // Look up button fresh — the original ref may be detached if
      // loadRoutines() re-rendered while the POST was in-flight
      setTimeout(() => {
        const freshBtn = document.querySelector(`.btn-run[data-id="${id}"]`);
        if (freshBtn) {
          freshBtn.textContent = origText;
          freshBtn.disabled = false;
        }
      }, BUTTON_RESET_DELAY_MS);
    });
}

async function deleteRoutine(id) {
  if (!(await confirmDialog('Delete this routine? This cannot be undone.', { danger: true, confirmText: 'Delete' })))
    return;

  apiDelete(`${ENDPOINTS.routine}/${id}`)
    .then(() => {
      showToast('Routine deleted', 'success');
      loadRoutines();
    })
    .catch((err) => {
      capture({ component: 'routines', action: 'deleteRoutine', error: err });
      showToast('Failed to delete routine', 'error');
    });
}

function createRoutine() {
  const name = document.getElementById('routine-name');
  const triggerType = document.getElementById('routine-trigger-type');
  const triggerConfig = document.getElementById('routine-trigger-config');
  const prompt = document.getElementById('routine-prompt');
  const cooldown = document.getElementById('routine-cooldown');

  if (!name?.value.trim()) {
    showToast('Routine name is required', 'error');
    return;
  }
  if (!triggerConfig?.value.trim()) {
    showToast('Trigger configuration is required', 'error');
    return;
  }
  if (!prompt?.value.trim()) {
    showToast('Prompt is required', 'error');
    return;
  }

  const body = {
    name: name.value.trim(),
    trigger_type: triggerType.value,
    trigger_config: triggerConfig.value.trim(),
    action_config: {
      prompt: prompt.value.trim(),
      approval_mode: 'auto',
    },
    cooldown_s: parseInt(cooldown.value, 10) || 0,
  };

  apiPost(ENDPOINTS.routine, body)
    .then(() => {
      showToast('Routine created', 'success');
      toggleCreateForm(false);
      clearCreateForm();
      loadRoutines();
    })
    .catch((err) => {
      capture({ component: 'routines', action: 'createRoutine', error: err });
      showToast(`Failed to create routine: ${err.message || err}`, 'error');
    });
}

// ── Create form helpers ─────────────────────────────────────

function toggleCreateForm(show) {
  const form = document.getElementById('routine-create-form');
  const btn = document.getElementById('btn-new-routine');
  if (!form || !btn) return;

  if (show === undefined) {
    show = form.style.display === 'none';
  }
  form.style.display = show ? 'block' : 'none';
  btn.textContent = show ? 'Cancel' : 'New Routine';
}

function clearCreateForm() {
  const name = document.getElementById('routine-name');
  const triggerType = document.getElementById('routine-trigger-type');
  const triggerConfig = document.getElementById('routine-trigger-config');
  const prompt = document.getElementById('routine-prompt');
  const cooldown = document.getElementById('routine-cooldown');

  if (name) name.value = '';
  if (triggerType) triggerType.value = 'cron';
  if (triggerConfig) {
    triggerConfig.value = '';
    triggerConfig.placeholder = TRIGGER_PLACEHOLDERS.cron;
  }
  if (prompt) prompt.value = '';
  if (cooldown) cooldown.value = '0';
  updateTriggerHint('cron');
}

function updateTriggerHint(type) {
  const hint = document.getElementById('trigger-hint');
  const config = document.getElementById('routine-trigger-config');
  if (config) config.placeholder = TRIGGER_PLACEHOLDERS[type] || '';
  if (!hint) return;
  const raw = config ? config.value.trim() : '';
  const base = TRIGGER_HINTS[type] || '';
  if (raw) {
    hint.textContent = `${base} — ${describeTrigger({ trigger_type: type, trigger_config: raw })}`;
  } else {
    hint.textContent = base;
  }
}

// ── Event delegation ────────────────────────────────────────

function handleListClick(e) {
  const target = e.target;

  // Toggle switch
  if (target.classList.contains('routine-toggle')) {
    toggleRoutine(target.getAttribute('data-id'), target.checked);
    return;
  }

  // Run Now button
  const runBtn = target.closest('.btn-run');
  if (runBtn) {
    runNow(runBtn.getAttribute('data-id'), runBtn);
    return;
  }

  // Delete button
  const delBtn = target.closest('.btn-delete');
  if (delBtn) {
    deleteRoutine(delBtn.getAttribute('data-id'));
    return;
  }

  // History toggle
  const histBtn = target.closest('.btn-history');
  if (histBtn) {
    const routineId = histBtn.getAttribute('data-id');
    const histEl = document.getElementById(`exec-history-${routineId}`);
    if (!histEl) return;
    const isVisible = histEl.style.display !== 'none';
    histEl.style.display = isVisible ? 'none' : 'block';
    histBtn.textContent = isVisible ? 'Show history' : 'Hide history';
    if (!isVisible) loadExecutionHistory(routineId);
    return;
  }
}

// ── Template ────────────────────────────────────────────────

function buildHtml() {
  return (
    '<div class="view-header">' +
    '<h2>Routines</h2>' +
    '<button class="btn btn-primary" id="btn-new-routine">New Routine</button>' +
    '</div>' +
    '<div class="view-content routines-content">' +
    '<div class="summary-bar" id="routines-summary">' +
    '<span class="summary-stat"><strong>0</strong> Total</span>' +
    '<span class="summary-stat ok"><strong>0</strong> Enabled</span>' +
    '<span class="summary-stat off"><strong>0</strong> Disabled</span>' +
    '</div>' +
    buildCreateFormHtml() +
    '<div id="routine-list" class="routine-list">' +
    '<div class="empty-state">Loading routines...</div>' +
    '</div>' +
    '</div>'
  );
}

function bindEvents() {
  const newBtn = document.getElementById('btn-new-routine');
  if (newBtn) {
    newBtn.addEventListener('click', () => {
      toggleCreateForm();
    });
  }

  const createBtn = document.getElementById('btn-create-routine');
  if (createBtn) {
    createBtn.addEventListener('click', () => {
      createRoutine();
    });
  }

  const cancelBtn = document.getElementById('btn-cancel-create');
  if (cancelBtn) {
    cancelBtn.addEventListener('click', () => {
      toggleCreateForm(false);
      clearCreateForm();
    });
  }

  const triggerSelect = document.getElementById('routine-trigger-type');
  if (triggerSelect) {
    triggerSelect.addEventListener('change', () => {
      updateTriggerHint(triggerSelect.value);
    });
  }

  const triggerConfig = document.getElementById('routine-trigger-config');
  if (triggerConfig && triggerSelect) {
    triggerConfig.addEventListener('input', () => {
      updateTriggerHint(triggerSelect.value);
    });
  }

  const routineList = document.getElementById('routine-list');
  if (routineList) {
    routineList.addEventListener('click', handleListClick);
  }
}

function renderTemplate(container) {
  container.innerHTML = buildHtml();
  bindEvents();
}

// ── Lifecycle ───────────────────────────────────────────────

function onLoad() {
  loadRoutines();
}

function onUnload() {
  // No polling or timers to clean up
}

// ── Event bus subscription ──────────────────────────────────
// Reload routine list when the backend emits routine events
// (e.g. a routine completes execution, is toggled externally)

onEvent('routine:event', () => {
  if (getState('currentView') === 'routines') loadRoutines();
});

// ── Registration ────────────────────────────────────────────

registerView({
  id: 'routines',
  label: 'Routines',
  icon:
    '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2">' +
    '<circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>' +
    '</svg>',
  navOrder: 4,
  render: renderTemplate,
  load: onLoad,
  unload: onUnload,
});
