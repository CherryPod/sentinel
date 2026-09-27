// @ts-check
/**
 * Plan & confirmation gate components.
 *
 * Renders plan approval gates, confirmation gates, and step results.
 * These are reusable UI components — they accept a `chatApi` context
 * object for message display and state management, keeping them
 * decoupled from the chat view's internal state.
 *
 * chatApi shape:
 *   addMessage(type, html, id) — append a message div
 *   addStatusMessage(text, id) — append a spinner+text status message
 *   addSystemMessage(text) — append a markdown system message
 *   addErrorMessage(text) — append an error message
 *   removeElement(id) — remove an element by id
 *   setInputEnabled(enabled) — enable/disable chat input
 *   appendToHistory(entry) — persist to chat history
 *   scrollMessages() — scroll to bottom
 */

import { apiGet, apiPost, ENDPOINTS } from '../core/api.js';
import { POLL_INTERVAL_MS, POLL_MAX_ATTEMPTS } from '../core/constants.js';
import { capture } from '../core/errors.js';
import { set as setState } from '../core/state.js';
import { escapeHtml, removeElement, showToast } from '../core/ui-helpers.js';
import { bindStepToggles, buildStepsHtml, stepStatusClass } from './plan-steps.js';

/**
 * Capability object handed to these gate components (the chat transcript
 * surface from views/chat/messages.js implements it). Methods are typed
 * loosely — this is a duck-typed contract, not a class.
 * @typedef {{
 *   addMessage: function(string, string, string=): HTMLElement,
 *   addStatusMessage: function(string, string=): HTMLElement,
 *   addSystemMessage: function(string): void,
 *   addErrorMessage: function(string): void,
 *   setInputEnabled: function(boolean): void,
 *   appendToHistory: function(Object): void,
 *   sentinelHead?: function(): string,
 *   addGuardianMessage?: function(string): void,
 * }} ChatApi
 */

// ── Validation ──────────────────────────────────────────────

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Validate that an ID is a well-formed UUID. Defence-in-depth against
 * path traversal via hostile worker output — approvalId and confirmationId
 * are used directly in API URLs and DOM id attributes.
 * @param {*} id
 * @returns {boolean}
 */
function isValidUuid(id) {
  return typeof id === 'string' && UUID_RE.test(id);
}

// ── Plan approval gate ───────────────────────────────────────

/**
 * Render a plan with approve/deny buttons.
 * @param {string} planSummary
 * @param {import('./plan-steps.js').PlanStep[]} steps
 * @param {string} approvalId
 * @param {ChatApi} chatApi
 */
export function renderPlan(planSummary, steps, approvalId, chatApi) {
  // B-04: Validate approvalId as UUID before use in DOM ids and API URLs.
  // Hostile worker output could contain '../' for path traversal.
  if (!isValidUuid(approvalId)) {
    capture({
      component: 'plan-gate',
      action: 'renderPlan',
      error: new Error('Invalid approvalId format'),
      context: { length: String(approvalId).length },
    });
    chatApi.addErrorMessage('Plan received with invalid approval ID — rejected for security.');
    return;
  }

  const n = steps ? steps.length : 0;
  let html = chatApi.sentinelHead ? chatApi.sentinelHead() : '';
  html += `<div class="plan-title">Here's my plan${n ? ` — ${n} step${n === 1 ? '' : 's'}` : ''}</div>`;
  html += `<div class="plan-summary">${escapeHtml(planSummary)}</div>`;
  html += buildStepsHtml(steps);
  // approvalId is validated as UUID — safe for use in id attributes and data attrs
  html += `<div class="approval-buttons" id="approval-${approvalId}">`;
  html += `<button class="btn btn-approve" data-approval-id="${approvalId}" data-granted="true">Approve and run</button>`;
  html += `<button class="btn btn-deny" data-approval-id="${approvalId}" data-granted="false">Cancel</button>`;
  html += '</div>';

  const msgEl = chatApi.addMessage('system', html);
  bindStepToggles(msgEl);

  // Use raw validated UUID for getElementById (not escaped — validated UUIDs
  // contain only hex digits and hyphens, so escaping would be a no-op but
  // using the raw value avoids the mismatch bug flagged in B-04)
  const approvalContainer = document.getElementById(`approval-${approvalId}`);
  if (approvalContainer) {
    approvalContainer.addEventListener('click', (e) => {
      const btn = /** @type {HTMLElement} */ (e.target).closest('button[data-approval-id]');
      if (btn) {
        handleApproval(
          btn.getAttribute('data-approval-id') || '',
          btn.getAttribute('data-granted') === 'true',
          chatApi,
        );
      }
    });
  }
  chatApi.appendToHistory({ role: 'plan', planSummary: planSummary, steps: steps, approvalId: approvalId });
}

// ── Confirmation gate ────────────────────────────────────────

/**
 * Build the HTML for a confirmation gate message.
 * @param {string} preview
 * @param {string} safeId
 * @param {ChatApi} chatApi
 * @returns {string}
 */
function buildConfirmationHtml(preview, safeId, chatApi) {
  return (
    `${chatApi.sentinelHead ? chatApi.sentinelHead() : ''}` +
    `<div class="plan-summary">${escapeHtml(preview)}</div>` +
    `<div class="approval-buttons" id="confirm-${safeId}">` +
    '<button class="btn btn-approve" data-action="confirm">Confirm</button>' +
    '<button class="btn btn-deny" data-action="cancel">Cancel</button>' +
    '</div>'
  );
}

/**
 * Handle the confirm action — POST granted:true and display result.
 * @param {string} confirmationId
 * @param {ChatApi} chatApi
 */
function submitConfirm(confirmationId, chatApi) {
  const statusId = `exec-${Date.now()}`;
  chatApi.addStatusMessage('Executing confirmed action...', statusId);
  apiPost(`${ENDPOINTS.confirm}/${confirmationId}`, { granted: true, reason: 'Confirmed via WebUI' })
    .then((data) => {
      removeElement(statusId);
      if (data.status === 'success') {
        chatApi.addSystemMessage(data.response || 'Action completed.');
        showToast('Action completed', 'success');
      } else if (data.status === 'blocked') {
        if (chatApi.addGuardianMessage) {
          chatApi.addGuardianMessage(data.reason || 'A safety policy stopped this action.');
        } else {
          chatApi.addErrorMessage(`Blocked: ${data.reason || 'Policy violation'}`);
        }
      } else if (data.status === 'error') {
        chatApi.addErrorMessage(`Error: ${data.reason || 'Action failed'}`);
      } else {
        chatApi.addSystemMessage(data.response || 'Action completed.');
      }
      setState('isProcessing', false);
      chatApi.setInputEnabled(true);
    })
    .catch((err) => {
      removeElement(statusId);
      chatApi.addErrorMessage(`Failed to confirm: ${err.message}`);
      capture({ component: 'plan-gate', action: 'confirm', error: err, context: { confirmationId: confirmationId } });
      setState('isProcessing', false);
      chatApi.setInputEnabled(true);
    });
}

/**
 * Handle the cancel action — POST granted:false.
 * @param {string} confirmationId
 * @param {ChatApi} chatApi
 */
function submitCancel(confirmationId, chatApi) {
  apiPost(`${ENDPOINTS.confirm}/${confirmationId}`, { granted: false, reason: 'Cancelled via WebUI' })
    .then(() => {
      chatApi.addSystemMessage('Action cancelled.');
      setState('isProcessing', false);
      chatApi.setInputEnabled(true);
    })
    .catch((err) => {
      chatApi.addErrorMessage(`Failed to cancel: ${err.message}`);
      capture({ component: 'plan-gate', action: 'cancelConfirmation', error: err });
      setState('isProcessing', false);
      chatApi.setInputEnabled(true);
    });
}

/**
 * Bind click handlers on the confirmation gate buttons.
 * @param {HTMLElement} confirmContainer
 * @param {string} confirmationId
 * @param {ChatApi} chatApi
 */
function bindConfirmationEvents(confirmContainer, confirmationId, chatApi) {
  confirmContainer.addEventListener('click', (e) => {
    const btn = /** @type {HTMLElement} */ (e.target).closest('button[data-action]');
    if (!btn) return;

    confirmContainer.querySelectorAll('button').forEach((b) => {
      b.disabled = true;
    });
    const granted = btn.getAttribute('data-action') === 'confirm';
    confirmContainer.innerHTML = `<span style="color:var(--text-muted)">${granted ? 'Confirmed' : 'Cancelled'}</span>`;

    if (granted) {
      submitConfirm(confirmationId, chatApi);
    } else {
      submitCancel(confirmationId, chatApi);
    }
  });
}

/**
 * Render a confirmation gate with confirm/cancel buttons.
 * Calls POST /api/confirm/{id} on user action.
 * @param {string} preview
 * @param {string} confirmationId
 * @param {*} _taskId
 * @param {*} _resolver
 * @param {ChatApi} chatApi
 */
export function renderConfirmation(preview, confirmationId, _taskId, _resolver, chatApi) {
  if (!isValidUuid(confirmationId)) {
    capture({
      component: 'plan-gate',
      action: 'renderConfirmation',
      error: new Error('Invalid confirmationId format'),
      context: { length: String(confirmationId).length },
    });
    chatApi.addErrorMessage('Confirmation received with invalid ID — rejected for security.');
    return;
  }
  const safeId = escapeHtml(confirmationId);
  chatApi.addMessage('system', buildConfirmationHtml(preview, safeId, chatApi));

  const confirmContainer = document.getElementById(`confirm-${safeId}`);
  if (confirmContainer) {
    bindConfirmationEvents(confirmContainer, confirmationId, chatApi);
  }
}

// ── Approval handler ─────────────────────────────────────────

/**
 * Handle approve/deny action for a plan.
 * Module-scoped — not exposed on window to prevent same-origin
 * scripts from auto-approving plans.
 */
/**
 * Submit an approved plan to the API and display results.
 * @param {string} approvalId
 * @param {ChatApi} chatApi
 */
function submitApproval(approvalId, chatApi) {
  const statusId = `exec-${Date.now()}`;
  chatApi.addStatusMessage('Executing approved plan...', statusId);
  apiPost(`${ENDPOINTS.approve}/${approvalId}`, { granted: true, reason: 'Approved via WebUI' })
    .then((data) => {
      removeElement(statusId);
      if (data.status === 'success') {
        chatApi.addSystemMessage(data.plan_summary || 'Plan executed successfully.');
        renderStepResults(data.step_results, chatApi);
        showToast('Plan executed successfully', 'success');
      } else if (data.status === 'blocked') {
        if (chatApi.addGuardianMessage) {
          chatApi.addGuardianMessage(data.reason || 'A safety policy stopped this plan.');
        } else {
          chatApi.addErrorMessage(`Execution blocked: ${data.reason || 'Policy violation'}`);
        }
        renderStepResults(data.step_results, chatApi);
      } else if (data.status === 'error') {
        chatApi.addErrorMessage(`Execution error: ${data.reason || 'Unknown error'}`);
      } else {
        chatApi.addErrorMessage(`Unexpected result: ${escapeHtml(JSON.stringify(data))}`);
      }
      setState('isProcessing', false);
      chatApi.setInputEnabled(true);
    })
    .catch((err) => {
      removeElement(statusId);
      chatApi.addErrorMessage(`Failed to submit approval: ${err.message}`);
      capture({ component: 'plan-gate', action: 'handleApproval', error: err, context: { approvalId: approvalId } });
      setState('isProcessing', false);
      chatApi.setInputEnabled(true);
    });
}

/**
 * Submit a plan denial to the API.
 * @param {string} approvalId
 * @param {ChatApi} chatApi
 */
function submitDenial(approvalId, chatApi) {
  apiPost(`${ENDPOINTS.approve}/${approvalId}`, { granted: false, reason: 'Denied via WebUI' })
    .then(() => {
      chatApi.addSystemMessage('Plan denied.');
      showToast('Plan denied', 'info');
      setState('isProcessing', false);
      chatApi.setInputEnabled(true);
    })
    .catch((err) => {
      chatApi.addErrorMessage(`Failed to submit denial: ${err.message}`);
      capture({ component: 'plan-gate', action: 'handleDenial', error: err });
      setState('isProcessing', false);
      chatApi.setInputEnabled(true);
    });
}

/**
 * @param {string} approvalId
 * @param {boolean} granted
 * @param {ChatApi} chatApi
 */
function handleApproval(approvalId, granted, chatApi) {
  // Defence-in-depth: re-validate even though renderPlan already validated.
  // The data-approval-id attribute could theoretically be mutated via devtools.
  if (!isValidUuid(approvalId)) {
    capture({
      component: 'plan-gate',
      action: 'handleApproval',
      error: new Error('Invalid approvalId format'),
      context: { length: String(approvalId).length },
    });
    chatApi.addErrorMessage('Invalid approval ID — action rejected.');
    return;
  }
  const btnContainer = document.getElementById(`approval-${approvalId}`);
  if (!btnContainer) return;

  btnContainer.querySelectorAll('button').forEach((b) => {
    b.disabled = true;
  });
  const action = granted ? 'Approved — running now' : 'Cancelled';
  btnContainer.innerHTML = `<span style="color:var(--text-muted)">${action}</span>`;

  if (granted) {
    submitApproval(approvalId, chatApi);
  } else {
    submitDenial(approvalId, chatApi);
  }

  chatApi.appendToHistory({ role: 'approval', approvalId: approvalId, granted: granted });
}

// ── Step results ─────────────────────────────────────────────

/**
 * @param {Array<*>} stepResults
 * @param {ChatApi} chatApi
 * @returns {string}
 */
function buildStepResultsHtml(stepResults, chatApi) {
  let html = `${chatApi.sentinelHead ? chatApi.sentinelHead() : ''}<div class="step-results">`;
  for (let i = 0; i < stepResults.length; i++) {
    const step = stepResults[i];
    const status = step.status || 'unknown';
    html += `<div class="step-result ${stepStatusClass(status)}">`;
    html += `<div class="step-result-header">${escapeHtml(step.step_id || 'Step')} — ${escapeHtml(status)}</div>`;
    if (step.content) html += `<div class="step-result-content">${escapeHtml(step.content)}</div>`;
    if (step.error) html += `<div class="step-result-content" style="color:var(--red)">${escapeHtml(step.error)}</div>`;
    html += '</div>';
  }
  html += '</div>';
  return html;
}

/**
 * Render step results and append to chat history.
 * @param {Array<Object>} stepResults
 * @param {ChatApi} chatApi
 */
export function renderStepResults(stepResults, chatApi) {
  if (!stepResults || stepResults.length === 0) return;
  chatApi.addMessage('system', buildStepResultsHtml(stepResults, chatApi));
  chatApi.appendToHistory({ role: 'results', stepResults: stepResults });
}

/**
 * Render step results without appending to history (for restored history).
 * @param {Array<Object>} stepResults
 * @param {ChatApi} chatApi
 */
export function renderStepResultsStatic(stepResults, chatApi) {
  if (!stepResults || stepResults.length === 0) return;
  chatApi.addMessage('system', buildStepResultsHtml(stepResults, chatApi));
}

// ── Approval polling ─────────────────────────────────────────

// Tracks active poll timers by approvalId so they can be cancelled
// on view unload or when the approval resolves — prevents orphaned
// setTimeout chains from continuing to fire API requests.
/** @type {Record<string, (ReturnType<typeof setTimeout>|null)>} */
const activePollTimers = {};

/**
 * Route a poll response by status. Returns true if the poll resolved
 * (no further polling needed), false if the caller should schedule
 * the next attempt.
 * @param {*} data
 * @param {string} approvalId
 * @param {string} statusElId
 * @param {ChatApi} chatApi
 * @returns {boolean}
 */
function handlePollResult(data, approvalId, statusElId, chatApi) {
  if (data.status === 'pending') {
    delete activePollTimers[approvalId];
    removeElement(statusElId);
    renderPlan(data.plan_summary || 'Plan ready', data.steps || [], approvalId, chatApi);
    return true;
  }
  if (data.status === 'approved' || data.status === 'denied' || data.status === 'expired') {
    delete activePollTimers[approvalId];
    removeElement(statusElId);
    chatApi.addSystemMessage(`Approval status: ${data.status}${data.reason ? ` — ${data.reason}` : ''}`);
    return true;
  }
  if (data.status === 'not_found') {
    delete activePollTimers[approvalId];
    removeElement(statusElId);
    chatApi.addErrorMessage('Approval request not found.');
    return true;
  }
  return false;
}

/**
 * Poll for approval status (HTTP transport fallback).
 * @param {string} approvalId
 * @param {string} statusElId
 * @param {ChatApi} chatApi
 * @param {number} [attempt]
 */
export function pollApproval(approvalId, statusElId, chatApi, attempt) {
  if (!isValidUuid(approvalId)) {
    capture({
      component: 'plan-gate',
      action: 'pollApproval',
      error: new Error('Invalid approvalId format'),
      context: { length: String(approvalId).length },
    });
    return;
  }
  const currentAttempt = attempt || 0;

  function scheduleNext() {
    const timerId = setTimeout(() => {
      pollApproval(approvalId, statusElId, chatApi, currentAttempt + 1);
    }, POLL_INTERVAL_MS);
    activePollTimers[approvalId] = timerId;
  }

  if (currentAttempt >= POLL_MAX_ATTEMPTS) {
    delete activePollTimers[approvalId];
    removeElement(statusElId);
    chatApi.addErrorMessage(
      `Approval polling timed out after ${Math.round((POLL_MAX_ATTEMPTS * POLL_INTERVAL_MS) / 1000)}s.`,
    );
    setState('isProcessing', false);
    chatApi.setInputEnabled(true);
    return;
  }
  // Mark as actively polling BEFORE dispatching the request —
  // ensures cancelApprovalPoll can find and cancel this poll even
  // if called during the (theoretically synchronous) fetch window.
  if (!(approvalId in activePollTimers)) {
    activePollTimers[approvalId] = null;
  }

  apiGet(`${ENDPOINTS.approval}/${approvalId}`)
    .then((data) => {
      if (!(approvalId in activePollTimers)) return;
      if (!handlePollResult(data, approvalId, statusElId, chatApi)) {
        scheduleNext();
      }
    })
    .catch((err) => {
      if (!(approvalId in activePollTimers)) return;
      capture({
        component: 'plan-gate',
        action: 'pollApproval',
        error: err,
        context: { approvalId: approvalId, attempt: currentAttempt },
      });
      scheduleNext();
    });
}

/**
 * Cancel an active approval poll. Safe to call if no poll is active.
 * @param {string} approvalId
 */
export function cancelApprovalPoll(approvalId) {
  if (approvalId in activePollTimers) {
    if (activePollTimers[approvalId] !== null) {
      clearTimeout(activePollTimers[approvalId]);
    }
    delete activePollTimers[approvalId];
  }
}

/**
 * Cancel all active approval polls. Called on view unload to prevent
 * orphaned poll chains from continuing after navigation.
 */
export function cancelAllApprovalPolls() {
  const ids = Object.keys(activePollTimers);
  for (let i = 0; i < ids.length; i++) {
    cancelApprovalPoll(ids[i]);
  }
}
