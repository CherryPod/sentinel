/**
 * Chat view — task submission, transport event routing, history restore.
 *
 * Self-registers with the router on import. Owns task lifecycle (WS + HTTP
 * fallback) and transport-event wiring. The transcript surface (message DOM,
 * welcome state, chatApi) lives in ./messages.js; plan/approval/confirmation
 * rendering is delegated to components/plan-gate.js.
 */

import { cherrySvg } from '../../assets/cherry.js';
import { brand } from '../../brand.js';
import { confirmDialog } from '../../components/confirm-dialog.js';
import { renderMarkdown } from '../../components/markdown.js';
import {
  cancelAllApprovalPolls,
  pollApproval,
  renderConfirmation,
  renderPlan,
  renderStepResults,
  renderStepResultsStatic,
} from '../../components/plan-gate.js';
import { bindStepToggles, buildStepsHtml, stepStatusClass } from '../../components/plan-steps.js';
import { apiPost, ENDPOINTS } from '../../core/api.js';
import { WS_TASK_TIMEOUT_MS } from '../../core/constants.js';
import { capture } from '../../core/errors.js';
import { on as onEvent } from '../../core/events.js';
import { registerView, showView } from '../../core/router.js';
import { get as getState, set as setState, subscribe } from '../../core/state.js';
import { getTransportType, isWsConnected, sendWs } from '../../core/transport.js';
import {
  appendToHistory,
  clearHistory,
  escapeHtml,
  getSessionId,
  loadHistory,
  removeElement,
  resetSessionId,
  showToast,
} from '../../core/ui-helpers.js';
import { createMessageSurface, guardianHtml, sentinelHead } from './messages.js';

// ── DOM references ──────────────────────────────────────────
// Set after the chat view renders (see registerView below)
let messagesEl = null;
let chatWelcome = null;
let chatInitialised = false;

// ── Transcript surface ──────────────────────────────────────
// The message surface owns message DOM + welcome state + the chatApi object
// handed to plan-gate. Created in render() once DOM refs exist; null before
// the chat view first renders.
let msgs = null;

// ── Task resolver tracking ──────────────────────────────────
// Maps task IDs to their UI state (status element ID, incremental step tracking).
// Pending tasks use 'pending-<id>' keys until the server assigns a real task ID.
const wsTaskResolvers = {};
// Tracks the single pending resolver key — avoids scanning wsTaskResolvers
// for 'pending-*' keys which would be order-dependent if multiple existed.
let currentPendingKey = null;
// True while an approval or confirmation gate is live. Prevents the permanent
// WS→HTTP fallback from clearing isProcessing prematurely — the gate itself
// (via plan-gate.js) resets isProcessing when the user acts on it over HTTP.
let approvalGateActive = false;

// ── Input references (from persistent footer in index.html) ─
const input = document.getElementById('task-input');
const sendBtn = document.getElementById('send-btn');

// ── Template ────────────────────────────────────────────────

function buildChatHtml() {
  return (
    '<div class="view-header chat-header">' +
    '<h2>Chat</h2>' +
    '<button class="btn btn-secondary btn-sm" id="clear-chat-btn" title="Clear conversation">Clear</button>' +
    '</div>' +
    '<div id="chat-welcome" class="chat-welcome">' +
    '<div class="welcome-mark">' +
    cherrySvg('idle', 96) +
    '</div>' +
    '<div class="welcome-title">' +
    escapeHtml(brand.name) +
    '</div>' +
    '<div class="welcome-sub">' +
    escapeHtml(brand.welcomeMessage) +
    '</div>' +
    '<div class="welcome-chips">' +
    '<button type="button" class="welcome-chip">What can you do?</button>' +
    '<button type="button" class="welcome-chip">Check my calendar for tomorrow</button>' +
    '<button type="button" class="welcome-chip">Summarise my unread email</button>' +
    '</div>' +
    '</div>' +
    '<main id="messages"></main>'
  );
}

function bindChatEvents() {
  const clearChatBtn = document.getElementById('clear-chat-btn');
  if (clearChatBtn) {
    clearChatBtn.addEventListener('click', async () => {
      if (await confirmDialog('Clear conversation history?', { confirmText: 'Clear' })) {
        clearHistory();
        messagesEl = document.getElementById('messages');
        if (messagesEl) messagesEl.innerHTML = '';
        resetSessionId();
        if (msgs) msgs.showWelcome();
        showToast('History cleared', 'info');
      }
    });
  }

  // Welcome chips FILL the input — they never auto-send; submission stays a
  // deliberate user action (Enter or the send button).
  document.querySelectorAll('.welcome-chip').forEach((chip) => {
    chip.addEventListener('click', () => {
      if (input) {
        input.value = chip.textContent;
        input.focus();
      }
    });
  });
}

// ── View registration ───────────────────────────────────────

registerView({
  id: 'chat',
  label: 'Chat',
  icon:
    '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2">' +
    '<path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>' +
    '</svg>',
  navOrder: 2,
  render: (container) => {
    container.innerHTML = buildChatHtml();
    bindChatEvents();
    subscribeTransportEvents();
    messagesEl = document.getElementById('messages');
    chatWelcome = document.getElementById('chat-welcome');
    msgs = createMessageSurface({
      messagesEl: messagesEl,
      welcomeEl: chatWelcome,
      setInputEnabled: setInputEnabled,
    });
  },
  load: () => {
    // Restore history on first load, focus input
    if (!chatInitialised) {
      restoreHistory();
      chatInitialised = true;
    }
    if (input) input.focus();
  },
  unload: () => {
    // Chat DOM refs stay valid — the container is hidden, not destroyed.
    // Transport event subscriptions stay active for the app lifecycle
    // (tasks run in background while other views are shown). The guard
    // in subscribeTransportEvents() prevents duplicates on re-import.
    // Call unsubscribeTransportEvents() explicitly for test teardown.
  },
});

// ── Transport event subscriptions ───────────────────────────
// Connection/reconnect/auth handled by core/transport.js.
// UI-level message routing is wired here via event subscriptions.
// Subscribed once in subscribeTransportEvents() (called from render),
// not at module scope — prevents duplicate handlers on re-import.

const eventUnsubs = [];

function onDisconnected() {
  cancelAllApprovalPolls();
  if (getState('isProcessing')) {
    // Task in flight — keep resolvers alive for potential WS reconnect.
    // WS_TASK_TIMEOUT_MS is the ultimate backstop.
    // Remove stale status spinners (they show misleading state).
    const keys = Object.keys(wsTaskResolvers);
    for (let i = 0; i < keys.length; i++) {
      const r = wsTaskResolvers[keys[i]];
      if (r && r.statusId) removeElement(r.statusId);
    }
    if (msgs) msgs.addErrorMessage('Connection lost — reconnecting. Task may still be running.');
  } else {
    // No task in flight — clean wipe.
    const keys = Object.keys(wsTaskResolvers);
    for (let i = 0; i < keys.length; i++) {
      delete wsTaskResolvers[keys[i]];
    }
    currentPendingKey = null;
  }
}

function onWsError(ev) {
  if (!msgs) return;
  msgs.addErrorMessage(ev.reason);
  if (getState('isProcessing') && !approvalGateActive) {
    setState('isProcessing', false);
    setInputEnabled(true);
  }
}

// ── Task event handler registry ─────────────────────────────
// Map of task event name → handler. New task lifecycle events
// register a handler instead of adding an if/else branch.
// Handler signature: (taskId, data, resolver) — resolver is
// guaranteed non-null by the dispatch function.

const taskEventHandlers = new Map();

function registerTaskEvent(eventName, fn) {
  taskEventHandlers.set(eventName, fn);
}

registerTaskEvent('started', (_taskId, data, resolver) => {
  msgs.updateStatusMessage(resolver.statusId, data.response || 'Planning task...');
});

registerTaskEvent('planned', (_taskId, _data, resolver) => {
  msgs.updateStatusMessage(resolver.statusId, 'Executing plan...');
});

registerTaskEvent('approval_requested', (_taskId, data, resolver) => {
  resolver.cleaned = true;
  approvalGateActive = true;
  removeElement(resolver.statusId);
  renderPlan(data.plan_summary || 'Plan ready', data.steps || [], data.approval_id || '', msgs);
});

registerTaskEvent('awaiting_confirmation', (taskId, data, resolver) => {
  resolver.cleaned = true;
  approvalGateActive = true;
  removeElement(resolver.statusId);
  renderConfirmation(data.preview || 'Confirm action?', data.confirmation_id || '', taskId, resolver, msgs);
});

registerTaskEvent('step_completed', (taskId, data, resolver) => {
  const stepStatus = data.status === 'success' ? 'completed' : data.status;
  msgs.updateStatusMessage(resolver.statusId, `Step ${data.step_id || '?'} ${stepStatus}`);
  const stepContent = data.content_preview || data.content || '';
  if (stepContent || data.error) {
    if (!resolver.incrementalStepsId) {
      resolver.incrementalStepsId = `incremental-steps-${taskId}`;
      const containerHtml =
        sentinelHead() + '<div class="step-results" id="' + resolver.incrementalStepsId + '-inner"></div>';
      msgs.addMessage('system', containerHtml, resolver.incrementalStepsId);
    }
    const inner = document.getElementById(`${resolver.incrementalStepsId}-inner`);
    if (inner) {
      let stepHtml = `<div class="step-result ${stepStatusClass(stepStatus)}">`;
      stepHtml +=
        '<div class="step-result-header">' +
        escapeHtml(data.step_id || 'Step') +
        ' — ' +
        escapeHtml(stepStatus) +
        '</div>';
      if (stepContent) stepHtml += `<div class="step-result-content">${escapeHtml(stepContent)}</div>`;
      if (data.error)
        stepHtml += `<div class="step-result-content" style="color:var(--red)">${escapeHtml(data.error)}</div>`;
      stepHtml += '</div>';
      inner.insertAdjacentHTML('beforeend', stepHtml);
      msgs.scrollMessages();
    }
    resolver.hasIncrementalSteps = true;
  }
});

registerTaskEvent('blocked', (taskId, data, resolver) => {
  resolver.cleaned = true;
  removeElement(resolver.statusId);
  delete wsTaskResolvers[taskId];
  msgs.addGuardianMessage(data.reason || 'A safety policy stopped this plan.');
  setState('isProcessing', false);
  setInputEnabled(true);
});

registerTaskEvent('completed', (taskId, data, resolver) => {
  resolver.cleaned = true;
  removeElement(resolver.statusId);
  delete wsTaskResolvers[taskId];
  if (data.status === 'success') {
    msgs.addSystemMessage(data.response || data.plan_summary || 'Task completed.');
    if (data.step_results) {
      if (resolver.hasIncrementalSteps && resolver.incrementalStepsId) {
        removeElement(resolver.incrementalStepsId);
      }
      renderStepResults(data.step_results, msgs);
    }
  } else if (data.status === 'blocked') {
    msgs.addGuardianMessage(data.reason || 'A safety policy stopped this plan.');
  } else if (data.status === 'error') {
    msgs.addErrorMessage(`Error: ${data.reason || 'Task failed'}`);
  } else {
    msgs.addSystemMessage(data.response || data.plan_summary || 'Task completed.');
  }
  setState('isProcessing', false);
  setInputEnabled(true);
});

function onTaskEvent(ev) {
  if (!msgs) return;
  const taskId = ev.taskId;
  const data = ev.data;
  let resolver = wsTaskResolvers[taskId];

  // Adopt pending resolver — map server-assigned task_id to the UI's pending key.
  if (!resolver && currentPendingKey && wsTaskResolvers[currentPendingKey]) {
    resolver = wsTaskResolvers[currentPendingKey];
    resolver.currentKey = taskId;
    wsTaskResolvers[taskId] = resolver;
    delete wsTaskResolvers[currentPendingKey];
    currentPendingKey = null;
  }

  if (!resolver) return;

  const handler = taskEventHandlers.get(ev.event);
  if (handler) handler(taskId, data, resolver);
}

function onApprovalResult(ev) {
  if (!msgs) return;
  const result = ev.data;
  if (result.status === 'success') {
    msgs.addSystemMessage(result.plan_summary || 'Plan executed successfully.');
    renderStepResults(result.step_results, msgs);
  } else if (result.status === 'denied') {
    msgs.addSystemMessage('Plan denied.');
  } else if (result.status === 'error') {
    msgs.addErrorMessage(result.reason || 'Approval error');
  }
}

// Subscribe all transport events — called once from render().
// Unsub handles stored for cleanup (test harness, full teardown).
function subscribeTransportEvents() {
  if (eventUnsubs.length > 0) return;
  eventUnsubs.push(onEvent('transport:disconnected', onDisconnected));
  eventUnsubs.push(onEvent('ws:error', onWsError));
  eventUnsubs.push(onEvent('task:event', onTaskEvent));
  eventUnsubs.push(onEvent('approval:result', onApprovalResult));
  // Permanent HTTP fallback — clean up if WS reconnect failed.
  eventUnsubs.push(
    subscribe('transportType', (newType, prevType) => {
      if (prevType === 'ws' && newType === 'http' && getState('isProcessing')) {
        const keys = Object.keys(wsTaskResolvers);
        for (let i = 0; i < keys.length; i++) {
          const r = wsTaskResolvers[keys[i]];
          if (r) r.cleaned = true;
          delete wsTaskResolvers[keys[i]];
        }
        currentPendingKey = null;
        if (approvalGateActive) {
          if (msgs) msgs.addErrorMessage('Connection lost — your approval decision will be submitted over HTTP.');
        } else {
          if (msgs) msgs.addErrorMessage('Connection lost permanently — task status unknown.');
          setState('isProcessing', false);
          setInputEnabled(true);
        }
      }
    }),
  );
}

// Exported for test teardown — unsubscribes all transport event handlers.
export function unsubscribeTransportEvents() {
  for (let i = 0; i < eventUnsubs.length; i++) eventUnsubs[i]();
  eventUnsubs.length = 0;
}

// ── Core task flow ──────────────────────────────────────────

/**
 * Send task over WebSocket with timeout guard.
 * Registers a pending resolver so incoming task:event messages
 * can be matched to this submission.
 */
function sendViaWs(text, statusId) {
  const pendingKey = `pending-${statusId}`;
  const resolver = { statusId: statusId, currentKey: pendingKey, cleaned: false };
  wsTaskResolvers[pendingKey] = resolver;
  currentPendingKey = pendingKey;
  try {
    sendWs({ type: 'task', request: text });
    setTimeout(() => {
      if (resolver.cleaned) return;
      resolver.cleaned = true;
      removeElement(resolver.statusId);
      delete wsTaskResolvers[resolver.currentKey];
      if (currentPendingKey === resolver.currentKey) currentPendingKey = null;
      msgs.addErrorMessage('Task timed out — no response from server.');
      setState('isProcessing', false);
      setInputEnabled(true);
    }, WS_TASK_TIMEOUT_MS);
  } catch (err) {
    resolver.cleaned = true;
    removeElement(statusId);
    delete wsTaskResolvers[pendingKey];
    if (currentPendingKey === pendingKey) currentPendingKey = null;
    msgs.addErrorMessage(`WebSocket send failed: ${err.message}`);
    capture({ component: 'chat', action: 'sendTask.ws', error: err });
    setState('isProcessing', false);
    setInputEnabled(true);
  }
}

/**
 * Send task over HTTP and route the response to the appropriate
 * UI handler (approval flow, success, error, etc.).
 */
function sendViaHttp(text, statusId) {
  apiPost(ENDPOINTS.task, { request: text, source: 'webui', session_id: getSessionId() })
    .then((data) => {
      removeElement(statusId);

      if (data.conversation?.warnings && data.conversation.warnings.length > 0) {
        msgs.renderWarnings(data.conversation.warnings);
        appendToHistory({ role: 'warnings', warnings: data.conversation.warnings });
      }

      if (data.status === 'awaiting_approval') {
        const approvalId = data.approval_id || data.reason.replace('approval_id:', '');
        msgs.addStatusMessage('Waiting for plan...', `${statusId}-poll`);
        pollApproval(approvalId, `${statusId}-poll`, msgs);
      } else if (data.status === 'success') {
        msgs.addSystemMessage(data.response || data.plan_summary || 'Task completed.');
        if (data.step_results) renderStepResults(data.step_results, msgs);
      } else if (data.status === 'blocked') {
        msgs.addGuardianMessage(data.reason || 'A safety policy stopped this plan.');
      } else if (data.status === 'refused') {
        msgs.addGuardianMessage(data.reason || 'I decided not to do this one.');
      } else if (data.status === 'error') {
        msgs.addErrorMessage(`Error: ${data.reason || 'Unknown error'}`);
      } else {
        msgs.addErrorMessage(`Unexpected response: ${escapeHtml(JSON.stringify(data))}`);
      }
      setState('isProcessing', false);
      setInputEnabled(true);
    })
    .catch((err) => {
      removeElement(statusId);
      msgs.addErrorMessage(`Failed to reach controller: ${err.message}`);
      capture({ component: 'chat', action: 'sendTask.http', error: err });
      setState('isProcessing', false);
      setInputEnabled(true);
    });
}

/**
 * Submit a task via WebSocket (preferred) or HTTP fallback.
 * Exported so app.js can delegate form submission here.
 */
export function sendTask(text) {
  if (getState('isProcessing')) return;
  approvalGateActive = false;
  setState('isProcessing', true);
  setInputEnabled(false);

  // Ensure we're on chat view (renders the view + sets `msgs` if first visit)
  if (getState('currentView') !== 'chat') showView('chat');

  // Safety net: every other msgs consumer guards this; sendTask is exported
  // and could in principle fire before the chat view has ever rendered.
  if (!msgs) {
    setState('isProcessing', false);
    setInputEnabled(true);
    return;
  }

  msgs.addUserMessage(text);
  const statusId = `status-${Date.now()}`;
  msgs.addStatusMessage('Sending task to planner...', statusId);

  if (getTransportType() === 'ws' && isWsConnected()) {
    sendViaWs(text, statusId);
  } else {
    sendViaHttp(text, statusId);
  }
}

// ── History restore ─────────────────────────────────────────

function restoreHistory() {
  const history = loadHistory();
  if (history.length > 0) msgs.dismissWelcome();
  for (let i = 0; i < history.length; i++) {
    const entry = history[i];
    if (entry.role === 'user') {
      msgs.addMessage('user', escapeHtml(entry.text));
    } else if (entry.role === 'system') {
      if (entry.text != null) {
        msgs.addMessage('system', `${sentinelHead()}<div class="md-content">${renderMarkdown(entry.text)}</div>`);
      } else if (entry.html != null) {
        msgs.addMessage('system', `${sentinelHead()}${escapeHtml(entry.html)}`);
      }
    } else if (entry.role === 'error') {
      msgs.addMessage('error', escapeHtml(entry.text));
    } else if (entry.role === 'guardian') {
      msgs.addMessage('guardian', guardianHtml(entry.text));
    } else if (entry.role === 'warnings') {
      if (entry.warnings) msgs.renderWarnings(entry.warnings);
    } else if (entry.role === 'plan') {
      let html = sentinelHead();
      html += `<div class="plan-summary">${escapeHtml(entry.planSummary || '')}</div>`;
      html += buildStepsHtml(entry.steps);
      const planMsgEl = msgs.addMessage('system', html);
      bindStepToggles(planMsgEl);
    } else if (entry.role === 'results') {
      renderStepResultsStatic(entry.stepResults, msgs);
    }
  }
}

// ── Helpers ─────────────────────────────────────────────────

function setInputEnabled(enabled) {
  input.disabled = !enabled;
  sendBtn.disabled = !enabled;
  if (enabled && getState('currentView') === 'chat') input.focus();
}

// ── Legacy shortcut ─────────────────────────────────────────
// Shift+click on nav brand to clear conversation history.
// Kept as a power-user feature — no UI affordance, intentionally hidden.

const navBrand = document.querySelector('.nav-brand');
if (navBrand)
  navBrand.addEventListener('click', async (e) => {
    if (e.shiftKey) {
      if (await confirmDialog('Clear conversation history?', { confirmText: 'Clear' })) {
        clearHistory();
        if (messagesEl) messagesEl.innerHTML = '';
        resetSessionId();
        if (msgs) msgs.showWelcome();
        showToast('History cleared', 'info');
      }
    }
  });
