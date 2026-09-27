// @ts-check
/**
 * Plan step rendering — extracted verbatim from plan-gate.js (Phase 3
 * Task 3.0, behaviour-identical move). Pure string-building + a delegated
 * toggle binder, so the builder is node-testable (see ui/tests/plan-steps.test.mjs).
 *
 * `escapeHtml` is imported from ../core/text.js (the node-safe, DOM-compatible
 * home) rather than ui-helpers.js so this module imports cleanly under node.
 */

import { escapeHtml } from '../core/text.js';

/**
 * A single plan step as delivered by the server (approval payload). All
 * fields optional — the builder tolerates partial steps and worker noise.
 * @typedef {Object} PlanStep
 * @property {string} [type] - 'llm_task' | 'tool_call' | other
 * @property {string} [id]
 * @property {string} [description]
 * @property {string} [prompt] - llm_task prompt (shown in detail drawer)
 * @property {string} [tool] - tool_call tool name
 * @property {Record<string, any>} [args] - tool_call arguments
 * @property {boolean} [expects_code]
 */

// Friendly step-type chips — never show the raw enum to users.
/** @type {Record<string, { chip: string, cls: string }>} */
const STEP_TYPE_META = {
  llm_task: { chip: 'think it through', cls: 'think' },
  tool_call: { chip: 'use a tool', cls: 'tool' },
};

/**
 * Concrete-target line for effectful steps (informed-consent invariant:
 * design doc section 5.1 — recipients/paths/commands visible BY DEFAULT,
 * never only behind the details drawer). Full args remain in the details
 * drawer regardless.
 *
 * The candidate key list is verified against the real tool handlers
 * (sentinel/tools/_handlers/, key-probe completeness sweep — Task 3.6
 * fixtures doc). Every side-effectful handler's primary target key appears
 * below; precedence puts the most consequence-bearing key first. A
 * server-provided `target_summary` field is the proper long-term fix
 * (Appendix B) — until then this probe is the informed-consent surface.
 *
 * @param {PlanStep} step
 * @returns {string}
 */
export function describeTarget(step) {
  if (step.type !== 'tool_call' || !step.tool) return '';
  const a = step.args || {};
  const candidates = [
    a.to,
    a.recipient,
    a.path,
    a.file_path,
    a.url,
    a.command,
    a.query,
    a.site_id,
    a.event_id,
    a.summary,
    a.context_path,
    a.tag,
    a.image,
    a.container_name,
    a.name,
    Array.isArray(a.files) ? a.files.join(', ') : undefined,
  ];
  const target = candidates.find((v) => v !== undefined && v !== null && v !== '');
  if (target !== undefined) return `${step.tool} → ${String(target)}`;
  // Messaging tools can omit an explicit recipient when the channel
  // auto-resolves one (e.g. matrix_send → primary room, needs_recipient=False).
  // The informed-consent invariant still requires telling the user it's a
  // send, not a bare tool name. Best-effort message body for context.
  if (/(_send|_draft|^send_|message)/i.test(step.tool)) {
    const body = a.body ?? a.message ?? a.text ?? a.content ?? '';
    const snippet = body ? ` "${String(body).slice(0, 40)}"` : '';
    return `${step.tool} → default recipient${snippet}`;
  }
  return String(step.tool);
}

// Closed set of status tokens that have a `.step-result.<token>` CSS rule.
// Interpolating a status into a class attribute with text-only escaping is
// not attribute-safe (escapeHtml does not escape quotes), so class names come
// from this allowlist — never from the raw value. Display text is escaped
// separately. Unknown statuses fall back to 'unknown' (styled neutrally).
const _STEP_STATUS_CLASSES = new Set(['success', 'completed', 'blocked', 'error', 'skipped']);

/**
 * Map a step status to a safe CSS class token (allowlist; unknown → 'unknown').
 * @param {*} status
 * @returns {string}
 */
export function stepStatusClass(status) {
  return _STEP_STATUS_CLASSES.has(status) ? String(status) : 'unknown';
}

/**
 * Build HTML for a list of plan steps (collapsible).
 * @param {PlanStep[]|null|undefined} steps
 * @returns {string}
 */
export function buildStepsHtml(steps) {
  if (!steps || steps.length === 0) return '';
  let html = '<ol class="plan-steps">';
  for (let i = 0; i < steps.length; i++) {
    const step = steps[i];
    const meta = STEP_TYPE_META[step.type || ''] || { chip: 'step', cls: 'other' };
    html += '<li class="step-header" tabindex="0">';
    html += `<span class="step-num">${i + 1}</span>`;
    html += `<span class="step-chip ${meta.cls}">${escapeHtml(meta.chip)}</span>`;
    if (step.expects_code) html += '<span class="step-badge">code</span>';
    html += `<span class="step-desc">${escapeHtml(step.description || step.id || '')}</span>`;
    const target = describeTarget(step);
    if (target) html += `<div class="step-target">${escapeHtml(target)}</div>`;
    html += '<span class="step-chevron">&#9654;</span>';
    let detail = '';
    if (step.type === 'llm_task' && step.prompt) {
      detail = escapeHtml(step.prompt);
    } else if (step.type === 'tool_call') {
      const parts = [];
      if (step.tool) parts.push(`tool: ${step.tool}`);
      if (step.args) {
        try {
          parts.push(`args: ${JSON.stringify(step.args, null, 2)}`);
        } catch (_e) {
          parts.push(`args: ${String(step.args)}`);
        }
      }
      detail = escapeHtml(parts.join('\n'));
    }
    if (detail) html += `<pre class="step-detail">${detail}</pre>`;
    html += '</li>';
  }
  html += '</ol>';
  return html;
}

/**
 * Bind click-to-expand on step headers via event delegation.
 * A single listener on the container handles all current and future
 * step headers — no per-element listeners to accumulate.
 * @param {HTMLElement} container
 * @returns {void}
 */
export function bindStepToggles(container) {
  container.addEventListener('click', (e) => {
    const target = /** @type {HTMLElement} */ (e.target);
    if (target.tagName === 'BUTTON') return;
    const stepHeader = target.closest('.step-header');
    if (stepHeader && container.contains(stepHeader)) {
      stepHeader.classList.toggle('expanded');
    }
  });
  container.addEventListener('keydown', (e) => {
    const ke = /** @type {KeyboardEvent} */ (e);
    if (ke.key !== 'Enter' && ke.key !== ' ') return;
    const stepHeader = /** @type {HTMLElement} */ (ke.target).closest('.step-header');
    if (stepHeader && container.contains(stepHeader)) {
      ke.preventDefault();
      stepHeader.classList.toggle('expanded');
    }
  });
}
