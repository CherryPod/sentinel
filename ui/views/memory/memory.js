/**
 * Memory view — search, store, browse, and delete episodic memory chunks.
 *
 * Self-registers with the view registry. All memory DOM is created
 * in render() — no markup needed in index.html.
 */

import '../../components/lit/cherry-empty-state.js';
import { confirmDialog } from '../../components/confirm-dialog.js';
import { apiDelete, apiGet, apiPost, ENDPOINTS } from '../../core/api.js';
import { MEMORY_PREVIEW_CHARS, MEMORY_SEARCH_DEBOUNCE_MS } from '../../core/constants.js';
import { capture } from '../../core/errors.js';
import { registerView } from '../../core/router.js';
import { escapeHtml, formatTime, showToast } from '../../core/ui-helpers.js';

// ── State ────────────────────────────────────────────────────

let searchTimer = null;
let storeFormVisible = false;

// ── DOM references (set in render) ──────────────────────────

let searchInput = null;
let resultsContainer = null;
let storeForm = null;
let storeContentEl = null;
let storeSourceEl = null;

// ── Data loading ────────────────────────────────────────────

function loadMemory() {
  const query = searchInput ? searchInput.value.trim() : '';
  const url = query
    ? `${ENDPOINTS.memory}/search?query=${encodeURIComponent(query)}`
    : `${ENDPOINTS.memory}/list?limit=20`;

  apiGet(url)
    .then((data) => {
      renderResults(data.chunks || data.results || []);
    })
    .catch((err) => {
      capture({ component: 'memory', action: 'loadMemory', error: err });
      showToast('Failed to load memory', 'error');
    });
}

// ── Search (debounced) ──────────────────────────────────────

function onSearchInput() {
  if (searchTimer) clearTimeout(searchTimer);
  searchTimer = setTimeout(() => {
    loadMemory();
  }, MEMORY_SEARCH_DEBOUNCE_MS);
}

// ── Results rendering ───────────────────────────────────────

function renderResults(chunks) {
  if (!resultsContainer) return;

  if (!chunks || chunks.length === 0) {
    resultsContainer.innerHTML =
      '<cherry-empty-state pose="sleeping" ' +
      'message="I haven’t remembered anything yet. I’ll store useful things as we work together."></cherry-empty-state>';
    return;
  }

  let html = '';
  for (let i = 0; i < chunks.length; i++) {
    const chunk = chunks[i];
    const content = chunk.content || chunk.text || '';
    const preview =
      content.length > MEMORY_PREVIEW_CHARS ? `${content.substring(0, MEMORY_PREVIEW_CHARS)}...` : content;
    const source = chunk.source || 'unknown';
    const score = chunk.score != null ? chunk.score.toFixed(3) : '';
    const chunkId = chunk.chunk_id || chunk.id || '';
    const created = formatTime(chunk.created_at);

    html += `<div class="memory-card" data-chunk-id="${escapeHtml(String(chunkId))}">`;
    html += `<div class="memory-card-preview">${escapeHtml(preview)}</div>`;
    html += `<div class="memory-card-full" style="display:none">${escapeHtml(content)}</div>`;
    html += '<div class="memory-card-meta">';
    html += `<span class="memory-source">From ${escapeHtml(source)} · ${escapeHtml(created)}</span>`;
    if (score) html += `<span class="memory-score precise-only">Score: ${escapeHtml(score)}</span>`;
    html += `<span class="memory-chunk-id precise-only">ID: ${escapeHtml(String(chunkId))}</span>`;
    html += '</div>';
    html += `<button class="btn-sm danger memory-delete-btn" data-delete-id="${escapeHtml(String(chunkId))}">Delete</button>`;
    html += '</div>';
  }
  resultsContainer.innerHTML = html;
}

// ── Card expand/collapse ────────────────────────────────────

function onResultsClick(e) {
  // Handle delete button
  const deleteBtn = e.target.closest('.memory-delete-btn');
  if (deleteBtn) {
    e.stopPropagation();
    const deleteId = deleteBtn.getAttribute('data-delete-id');
    deleteMemory(deleteId);
    return;
  }

  // Handle card expand/collapse
  const card = e.target.closest('.memory-card');
  if (!card) return;

  const preview = card.querySelector('.memory-card-preview');
  const full = card.querySelector('.memory-card-full');
  if (!preview || !full) return;

  const isExpanded = full.style.display !== 'none';
  if (isExpanded) {
    full.style.display = 'none';
    preview.style.display = '';
    card.classList.remove('expanded');
  } else {
    full.style.display = '';
    preview.style.display = 'none';
    card.classList.add('expanded');
  }
}

// ── Delete ──────────────────────────────────────────────────

async function deleteMemory(id) {
  if (!(await confirmDialog('Delete this memory chunk?', { danger: true, confirmText: 'Delete' }))) return;

  apiDelete(`${ENDPOINTS.memory}/${id}`)
    .then(() => {
      showToast('Memory chunk deleted', 'success');
      loadMemory();
    })
    .catch((err) => {
      capture({ component: 'memory', action: 'deleteMemory', error: err });
      showToast('Failed to delete memory chunk', 'error');
    });
}

// ── Store form ──────────────────────────────────────────────

function toggleStoreForm() {
  storeFormVisible = !storeFormVisible;
  if (storeForm) {
    storeForm.style.display = storeFormVisible ? '' : 'none';
  }
  // Clear fields when hiding
  if (!storeFormVisible) {
    if (storeContentEl) storeContentEl.value = '';
    if (storeSourceEl) storeSourceEl.value = '';
  }
}

function saveMemory() {
  const text = storeContentEl ? storeContentEl.value.trim() : '';
  const source = storeSourceEl ? storeSourceEl.value.trim() : '';

  if (!text) {
    showToast('Memory content is required', 'error');
    return;
  }

  apiPost(ENDPOINTS.memory, { text: text, source: source || 'manual' })
    .then(() => {
      showToast('Memory stored', 'success');
      toggleStoreForm();
      loadMemory();
    })
    .catch((err) => {
      capture({ component: 'memory', action: 'saveMemory', error: err });
      showToast('Failed to store memory', 'error');
    });
}

// ── Template ────────────────────────────────────────────────

function buildMemoryHtml() {
  return (
    '<div class="view-header">' +
    '<h2>Memory</h2>' +
    '<button class="btn btn-primary" id="memory-store-toggle">Store Memory</button>' +
    '</div>' +
    '<div class="view-content memory-content">' +
    // Store form (hidden by default)
    '<div class="memory-store-form" id="memory-store-form" style="display:none">' +
    '<label for="memory-store-content" class="sr-only">Memory content</label>' +
    '<textarea id="memory-store-content" class="memory-textarea" ' +
    'placeholder="Enter memory content..." rows="4"></textarea>' +
    '<label for="memory-store-source" class="sr-only">Source</label>' +
    '<input type="text" id="memory-store-source" class="memory-input" ' +
    'placeholder="Source (optional)">' +
    '<div class="memory-store-actions">' +
    '<button class="btn btn-primary" id="memory-save-btn">Save</button>' +
    '<button class="btn btn-secondary" id="memory-cancel-btn">Cancel</button>' +
    '</div>' +
    '</div>' +
    // Search bar
    '<div class="memory-search">' +
    '<label for="memory-search-input" class="sr-only">Search memory</label>' +
    '<input type="text" id="memory-search-input" class="memory-search-input" ' +
    'placeholder="Search memory...">' +
    '</div>' +
    // Results
    '<div class="memory-results" id="memory-results">' +
    '<div class="empty-state">No memory chunks loaded</div>' +
    '</div>' +
    '</div>'
  );
}

function bindMemoryEvents() {
  // Acquire DOM references
  searchInput = document.getElementById('memory-search-input');
  resultsContainer = document.getElementById('memory-results');
  storeForm = document.getElementById('memory-store-form');
  storeContentEl = document.getElementById('memory-store-content');
  storeSourceEl = document.getElementById('memory-store-source');

  // Bind events
  if (searchInput) {
    searchInput.addEventListener('input', onSearchInput);
  }

  const toggleBtn = document.getElementById('memory-store-toggle');
  if (toggleBtn) {
    toggleBtn.addEventListener('click', toggleStoreForm);
  }

  const saveBtn = document.getElementById('memory-save-btn');
  if (saveBtn) {
    saveBtn.addEventListener('click', saveMemory);
  }

  const cancelBtn = document.getElementById('memory-cancel-btn');
  if (cancelBtn) {
    cancelBtn.addEventListener('click', toggleStoreForm);
  }

  // Event delegation for results (expand/collapse + delete)
  if (resultsContainer) {
    resultsContainer.addEventListener('click', onResultsClick);
  }
}

function renderTemplate(container) {
  container.innerHTML = buildMemoryHtml();
  bindMemoryEvents();
}

// ── Lifecycle ───────────────────────────────────────────────

function onLoad() {
  storeFormVisible = false;
  loadMemory();
}

function onUnload() {
  // Clear any pending search timer
  if (searchTimer) {
    clearTimeout(searchTimer);
    searchTimer = null;
  }
  // DOM refs are NOT nullified — the view section persists in the DOM
  // and render() is only called once. Refs remain valid across load/unload cycles.
}

// ── Registration ────────────────────────────────────────────

registerView({
  id: 'memory',
  label: 'Memory',
  icon:
    '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2">' +
    '<ellipse cx="12" cy="5" rx="9" ry="3"/>' +
    '<path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/>' +
    '<path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>' +
    '</svg>',
  navOrder: 3,
  render: renderTemplate,
  load: onLoad,
  unload: onUnload,
});
