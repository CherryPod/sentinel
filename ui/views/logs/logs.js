/**
 * Logs view — real-time SSE log stream with level/task filtering.
 *
 * Self-registers with the view registry. All logs DOM is created
 * in render() — no markup needed in index.html.
 */

import { LOG_MAX_ENTRIES, UUID_DISPLAY_LENGTH } from '../../core/constants.js';
import { capture } from '../../core/errors.js';
import { registerView } from '../../core/router.js';
import { escapeHtml } from '../../core/ui-helpers.js';

// ── State ────────────────────────────────────────────────────

let logAbortController = null;
let logPaused = false;
const logRecentTasks = {}; // task_id → {preview, source}
// Generation counter — incremented on clear and level-change reconnects.
// appendLogEntry checks this to discard stale SSE chunks that were
// in-flight when the clear happened, preventing count/DOM mismatches.
let logGeneration = 0;

// ── DOM references (set in render, cleared in onUnload) ─────

let logEntries = null;
let logEmpty = null;
let logCount = null;
let logLevelFilter = null;
let logTaskFilter = null;
let logPauseBtn = null;

// ── SSE stream connection ───────────────────────────────────

/**
 * Parse an SSE buffer into data-line payloads. Returns the parsed
 * entries and any incomplete trailing chunk to carry forward.
 * Pure function — no DOM, no side effects.
 */
function parseSseBuffer(buffer) {
  // Normalise CRLF → LF (sse_starlette sends \r\n)
  const normalised = buffer.replace(/\r\n/g, '\n');
  // Split on double newline: "event: log\ndata: {...}\n\n"
  const parts = normalised.split('\n\n');
  const remainder = parts.pop(); // keep incomplete chunk
  const entries = [];
  for (let i = 0; i < parts.length; i++) {
    let dataLine = '';
    const lines = parts[i].split('\n');
    for (let j = 0; j < lines.length; j++) {
      if (lines[j].indexOf('data: ') === 0) dataLine = lines[j].substring(6);
    }
    if (dataLine) entries.push(dataLine);
  }
  return { entries: entries, remainder: remainder };
}

/**
 * Start the ReadableStream pump loop for an SSE response.
 * Reads chunks, parses SSE events, and feeds them to appendLogEntry.
 */
function pumpSseStream(reader, streamGeneration) {
  const decoder = new TextDecoder();
  let buffer = '';

  function pump() {
    return reader.read().then((result) => {
      if (result.done) return;
      if (streamGeneration !== logGeneration) return reader.cancel().catch(() => {});
      buffer += decoder.decode(result.value, { stream: true });
      const parsed = parseSseBuffer(buffer);
      buffer = parsed.remainder;
      for (let i = 0; i < parsed.entries.length; i++) {
        if (logPaused || streamGeneration !== logGeneration) return reader.cancel().catch(() => {});
        try {
          appendLogEntry(JSON.parse(parsed.entries[i]));
        } catch (err) {
          capture({
            component: 'logs',
            action: 'parseSSE',
            error: err,
            context: { dataLength: parsed.entries[i].length },
          });
        }
      }
      return pump();
    });
  }
  return pump();
}

/**
 * Handle SSE stream errors. AbortError is expected on navigation/pause.
 */
function handleStreamError(err) {
  if (err.name === 'AbortError') return;
  if (logEmpty) {
    logEmpty.textContent = 'Log stream disconnected. Click Resume to reconnect.';
    logEmpty.style.display = '';
  }
  logAbortController = null;
  capture({ component: 'logs', action: 'connectLogStream', error: err });
}

/**
 * Connect to the log SSE stream using fetch + ReadableStream.
 * Fetch is used instead of EventSource for AbortController support,
 * allowing clean disconnection on view unload or pause.
 */
function connectLogStream() {
  if (logAbortController) {
    logAbortController.abort();
    logAbortController = null;
  }

  const level = logLevelFilter ? logLevelFilter.value : 'INFO';
  const url = `/api/logs/stream?level=${encodeURIComponent(level)}`;

  logAbortController = new AbortController();
  // Capture the generation at connect time — if a clear happens while
  // this stream is delivering, the generation will have advanced and
  // appendLogEntry will discard stale chunks.
  const streamGeneration = logGeneration;

  if (logEmpty) logEmpty.style.display = 'none';

  fetch(url, { signal: logAbortController.signal })
    .then((resp) => {
      if (!resp.ok) throw new Error(`Log stream HTTP ${resp.status}`);
      return pumpSseStream(resp.body.getReader(), streamGeneration);
    })
    .catch(handleStreamError);
}

// ── Task filter dropdown management ─────────────────────────

/**
 * Add a task to the task filter dropdown if not already present.
 * Newest tasks are inserted first (after the "All tasks" option).
 */
function addLogTaskOption(taskId, preview, source) {
  if (!logTaskFilter || logRecentTasks[taskId]) return;
  const short = taskId.substring(0, UUID_DISPLAY_LENGTH);
  const label = `${short} — ${(preview || source || 'task').substring(0, 50)}`;
  logRecentTasks[taskId] = { preview: preview, source: source };
  const opt = document.createElement('option');
  opt.value = taskId;
  opt.textContent = label;
  // Insert after "All tasks" but before older entries (newest first)
  if (logTaskFilter.options.length > 1) {
    logTaskFilter.insertBefore(opt, logTaskFilter.options[1]);
  } else {
    logTaskFilter.appendChild(opt);
  }
}

// ── Log entry rendering ─────────────────────────────────────

/**
 * Build a DOM element for a single log entry row.
 * Pure DOM construction — no container mutation or side effects.
 */
function buildLogRow(entry, entryTaskId) {
  const row = document.createElement('div');
  row.className = `log-entry log-${(entry.level || 'INFO').toLowerCase()}`;
  if (entryTaskId) row.setAttribute('data-task-id', entryTaskId);

  const ts = entry.timestamp
    ? new Date(entry.timestamp * 1000).toLocaleTimeString(undefined, {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
      })
    : '--:--:--';

  let taskBadge = '';
  if (entryTaskId) {
    taskBadge =
      '<span class="log-task-id" title="' +
      escapeHtml(entryTaskId) +
      '">' +
      escapeHtml(entryTaskId.substring(0, UUID_DISPLAY_LENGTH)) +
      '</span>';
  }

  row.innerHTML =
    '<span class="log-ts">' +
    ts +
    '</span>' +
    '<span class="log-level">' +
    escapeHtml(entry.level || 'INFO') +
    '</span>' +
    taskBadge +
    '<span class="log-msg">' +
    escapeHtml(entry.message || '') +
    '</span>' +
    (entry.event ? `<span class="log-event">${escapeHtml(entry.event)}</span>` : '');

  return row;
}

/**
 * Remove oldest log entries to stay within LOG_MAX_ENTRIES.
 */
function capLogEntries() {
  while (logEntries.children.length > LOG_MAX_ENTRIES) {
    logEntries.removeChild(logEntries.firstChild);
  }
}

function appendLogEntry(entry) {
  if (!logEntries) return;
  if (logEmpty) logEmpty.style.display = 'none';

  const entryTaskId = entry.task_id || '';

  // Track new tasks from task_received events for the dropdown
  if (entry.event === 'task_received' && entryTaskId) {
    addLogTaskOption(entryTaskId, entry.message || '', entry.source || '');
  }

  // Client-side task filter
  const taskFilter = logTaskFilter ? logTaskFilter.value : '';
  if (taskFilter && entryTaskId !== taskFilter) return;

  logEntries.appendChild(buildLogRow(entry, entryTaskId));
  capLogEntries();

  logEntries.scrollTop = logEntries.scrollHeight;

  // Update count — use DOM as authoritative source to avoid drift
  const activeFilter = logTaskFilter?.value;
  if (activeFilter) {
    filterLogEntries();
  } else if (logCount) {
    logCount.textContent = `${logEntries.querySelectorAll('.log-entry').length} entries`;
  }
}

// ── Controls ────────────────────────────────────────────────

function toggleLogPause() {
  logPaused = !logPaused;
  if (logPauseBtn) {
    logPauseBtn.textContent = logPaused ? 'Resume' : 'Pause';
  }
  if (logPaused && logAbortController) {
    logAbortController.abort();
    logAbortController = null;
  }
  if (!logPaused) {
    connectLogStream();
  }
}

function clearLogEntries() {
  // Bump generation so in-flight SSE chunks from the old stream
  // are discarded by appendLogEntry — prevents count/DOM mismatches.
  logGeneration++;
  if (logEntries) {
    logEntries.innerHTML = '';
    if (logEmpty) {
      logEmpty.textContent = 'Log entries cleared';
      logEmpty.style.display = '';
      logEntries.appendChild(logEmpty);
    }
  }
  if (logCount) logCount.textContent = '0 entries';
}

/**
 * Client-side filter: show/hide existing log entries by task ID.
 */
function filterLogEntries() {
  const filter = logTaskFilter ? logTaskFilter.value : '';
  if (!logEntries) return;
  const rows = logEntries.querySelectorAll('.log-entry');
  let visible = 0;
  for (let i = 0; i < rows.length; i++) {
    const rowTaskId = rows[i].getAttribute('data-task-id') || '';
    const show = !filter || rowTaskId === filter;
    rows[i].style.display = show ? '' : 'none';
    if (show) visible++;
  }
  if (logCount) logCount.textContent = `${visible} entries`;
}

// ── Template ────────────────────────────────────────────────

function buildLogsHtml() {
  return (
    '<div class="view-header">' +
    '<h2>Logs</h2>' +
    '<div class="log-header-actions">' +
    '<button class="btn btn-secondary btn-sm" id="log-pause-btn" title="Pause log stream">Pause</button>' +
    '<button class="btn btn-secondary btn-sm" id="log-clear-btn" title="Clear log entries">Clear</button>' +
    '</div>' +
    '</div>' +
    '<div class="view-content logs-content">' +
    '<div class="log-controls">' +
    '<div class="log-filter-group">' +
    '<label for="log-level-filter">Level</label>' +
    '<select id="log-level-filter">' +
    '<option value="DEBUG">DEBUG</option>' +
    '<option value="INFO" selected>INFO</option>' +
    '<option value="WARNING">WARNING</option>' +
    '<option value="ERROR">ERROR</option>' +
    '<option value="CRITICAL">CRITICAL</option>' +
    '</select>' +
    '</div>' +
    '<div class="log-filter-group">' +
    '<label for="log-task-filter">Task</label>' +
    '<select id="log-task-filter">' +
    '<option value="">All tasks</option>' +
    '</select>' +
    '</div>' +
    '<span class="log-count" id="log-count">0 entries</span>' +
    '</div>' +
    '<div class="log-stream" id="log-entries">' +
    '<div class="empty-state" id="log-empty">Connecting to log stream...</div>' +
    '</div>' +
    '</div>'
  );
}

function bindLogsEvents() {
  // Acquire DOM references
  logEntries = document.getElementById('log-entries');
  logEmpty = document.getElementById('log-empty');
  logCount = document.getElementById('log-count');
  logLevelFilter = document.getElementById('log-level-filter');
  logTaskFilter = document.getElementById('log-task-filter');
  logPauseBtn = document.getElementById('log-pause-btn');

  // Bind event listeners
  if (logPauseBtn) logPauseBtn.addEventListener('click', toggleLogPause);

  const logClearBtn = document.getElementById('log-clear-btn');
  if (logClearBtn) logClearBtn.addEventListener('click', clearLogEntries);

  if (logLevelFilter) {
    logLevelFilter.addEventListener('change', () => {
      clearLogEntries();
      if (!logPaused) {
        connectLogStream();
      } else if (logEntries) {
        logEntries.innerHTML = '<div class="empty-state">Level changed. Click Resume to see logs.</div>';
      }
    });
  }

  if (logTaskFilter) {
    logTaskFilter.addEventListener('change', () => {
      filterLogEntries();
    });
  }

  // Click on a task ID badge to filter to that task (event delegation)
  if (logEntries) {
    logEntries.addEventListener('click', (e) => {
      const badge = e.target.closest('.log-task-id');
      if (!badge || !logTaskFilter) return;
      const fullId = badge.getAttribute('title');
      if (!fullId) return;
      // Ensure the task is in the dropdown
      addLogTaskOption(fullId, '', '');
      logTaskFilter.value = fullId;
      filterLogEntries();
    });
  }
}

function renderTemplate(container) {
  container.innerHTML = buildLogsHtml();
  bindLogsEvents();
}

// ── Lifecycle ───────────────────────────────────────────────

function onLoad() {
  if (!logPaused && !logAbortController) {
    connectLogStream();
  }
}

function onUnload() {
  // Abort the SSE stream to prevent it running in the background
  if (logAbortController) {
    logAbortController.abort();
    logAbortController = null;
  }
  // Reset view state to prevent stale data on next load
  logPaused = false;
  for (const k of Object.keys(logRecentTasks)) delete logRecentTasks[k];
}

// ── Registration ────────────────────────────────────────────

registerView({
  id: 'logs',
  label: 'Logs',
  icon:
    '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2">' +
    '<polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/>' +
    '</svg>',
  navOrder: 8,
  roles: ['admin', 'owner'],
  render: renderTemplate,
  load: onLoad,
  unload: onUnload,
});
