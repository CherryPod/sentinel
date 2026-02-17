(function () {
    'use strict';

    const messagesEl = document.getElementById('messages');
    const form = document.getElementById('input-form');
    const input = document.getElementById('task-input');
    const sendBtn = document.getElementById('send-btn');
    const statusDot = document.getElementById('status-dot');
    const statusText = document.getElementById('status-text');

    const STORAGE_KEY = 'sentinel-history';
    const SESSION_KEY = 'sentinel-session-id';
    const PIN_KEY = 'sentinel-pin';
    const POLL_INTERVAL = 2000;

    let isProcessing = false;

    // --- Transport layer (WS → SSE → HTTP polling) ---

    let transport = null;  // 'ws' | 'sse' | 'http'
    let ws = null;
    let wsReconnectAttempts = 0;
    const WS_MAX_RECONNECT = 5;
    const WS_RECONNECT_BASE_MS = 1000;
    let wsTaskResolvers = {};  // task_id → {resolve, statusId}

    // --- PIN management (sessionStorage — cleared on tab close) ---

    function getPin() {
        return sessionStorage.getItem(PIN_KEY);
    }

    function setPin(pin) {
        sessionStorage.setItem(PIN_KEY, pin);
    }

    function clearPin() {
        sessionStorage.removeItem(PIN_KEY);
    }

    // --- Session ID (per-tab, cleared on tab close) ---

    function getSessionId() {
        let sid = sessionStorage.getItem(SESSION_KEY);
        if (!sid) {
            sid = ([1e7]+-1e3+-4e3+-8e3+-1e11).replace(/[018]/g,function(c){return(c^crypto.getRandomValues(new Uint8Array(1))[0]&15>>c/4).toString(16)});
            sessionStorage.setItem(SESSION_KEY, sid);
        }
        return sid;
    }

    function resetSessionId() {
        const sid = ([1e7]+-1e3+-4e3+-8e3+-1e11).replace(/[018]/g,function(c){return(c^crypto.getRandomValues(new Uint8Array(1))[0]&15>>c/4).toString(16)});
        sessionStorage.setItem(SESSION_KEY, sid);
        return sid;
    }

    // --- localStorage history ---

    function loadHistory() {
        try {
            return JSON.parse(localStorage.getItem(STORAGE_KEY)) || [];
        } catch {
            return [];
        }
    }

    function saveHistory(history) {
        try {
            localStorage.setItem(STORAGE_KEY, JSON.stringify(history));
        } catch {
            // Storage full — silently drop
        }
    }

    function appendToHistory(entry) {
        const history = loadHistory();
        history.push(entry);
        // Keep last 100 entries to avoid bloating storage
        if (history.length > 100) history.splice(0, history.length - 100);
        saveHistory(history);
    }

    // --- Message rendering ---

    function scrollToBottom() {
        messagesEl.scrollTop = messagesEl.scrollHeight;
    }

    function addMessage(type, html, id) {
        const div = document.createElement('div');
        div.className = 'message ' + type;
        if (id) div.id = id;
        div.innerHTML = html;
        messagesEl.appendChild(div);
        scrollToBottom();
        return div;
    }

    function addUserMessage(text) {
        addMessage('user', '<div class="label">You</div>' + escapeHtml(text));
        appendToHistory({ role: 'user', text: text });
    }

    function addSystemMessage(text) {
        addMessage('system', '<div class="label">Sentinel</div>' + escapeHtml(text));
        appendToHistory({ role: 'system', text: text });
    }

    function addStatusMessage(text, id) {
        return addMessage('status', '<span class="spinner"></span>' + escapeHtml(text), id);
    }

    function addErrorMessage(text) {
        addMessage('error', '<div class="label">Error</div>' + escapeHtml(text));
        appendToHistory({ role: 'error', text: text });
    }

    function removeElement(id) {
        const el = document.getElementById(id);
        if (el) el.remove();
    }

    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    // --- Render conversation warnings ---

    function renderWarnings(warnings) {
        let html = '<div class="label">Security</div>';
        html += '<div class="conversation-warnings">';
        for (const w of warnings) {
            html += '<div class="conv-warning">\u26a0 ' + escapeHtml(w) + '</div>';
        }
        html += '</div>';
        addMessage('system', html);
    }

    // --- Render step list (shared by renderPlan and restoreHistory) ---

    function buildStepsHtml(steps) {
        if (!steps || steps.length === 0) return '';
        let html = '<ul class="plan-steps">';
        for (const step of steps) {
            html += '<li class="step-header">';
            html += '<span class="step-type">' + escapeHtml(step.type || 'step') + '</span>';
            if (step.expects_code) {
                html += '<span class="step-badge">code</span>';
            }
            html += '<span class="step-desc">' + escapeHtml(step.description || step.id || '') + '</span>';
            html += '<span class="step-chevron">&#9654;</span>';

            // Expandable detail block
            var detail = '';
            if (step.type === 'llm_task' && step.prompt) {
                detail = escapeHtml(step.prompt);
            } else if (step.type === 'tool_call') {
                var parts = [];
                if (step.tool) parts.push('tool: ' + step.tool);
                if (step.args) {
                    try {
                        parts.push('args: ' + JSON.stringify(step.args, null, 2));
                    } catch (e) {
                        parts.push('args: ' + String(step.args));
                    }
                }
                detail = escapeHtml(parts.join('\n'));
            }
            if (detail) {
                html += '<pre class="step-detail">' + detail + '</pre>';
            }
            html += '</li>';
        }
        html += '</ul>';
        return html;
    }

    function bindStepToggles(container) {
        var headers = container.querySelectorAll('.step-header');
        headers.forEach(function (li) {
            li.addEventListener('click', function (e) {
                // Don't toggle if clicking a button inside
                if (e.target.tagName === 'BUTTON') return;
                li.classList.toggle('expanded');
            });
        });
    }

    // --- Render plan with approve/deny ---

    function renderPlan(planSummary, steps, approvalId) {
        let html = '<div class="label">Sentinel</div>';
        html += '<div class="plan-summary">' + escapeHtml(planSummary) + '</div>';
        html += buildStepsHtml(steps);

        html += '<div class="approval-buttons" id="approval-' + approvalId + '">';
        html += '<button class="btn btn-approve" data-approval-id="' + approvalId + '" data-granted="true">Approve</button>';
        html += '<button class="btn btn-deny" data-approval-id="' + approvalId + '" data-granted="false">Deny</button>';
        html += '</div>';

        var msgEl = addMessage('system', html);

        // Bind expand/collapse on step headers
        bindStepToggles(msgEl);

        // Bind click handlers (CSP blocks inline onclick)
        var container = document.getElementById('approval-' + approvalId);
        console.log('[Sentinel] Binding approval buttons, container found:', !!container, 'approvalId:', approvalId);
        if (container) {
            var buttons = container.querySelectorAll('button');
            console.log('[Sentinel] Found', buttons.length, 'buttons to bind');
            buttons.forEach(function (btn) {
                btn.addEventListener('click', function () {
                    console.log('[Sentinel] Button clicked:', btn.getAttribute('data-granted'));
                    handleApproval(btn.getAttribute('data-approval-id'), btn.getAttribute('data-granted') === 'true');
                });
            });
        }
        appendToHistory({ role: 'plan', planSummary: planSummary, steps: steps, approvalId: approvalId });
    }

    // --- Render step results ---

    function renderStepResults(stepResults) {
        if (!stepResults || stepResults.length === 0) return;

        let html = '<div class="label">Sentinel</div>';
        html += '<div class="step-results">';

        for (const step of stepResults) {
            const status = step.status || 'unknown';
            html += '<div class="step-result ' + status + '">';
            html += '<div class="step-result-header">' + escapeHtml(step.step_id || 'Step') + ' — ' + status + '</div>';
            if (step.content) {
                html += '<div class="step-result-content">' + escapeHtml(step.content) + '</div>';
            }
            if (step.error) {
                html += '<div class="step-result-content" style="color:var(--red)">' + escapeHtml(step.error) + '</div>';
            }
            html += '</div>';
        }

        html += '</div>';
        addMessage('system', html);
        appendToHistory({ role: 'results', stepResults: stepResults });
    }

    // --- API calls ---

    async function parseJsonResponse(resp) {
        var contentType = resp.headers.get('content-type') || '';
        if (!contentType.includes('application/json')) {
            var text = await resp.text();
            throw new Error('Server returned non-JSON response (HTTP ' + resp.status + '): ' + text.substring(0, 200));
        }
        return resp.json();
    }

    async function apiPost(path, body) {
        const headers = { 'Content-Type': 'application/json' };
        const pin = getPin();
        if (pin) headers['X-Sentinel-Pin'] = pin;
        const resp = await fetch('/api/' + path, {
            method: 'POST',
            headers: headers,
            body: JSON.stringify(body),
        });
        if (resp.status === 401) {
            clearPin();
            showPinOverlay();
            throw new Error('Authentication required');
        }
        return parseJsonResponse(resp);
    }

    async function apiGet(path) {
        const headers = {};
        const pin = getPin();
        if (pin) headers['X-Sentinel-Pin'] = pin;
        const resp = await fetch('/api/' + path, { headers: headers });
        if (resp.status === 401) {
            clearPin();
            showPinOverlay();
            throw new Error('Authentication required');
        }
        return parseJsonResponse(resp);
    }

    // --- Transport initialization ---

    function getWsUrl() {
        var proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
        return proto + '//' + location.host + '/ws';
    }

    function initWebSocket() {
        return new Promise(function (resolve) {
            try {
                var socket = new WebSocket(getWsUrl());
                var authTimeout = setTimeout(function () {
                    socket.close();
                    resolve(false);
                }, 5000);

                socket.onopen = function () {
                    // Send auth message
                    var pin = getPin();
                    socket.send(JSON.stringify({ type: 'auth', pin: pin || '' }));
                };

                socket.onmessage = function (event) {
                    var msg;
                    try { msg = JSON.parse(event.data); } catch { return; }

                    if (msg.type === 'auth_ok') {
                        clearTimeout(authTimeout);
                        ws = socket;
                        transport = 'ws';
                        wsReconnectAttempts = 0;
                        // Switch to normal message handling
                        socket.onmessage = handleWsMessage;
                        socket.onclose = handleWsClose;
                        console.log('[Sentinel] WebSocket connected');
                        resolve(true);
                    } else if (msg.type === 'auth_error') {
                        clearTimeout(authTimeout);
                        socket.close();
                        resolve(false);
                    }
                };

                socket.onerror = function () {
                    clearTimeout(authTimeout);
                    resolve(false);
                };

                socket.onclose = function () {
                    clearTimeout(authTimeout);
                    resolve(false);
                };
            } catch (e) {
                resolve(false);
            }
        });
    }

    function handleWsMessage(event) {
        var msg;
        try { msg = JSON.parse(event.data); } catch { return; }

        var type = msg.type || '';
        var data = msg.data || {};

        // Extract task_id from event type: "task.<id>.started" → task_id from data
        // Or it may just be a direct type like "error"
        if (type === 'error') {
            addErrorMessage(msg.reason || data.reason || 'Unknown WebSocket error');
            return;
        }

        // Route events to the correct task handler
        // The event_type from bus will be like "task.<task_id>.started"
        var parts = type.split('.');
        if (parts.length >= 3 && parts[0] === 'task') {
            var taskId = parts[1];
            var eventName = parts[2];
            var resolver = wsTaskResolvers[taskId];

            if (eventName === 'started' && resolver) {
                updateStatusMessage(resolver.statusId, 'Planning task...');
            } else if (eventName === 'planned' && resolver) {
                updateStatusMessage(resolver.statusId, 'Executing plan...');
            } else if (eventName === 'approval_requested' && resolver) {
                removeElement(resolver.statusId);
                renderPlan(
                    data.plan_summary || 'Plan ready',
                    data.steps || [],
                    data.approval_id || ''
                );
            } else if (eventName === 'step_completed' && resolver) {
                // Show incremental progress
                var stepStatus = data.status === 'success' ? 'completed' : data.status;
                updateStatusMessage(resolver.statusId, 'Step ' + (data.step_id || '?') + ' ' + stepStatus);
            } else if (eventName === 'completed' && resolver) {
                removeElement(resolver.statusId);
                delete wsTaskResolvers[taskId];
                // The full result comes in data
                if (data.status === 'success') {
                    addSystemMessage(data.plan_summary || 'Task completed.');
                } else if (data.status === 'blocked') {
                    addErrorMessage('Blocked: ' + (data.reason || 'Policy violation'));
                }
            }
        }

        // Approval result
        if (type === 'approval_result') {
            var result = data;
            if (result.status === 'success') {
                addSystemMessage(result.plan_summary || 'Plan executed successfully.');
                renderStepResults(result.step_results);
            } else if (result.status === 'denied') {
                addSystemMessage('Plan denied.');
            } else if (result.status === 'error') {
                addErrorMessage(result.reason || 'Approval error');
            }
        }
    }

    function handleWsClose() {
        console.log('[Sentinel] WebSocket disconnected');
        ws = null;
        // Try to reconnect with backoff
        if (wsReconnectAttempts < WS_MAX_RECONNECT) {
            wsReconnectAttempts++;
            var delay = WS_RECONNECT_BASE_MS * Math.pow(2, wsReconnectAttempts - 1);
            console.log('[Sentinel] Reconnecting in ' + delay + 'ms (attempt ' + wsReconnectAttempts + ')');
            setTimeout(function () {
                initWebSocket().then(function (ok) {
                    if (!ok) {
                        transport = 'http';
                        updateTransportStatus();
                    }
                });
            }, delay);
        } else {
            transport = 'http';
            updateTransportStatus();
        }
    }

    function updateStatusMessage(id, text) {
        var el = document.getElementById(id);
        if (el) el.innerHTML = '<span class="spinner"></span>' + escapeHtml(text);
    }

    function updateTransportStatus() {
        var label = transport === 'ws' ? 'Controller online (WebSocket)' :
                    transport === 'sse' ? 'Controller online (SSE)' :
                    'Controller online (polling)';
        statusText.textContent = label;
    }

    async function initTransport() {
        // Try WebSocket first
        if (getPin()) {
            var ok = await initWebSocket();
            if (ok) {
                updateTransportStatus();
                return;
            }
        }
        // Fall back to HTTP polling (SSE used per-task when available)
        transport = 'http';
        updateTransportStatus();
    }

    // --- Health check ---

    async function checkHealth() {
        try {
            const data = await apiGet('health');
            if (data.status === 'ok') {
                statusDot.className = 'status-dot healthy';
                statusText.textContent = 'Controller online';
                input.disabled = false;
                sendBtn.disabled = false;
                // If PIN auth is enabled and we don't have a PIN, show overlay
                if (data.pin_auth_enabled && !getPin()) {
                    showPinOverlay();
                } else {
                    input.focus();
                }
            } else {
                statusDot.className = 'status-dot error';
                statusText.textContent = 'Controller unhealthy';
            }
        } catch {
            statusDot.className = 'status-dot error';
            statusText.textContent = 'Controller offline';
        }
    }

    // --- Core flow ---

    async function sendTask(text) {
        if (isProcessing) return;
        isProcessing = true;
        setInputEnabled(false);

        addUserMessage(text);
        const statusId = 'status-' + Date.now();
        addStatusMessage('Sending task to planner...', statusId);

        // WebSocket transport: send via WS, events arrive in handleWsMessage
        if (transport === 'ws' && ws && ws.readyState === WebSocket.OPEN) {
            wsTaskResolvers['pending-' + statusId] = { statusId: statusId };
            try {
                ws.send(JSON.stringify({ type: 'task', request: text }));
                // The WS message handler will update the UI as events arrive.
                // We set a timeout to fall back if no events come.
                setTimeout(function () {
                    if (wsTaskResolvers['pending-' + statusId]) {
                        // No task_id received — the handler hasn't picked it up
                        // Events will still route by task_id from the server
                    }
                }, 30000);
            } catch (err) {
                removeElement(statusId);
                delete wsTaskResolvers['pending-' + statusId];
                addErrorMessage('WebSocket send failed: ' + err.message);
                isProcessing = false;
                setInputEnabled(true);
            }
            // WS flow handles completion asynchronously
            // We'll re-enable input when the completed event arrives
            return;
        }

        // HTTP transport (with SSE streaming if available)
        try {
            const data = await apiPost('task', { request: text, source: 'webui', session_id: getSessionId() });
            removeElement(statusId);

            // Display conversation warnings if present
            if (data.conversation && data.conversation.warnings && data.conversation.warnings.length > 0) {
                renderWarnings(data.conversation.warnings);
                appendToHistory({ role: 'warnings', warnings: data.conversation.warnings });
            }

            if (data.status === 'awaiting_approval') {
                // Read approval_id from dedicated field (fallback to reason for backwards compat)
                const approvalId = data.approval_id || data.reason.replace('approval_id:', '');
                addStatusMessage('Waiting for plan...', statusId + '-poll');
                await pollApproval(approvalId, statusId + '-poll');
            } else if (data.status === 'success') {
                addSystemMessage(data.plan_summary || 'Task completed.');
                renderStepResults(data.step_results);
            } else if (data.status === 'blocked') {
                addErrorMessage('Blocked: ' + (data.reason || 'Policy violation'));
            } else if (data.status === 'refused') {
                addErrorMessage('Refused: ' + (data.reason || 'Request refused by planner'));
            } else if (data.status === 'error') {
                addErrorMessage('Error: ' + (data.reason || 'Unknown error'));
            } else {
                addSystemMessage('Response: ' + JSON.stringify(data));
            }
        } catch (err) {
            removeElement(statusId);
            addErrorMessage('Failed to reach controller: ' + err.message);
        }

        isProcessing = false;
        setInputEnabled(true);
    }

    async function pollApproval(approvalId, statusElId) {
        while (true) {
            try {
                const data = await apiGet('approval/' + approvalId);

                if (data.status === 'pending') {
                    removeElement(statusElId);
                    renderPlan(data.plan_summary || 'Plan ready', data.steps || [], approvalId);
                    return; // User will click approve/deny
                } else if (data.status === 'approved' || data.status === 'denied' || data.status === 'expired') {
                    removeElement(statusElId);
                    addSystemMessage('Approval status: ' + data.status + (data.reason ? ' — ' + data.reason : ''));
                    return;
                } else if (data.status === 'not_found') {
                    removeElement(statusElId);
                    addErrorMessage('Approval request not found.');
                    return;
                }
            } catch {
                // Network error — keep polling
            }
            await sleep(POLL_INTERVAL);
        }
    }

    // Approval handler
    window.handleApproval = async function (approvalId, granted) {
        console.log('[Sentinel] handleApproval called:', approvalId, granted);
        const btnContainer = document.getElementById('approval-' + approvalId);
        if (!btnContainer) { console.log('[Sentinel] btnContainer not found for:', approvalId); return; }

        // Disable buttons immediately
        const buttons = btnContainer.querySelectorAll('button');
        buttons.forEach(function (b) { b.disabled = true; });

        const action = granted ? 'Approved' : 'Denied';
        btnContainer.innerHTML = '<span style="color:var(--text-muted)">' + action + '</span>';

        if (granted) {
            const statusId = 'exec-' + Date.now();
            addStatusMessage('Executing approved plan...', statusId);

            try {
                const data = await apiPost('approve/' + approvalId, { granted: true, reason: 'Approved via WebUI' });
                removeElement(statusId);

                if (data.status === 'success') {
                    addSystemMessage(data.plan_summary || 'Plan executed successfully.');
                    renderStepResults(data.step_results);
                } else if (data.status === 'blocked') {
                    addErrorMessage('Execution blocked: ' + (data.reason || 'Policy violation'));
                    renderStepResults(data.step_results);
                } else if (data.status === 'error') {
                    addErrorMessage('Execution error: ' + (data.reason || 'Unknown error'));
                } else {
                    addSystemMessage('Result: ' + JSON.stringify(data));
                }
            } catch (err) {
                removeElement(statusId);
                addErrorMessage('Failed to submit approval: ' + err.message);
            }
        } else {
            try {
                await apiPost('approve/' + approvalId, { granted: false, reason: 'Denied via WebUI' });
                addSystemMessage('Plan denied.');
            } catch (err) {
                addErrorMessage('Failed to submit denial: ' + err.message);
            }
        }

        appendToHistory({ role: 'approval', approvalId: approvalId, granted: granted });
    };

    // --- Restore history on load ---

    function restoreHistory() {
        const history = loadHistory();
        for (const entry of history) {
            if (entry.role === 'user') {
                addMessage('user', '<div class="label">You</div>' + escapeHtml(entry.text));
            } else if (entry.role === 'system') {
                // New format stores text; old format stored pre-rendered html
                if (entry.text != null) {
                    addMessage('system', '<div class="label">Sentinel</div>' + escapeHtml(entry.text));
                } else if (entry.html != null) {
                    // Legacy: re-escape to prevent stored XSS from old entries
                    addMessage('system', '<div class="label">Sentinel</div>' + escapeHtml(entry.html));
                }
            } else if (entry.role === 'error') {
                addMessage('error', '<div class="label">Error</div>' + escapeHtml(entry.text));
            } else if (entry.role === 'warnings') {
                if (entry.warnings) renderWarnings(entry.warnings);
            } else if (entry.role === 'plan') {
                // Render plan without active buttons (already resolved)
                let html = '<div class="label">Sentinel</div>';
                html += '<div class="plan-summary">' + escapeHtml(entry.planSummary || '') + '</div>';
                html += buildStepsHtml(entry.steps);
                var planMsgEl = addMessage('system', html);
                bindStepToggles(planMsgEl);
            } else if (entry.role === 'results') {
                renderStepResultsStatic(entry.stepResults);
            }
        }
    }

    function renderStepResultsStatic(stepResults) {
        if (!stepResults || stepResults.length === 0) return;
        let html = '<div class="label">Sentinel</div><div class="step-results">';
        for (const step of stepResults) {
            const status = step.status || 'unknown';
            html += '<div class="step-result ' + status + '">';
            html += '<div class="step-result-header">' + escapeHtml(step.step_id || 'Step') + ' — ' + status + '</div>';
            if (step.content) html += '<div class="step-result-content">' + escapeHtml(step.content) + '</div>';
            if (step.error) html += '<div class="step-result-content" style="color:var(--red)">' + escapeHtml(step.error) + '</div>';
            html += '</div>';
        }
        html += '</div>';
        addMessage('system', html);
    }

    // --- Helpers ---

    function setInputEnabled(enabled) {
        input.disabled = !enabled;
        sendBtn.disabled = !enabled;
        if (enabled) input.focus();
    }

    function sleep(ms) {
        return new Promise(function (resolve) { setTimeout(resolve, ms); });
    }

    // --- PIN overlay ---

    function showPinOverlay() {
        // Don't create duplicate overlays
        if (document.getElementById('pin-overlay')) return;

        const overlay = document.createElement('div');
        overlay.id = 'pin-overlay';
        overlay.className = 'pin-overlay';

        overlay.innerHTML =
            '<div class="pin-dialog">' +
            '<h2>Sentinel PIN</h2>' +
            '<p>Enter your 4-digit PIN to continue</p>' +
            '<input type="password" id="pin-input" maxlength="4" pattern="[0-9]{4}" inputmode="numeric" autocomplete="off" placeholder="----">' +
            '<button class="btn btn-approve" id="pin-submit">Unlock</button>' +
            '<div id="pin-error" class="pin-error"></div>' +
            '</div>';

        document.body.appendChild(overlay);

        var pinInput = document.getElementById('pin-input');
        var pinSubmit = document.getElementById('pin-submit');

        function submitPin() {
            var val = pinInput.value.trim();
            if (val.length !== 4 || !/^\d{4}$/.test(val)) {
                document.getElementById('pin-error').textContent = 'PIN must be exactly 4 digits';
                return;
            }
            setPin(val);
            overlay.remove();
            // Re-run health check to verify PIN works
            checkHealth();
        }

        pinSubmit.addEventListener('click', submitPin);
        pinInput.addEventListener('keydown', function (e) {
            if (e.key === 'Enter') submitPin();
        });

        pinInput.focus();
    }

    // --- Init ---

    form.addEventListener('submit', function (e) {
        e.preventDefault();
        const text = input.value.trim();
        if (!text) return;
        input.value = '';
        sendTask(text);
    });

    // Clear history button (Shift+click on header title)
    document.querySelector('header h1').addEventListener('click', function (e) {
        if (e.shiftKey) {
            if (confirm('Clear conversation history?')) {
                localStorage.removeItem(STORAGE_KEY);
                messagesEl.innerHTML = '';
                resetSessionId();
            }
        }
    });

    restoreHistory();
    checkHealth();
    // Initialize transport after health check confirms server is up
    setTimeout(initTransport, 1000);
    // Re-check health every 30s
    setInterval(checkHealth, 30000);
})();
