(function () {
    'use strict';

    const messagesEl = document.getElementById('messages');
    const form = document.getElementById('input-form');
    const input = document.getElementById('task-input');
    const sendBtn = document.getElementById('send-btn');
    const statusDot = document.getElementById('status-dot');
    const statusText = document.getElementById('status-text');

    const STORAGE_KEY = 'sentinel-history';
    const POLL_INTERVAL = 2000;

    let isProcessing = false;

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

    function addSystemMessage(html) {
        addMessage('system', '<div class="label">Sentinel</div>' + html);
        appendToHistory({ role: 'system', html: html });
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

    // --- Render plan with approve/deny ---

    function renderPlan(planSummary, steps, approvalId) {
        let html = '<div class="label">Sentinel</div>';
        html += '<div class="plan-summary">' + escapeHtml(planSummary) + '</div>';

        if (steps && steps.length > 0) {
            html += '<ul class="plan-steps">';
            for (const step of steps) {
                html += '<li>';
                html += '<span class="step-type">' + escapeHtml(step.type || 'step') + '</span>';
                html += escapeHtml(step.description || step.id || '');
                html += '</li>';
            }
            html += '</ul>';
        }

        html += '<div class="approval-buttons" id="approval-' + approvalId + '">';
        html += '<button class="btn btn-approve" onclick="handleApproval(\'' + approvalId + '\', true)">Approve</button>';
        html += '<button class="btn btn-deny" onclick="handleApproval(\'' + approvalId + '\', false)">Deny</button>';
        html += '</div>';

        addMessage('system', html);
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

    async function apiPost(path, body) {
        const resp = await fetch('/api/' + path, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        return resp.json();
    }

    async function apiGet(path) {
        const resp = await fetch('/api/' + path);
        return resp.json();
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
                input.focus();
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

        try {
            const data = await apiPost('task', { request: text, source: 'webui' });
            removeElement(statusId);

            if (data.status === 'awaiting_approval') {
                // Extract approval ID from reason field
                const approvalId = data.reason.replace('approval_id:', '');
                addStatusMessage('Waiting for plan...', statusId + '-poll');
                await pollApproval(approvalId, statusId + '-poll');
            } else if (data.status === 'success') {
                addSystemMessage(escapeHtml(data.plan_summary || 'Task completed.'));
                renderStepResults(data.step_results);
            } else if (data.status === 'blocked') {
                addErrorMessage('Blocked: ' + (data.reason || 'Policy violation'));
            } else if (data.status === 'error') {
                addErrorMessage('Error: ' + (data.reason || 'Unknown error'));
            } else {
                addSystemMessage('Response: ' + escapeHtml(JSON.stringify(data)));
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
                    addSystemMessage('Approval status: ' + data.status + (data.reason ? ' — ' + escapeHtml(data.reason) : ''));
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

    // Exposed globally for onclick handlers
    window.handleApproval = async function (approvalId, granted) {
        const btnContainer = document.getElementById('approval-' + approvalId);
        if (!btnContainer) return;

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
                    addSystemMessage(escapeHtml(data.plan_summary || 'Plan executed successfully.'));
                    renderStepResults(data.step_results);
                } else if (data.status === 'blocked') {
                    addErrorMessage('Execution blocked: ' + (data.reason || 'Policy violation'));
                    renderStepResults(data.step_results);
                } else if (data.status === 'error') {
                    addErrorMessage('Execution error: ' + (data.reason || 'Unknown error'));
                } else {
                    addSystemMessage('Result: ' + escapeHtml(JSON.stringify(data)));
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
                addMessage('system', entry.html);
            } else if (entry.role === 'error') {
                addMessage('error', '<div class="label">Error</div>' + escapeHtml(entry.text));
            } else if (entry.role === 'plan') {
                // Render plan without active buttons (already resolved)
                let html = '<div class="label">Sentinel</div>';
                html += '<div class="plan-summary">' + escapeHtml(entry.planSummary || '') + '</div>';
                if (entry.steps && entry.steps.length > 0) {
                    html += '<ul class="plan-steps">';
                    for (const step of entry.steps) {
                        html += '<li>';
                        html += '<span class="step-type">' + escapeHtml(step.type || 'step') + '</span>';
                        html += escapeHtml(step.description || step.id || '');
                        html += '</li>';
                    }
                    html += '</ul>';
                }
                addMessage('system', html);
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
            }
        }
    });

    restoreHistory();
    checkHealth();
    // Re-check health every 30s
    setInterval(checkHealth, 30000);
})();
