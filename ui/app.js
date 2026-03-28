(function () {
    'use strict';

    // ── DOM references ────────────────────────────────────────────
    var messagesEl = document.getElementById('messages');
    var form = document.getElementById('input-form');
    var input = document.getElementById('task-input');
    var sendBtn = document.getElementById('send-btn');
    var statusDot = document.getElementById('status-dot');
    var statusText = document.getElementById('status-text');
    var inputBar = document.getElementById('input-bar');
    var chatWelcome = document.getElementById('chat-welcome');

    var STORAGE_KEY = 'sentinel-history';
    var SESSION_KEY = 'sentinel-session-id';
    var TOKEN_KEY = 'sentinel-token';
    var POLL_INTERVAL = 2000;

    var isProcessing = false;

    // ── Transport layer (WS → SSE → HTTP polling) ─────────────────

    var transport = null;  // 'ws' | 'sse' | 'http'
    var ws = null;
    var wsReconnectAttempts = 0;
    var WS_MAX_RECONNECT = 5;
    var WS_RECONNECT_BASE_MS = 1000;
    var wsTaskResolvers = {};

    // ── JWT token management (localStorage — persists across tabs) ──

    function getToken() { return localStorage.getItem(TOKEN_KEY); }
    function setToken(token) { localStorage.setItem(TOKEN_KEY, token); }
    function clearToken() {
        localStorage.removeItem(TOKEN_KEY);
        localStorage.removeItem('sentinel-user-id');
        localStorage.removeItem('sentinel-role');
        localStorage.removeItem('sentinel-display-name');
    }

    // ── Auth helpers ────────────────────────────────────────────
    // Builds Authorization header from stored JWT. Redirects to login if missing.
    function getAuthHeaders() {
        var token = getToken();
        if (!token) {
            window.location.href = '/login.html';
            return {};
        }
        return { 'Authorization': 'Bearer ' + token };
    }

    // Handles sliding token refresh and 401 redirects on every API response.
    function handleAuthResponse(resp) {
        var newToken = resp.headers.get('X-Refreshed-Token');
        if (newToken) setToken(newToken);
        if (resp.status === 401) {
            clearToken();
            window.location.href = '/login.html';
        }
        return resp;
    }

    // ── Session ID (per-tab) ──────────────────────────────────────

    function makeUUID() {
        return ([1e7]+-1e3+-4e3+-8e3+-1e11).replace(/[018]/g, function(c) {
            return (c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> c / 4).toString(16);
        });
    }

    function getSessionId() {
        var sid = sessionStorage.getItem(SESSION_KEY);
        if (!sid) {
            sid = makeUUID();
            sessionStorage.setItem(SESSION_KEY, sid);
        }
        return sid;
    }

    function resetSessionId() {
        var sid = makeUUID();
        sessionStorage.setItem(SESSION_KEY, sid);
        return sid;
    }

    // ── localStorage history ──────────────────────────────────────
    // Q-002: History is stored as plaintext JSON. localStorage is same-origin
    // protected; encrypting it client-side wouldn't add real security since the
    // key would also be accessible to the same origin. PIN lives in
    // sessionStorage (cleared on tab close).

    function loadHistory() {
        try { return JSON.parse(localStorage.getItem(STORAGE_KEY)) || []; }
        catch { return []; }
    }

    function saveHistory(history) {
        try { localStorage.setItem(STORAGE_KEY, JSON.stringify(history)); }
        catch { /* Storage full */ }
    }

    function appendToHistory(entry) {
        var history = loadHistory();
        history.push(entry);
        if (history.length > 100) history.splice(0, history.length - 100);
        saveHistory(history);
    }

    // ── Toast notification system ─────────────────────────────────

    var toastContainer = document.getElementById('toast-container');
    var toastCount = 0;

    function showToast(message, type) {
        type = type || 'info';
        toastCount++;
        // Cap at 3 visible toasts
        var toasts = toastContainer.querySelectorAll('.toast:not(.removing)');
        if (toasts.length >= 3) {
            dismissToast(toasts[0]);
        }

        var toast = document.createElement('div');
        toast.className = 'toast ' + type;
        toast.innerHTML =
            '<span class="toast-message">' + escapeHtml(message) + '</span>' +
            '<button class="toast-close" aria-label="Dismiss">&times;</button>';

        toast.querySelector('.toast-close').addEventListener('click', function () {
            dismissToast(toast);
        });

        toastContainer.appendChild(toast);

        // Auto-dismiss after 4 seconds
        setTimeout(function () { dismissToast(toast); }, 4000);
    }

    function dismissToast(toast) {
        if (!toast || toast.classList.contains('removing')) return;
        toast.classList.add('removing');
        setTimeout(function () { toast.remove(); }, 300);
    }

    // ── View routing ──────────────────────────────────────────────

    var currentView = 'chat';
    var viewCallbacks = {
        dashboard: loadDashboard,
        chat: function () {},
        memory: loadMemory,
        routines: loadRoutines,
        logs: initLogView,
    };

    function showView(viewName) {
        if (!document.getElementById('view-' + viewName)) return;

        // Update nav items
        var navItems = document.querySelectorAll('.nav-item');
        navItems.forEach(function (item) {
            if (item.getAttribute('data-view') === viewName) {
                item.classList.add('active');
                item.setAttribute('aria-current', 'page');
            } else {
                item.classList.remove('active');
                item.removeAttribute('aria-current');
            }
        });

        // Switch views
        document.querySelectorAll('.view').forEach(function (v) {
            v.classList.remove('active');
        });
        document.getElementById('view-' + viewName).classList.add('active');

        // Show/hide input bar (only visible on chat)
        inputBar.style.display = (viewName === 'chat') ? '' : 'none';

        currentView = viewName;

        // Stop metrics polling when leaving dashboard
        if (viewName !== 'dashboard') stopMetricsPolling();

        // Run view-specific init
        if (viewCallbacks[viewName]) viewCallbacks[viewName]();

        // Focus management
        if (viewName === 'chat') {
            input.focus();
        }
    }

    // Bind nav clicks
    document.querySelectorAll('.nav-item').forEach(function (item) {
        item.addEventListener('click', function () {
            showView(item.getAttribute('data-view'));
        });
    });

    // Keyboard shortcuts: Ctrl/Cmd + 1-5
    document.addEventListener('keydown', function (e) {
        if (!(e.ctrlKey || e.metaKey)) return;
        var views = ['dashboard', 'chat', 'memory', 'routines', 'logs'];
        var num = parseInt(e.key);
        if (num >= 1 && num <= 5) {
            e.preventDefault();
            showView(views[num - 1]);
        }
        if (e.key === 'Escape') {
            e.preventDefault();
            showView('chat');
        }
    });

    // ── Message rendering ─────────────────────────────────────────

    function scrollToBottom() {
        messagesEl.scrollTop = messagesEl.scrollHeight;
    }

    function dismissWelcome() {
        if (chatWelcome) chatWelcome.style.display = 'none';
    }

    function addMessage(type, html, id) {
        var div = document.createElement('div');
        div.className = 'message ' + type;
        if (id) div.id = id;
        div.innerHTML = html;
        messagesEl.appendChild(div);
        scrollToBottom();
        return div;
    }

    function addUserMessage(text) {
        dismissWelcome();
        addMessage('user',
            '<div class="label">You <span class="msg-time">' + formatTimestamp() + '</span></div>' +
            escapeHtml(text));
        appendToHistory({ role: 'user', text: text });
    }

    function addSystemMessage(text) {
        addMessage('system',
            '<div class="label">Sentinel <span class="msg-time">' + formatTimestamp() + '</span></div>' +
            '<div class="md-content">' + renderMarkdown(text) + '</div>');
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
        var el = document.getElementById(id);
        if (el) el.remove();
    }

    function escapeHtml(str) {
        var div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    function updateStatusMessage(id, text) {
        var el = document.getElementById(id);
        if (el) el.innerHTML = '<span class="spinner"></span>' + escapeHtml(text);
    }

    // ── Markdown rendering (XSS-safe) ──────────────────────────

    // Tags allowed in rendered markdown — everything else is stripped
    var SAFE_TAGS = /^(p|br|strong|em|b|i|code|pre|ul|ol|li|h[1-6]|blockquote|a|hr|table|thead|tbody|tr|th|td|del|sup|sub|span|div)$/i;
    // Attributes that could execute code
    var EVENT_HANDLER_RE = /\s+on\w+\s*=/gi;
    // Dangerous URL schemes
    var DANGEROUS_HREF_RE = /^\s*(javascript|data|vbscript)\s*:/i;

    function renderMarkdown(text) {
        // Render markdown to HTML using marked.js
        if (typeof marked === 'undefined' || !marked.parse) return escapeHtml(text);

        var html;
        try {
            html = marked.parse(text, { breaks: true, gfm: true });
        } catch (e) {
            return escapeHtml(text);
        }

        // Defence-in-depth: strip dangerous tags and attributes via DOM parsing
        var tmp = document.createElement('div');
        tmp.innerHTML = html;

        // Remove dangerous elements
        var dangerous = tmp.querySelectorAll('script,style,iframe,object,embed,svg,math,link,meta,base,form,input,textarea,select,button');
        for (var i = dangerous.length - 1; i >= 0; i--) {
            dangerous[i].remove();
        }

        // Walk all remaining elements and sanitize attributes
        var all = tmp.querySelectorAll('*');
        for (var j = 0; j < all.length; j++) {
            var el = all[j];
            var tag = el.tagName.toLowerCase();

            // Remove elements with unsafe tags
            if (!SAFE_TAGS.test(tag)) {
                // Replace with text content to preserve readable text
                el.replaceWith(document.createTextNode(el.textContent));
                continue;
            }

            // Remove all event handler attributes
            var attrs = el.attributes;
            for (var k = attrs.length - 1; k >= 0; k--) {
                var name = attrs[k].name.toLowerCase();
                if (name.startsWith('on') || name === 'style') {
                    el.removeAttribute(attrs[k].name);
                } else if (name === 'href' && DANGEROUS_HREF_RE.test(attrs[k].value)) {
                    el.setAttribute('href', '#');
                } else if (name === 'src' && DANGEROUS_HREF_RE.test(attrs[k].value)) {
                    el.removeAttribute('src');
                }
            }

            // Force links to open safely
            if (tag === 'a') {
                el.setAttribute('target', '_blank');
                el.setAttribute('rel', 'noopener noreferrer');
            }
        }

        return tmp.innerHTML;
    }

    function formatTimestamp() {
        var d = new Date();
        return d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
    }

    // ── Conversation warnings ─────────────────────────────────────

    function renderWarnings(warnings) {
        var html = '<div class="label">Security</div>';
        html += '<div class="conversation-warnings">';
        for (var i = 0; i < warnings.length; i++) {
            html += '<div class="conv-warning">\u26a0 ' + escapeHtml(warnings[i]) + '</div>';
        }
        html += '</div>';
        addMessage('system', html);
    }

    // ── Plan + step rendering ─────────────────────────────────────

    function buildStepsHtml(steps) {
        if (!steps || steps.length === 0) return '';
        var html = '<ul class="plan-steps">';
        for (var i = 0; i < steps.length; i++) {
            var step = steps[i];
            html += '<li class="step-header">';
            html += '<span class="step-type">' + escapeHtml(step.type || 'step') + '</span>';
            if (step.expects_code) html += '<span class="step-badge">code</span>';
            html += '<span class="step-desc">' + escapeHtml(step.description || step.id || '') + '</span>';
            html += '<span class="step-chevron">&#9654;</span>';
            var detail = '';
            if (step.type === 'llm_task' && step.prompt) {
                detail = escapeHtml(step.prompt);
            } else if (step.type === 'tool_call') {
                var parts = [];
                if (step.tool) parts.push('tool: ' + step.tool);
                if (step.args) {
                    try { parts.push('args: ' + JSON.stringify(step.args, null, 2)); }
                    catch (e) { parts.push('args: ' + String(step.args)); }
                }
                detail = escapeHtml(parts.join('\n'));
            }
            if (detail) html += '<pre class="step-detail">' + detail + '</pre>';
            html += '</li>';
        }
        html += '</ul>';
        return html;
    }

    function bindStepToggles(container) {
        container.querySelectorAll('.step-header').forEach(function (li) {
            li.addEventListener('click', function (e) {
                if (e.target.tagName === 'BUTTON') return;
                li.classList.toggle('expanded');
            });
        });
    }

    function renderPlan(planSummary, steps, approvalId) {
        // Q-001: Escape approvalId before injecting into HTML attributes to
        // prevent DOM injection if the server ever sends a non-UUID value.
        var safeId = escapeHtml(approvalId);
        var html = '<div class="label">Sentinel</div>';
        html += '<div class="plan-summary">' + escapeHtml(planSummary) + '</div>';
        html += buildStepsHtml(steps);
        html += '<div class="approval-buttons" id="approval-' + safeId + '">';
        html += '<button class="btn btn-approve" data-approval-id="' + safeId + '" data-granted="true">Approve</button>';
        html += '<button class="btn btn-deny" data-approval-id="' + safeId + '" data-granted="false">Deny</button>';
        html += '</div>';

        var msgEl = addMessage('system', html);
        bindStepToggles(msgEl);

        var container = document.getElementById('approval-' + safeId);
        if (container) {
            container.querySelectorAll('button').forEach(function (btn) {
                btn.addEventListener('click', function () {
                    handleApproval(btn.getAttribute('data-approval-id'), btn.getAttribute('data-granted') === 'true');
                });
            });
        }
        appendToHistory({ role: 'plan', planSummary: planSummary, steps: steps, approvalId: approvalId });
    }

    function renderConfirmation(preview, confirmationId, taskId, resolver) {
        // Confirmation gate UI — same pattern as plan approval.
        // Calls POST /api/confirm/{id} instead of sending "go" via WebSocket.
        var safeId = escapeHtml(confirmationId);
        var html = '<div class="label">Sentinel <span class="msg-time">' + formatTimestamp() + '</span></div>';
        html += '<div class="plan-summary">' + escapeHtml(preview) + '</div>';
        html += '<div class="approval-buttons" id="confirm-' + safeId + '">';
        html += '<button class="btn btn-approve" data-action="confirm">Confirm</button>';
        html += '<button class="btn btn-deny" data-action="cancel">Cancel</button>';
        html += '</div>';

        addMessage('system', html);

        var container = document.getElementById('confirm-' + safeId);
        if (container) {
            container.querySelectorAll('button').forEach(function (btn) {
                btn.addEventListener('click', function () {
                    container.querySelectorAll('button').forEach(function (b) { b.disabled = true; });
                    var granted = btn.getAttribute('data-action') === 'confirm';
                    container.innerHTML = '<span style="color:var(--text-muted)">' + (granted ? 'Confirmed' : 'Cancelled') + '</span>';

                    if (granted) {
                        var statusId = 'exec-' + Date.now();
                        addStatusMessage('Executing confirmed action...', statusId);
                        apiPost('confirm/' + confirmationId, { granted: true, reason: 'Confirmed via WebUI' }).then(function (data) {
                            removeElement(statusId);
                            if (data.status === 'success') {
                                addSystemMessage(data.response || 'Action completed.');
                                showToast('Action completed', 'success');
                            } else if (data.status === 'blocked') {
                                addErrorMessage('Blocked: ' + (data.reason || 'Policy violation'));
                            } else if (data.status === 'error') {
                                addErrorMessage('Error: ' + (data.reason || 'Action failed'));
                            } else {
                                addSystemMessage(data.response || 'Action completed.');
                            }
                            isProcessing = false;
                            setInputEnabled(true);
                        }).catch(function (err) {
                            removeElement(statusId);
                            addErrorMessage('Failed to confirm: ' + err.message);
                            isProcessing = false;
                            setInputEnabled(true);
                        });
                    } else {
                        apiPost('confirm/' + confirmationId, { granted: false, reason: 'Cancelled via WebUI' }).then(function () {
                            addSystemMessage('Action cancelled.');
                            isProcessing = false;
                            setInputEnabled(true);
                        }).catch(function (err) {
                            addErrorMessage('Failed to cancel: ' + err.message);
                            isProcessing = false;
                            setInputEnabled(true);
                        });
                    }
                });
            });
        }
    }

    function renderStepResults(stepResults) {
        if (!stepResults || stepResults.length === 0) return;
        var html = '<div class="label">Sentinel</div><div class="step-results">';
        for (var i = 0; i < stepResults.length; i++) {
            var step = stepResults[i];
            var status = step.status || 'unknown';
            html += '<div class="step-result ' + escapeHtml(status) + '">';
            html += '<div class="step-result-header">' + escapeHtml(step.step_id || 'Step') + ' — ' + escapeHtml(status) + '</div>';
            if (step.content) html += '<div class="step-result-content">' + escapeHtml(step.content) + '</div>';
            if (step.error) html += '<div class="step-result-content" style="color:var(--red)">' + escapeHtml(step.error) + '</div>';
            html += '</div>';
        }
        html += '</div>';
        addMessage('system', html);
        appendToHistory({ role: 'results', stepResults: stepResults });
    }

    function renderStepResultsStatic(stepResults) {
        if (!stepResults || stepResults.length === 0) return;
        var html = '<div class="label">Sentinel</div><div class="step-results">';
        for (var i = 0; i < stepResults.length; i++) {
            var step = stepResults[i];
            var status = step.status || 'unknown';
            html += '<div class="step-result ' + escapeHtml(status) + '">';
            html += '<div class="step-result-header">' + escapeHtml(step.step_id || 'Step') + ' — ' + escapeHtml(status) + '</div>';
            if (step.content) html += '<div class="step-result-content">' + escapeHtml(step.content) + '</div>';
            if (step.error) html += '<div class="step-result-content" style="color:var(--red)">' + escapeHtml(step.error) + '</div>';
            html += '</div>';
        }
        html += '</div>';
        addMessage('system', html);
    }

    // ── API helpers ───────────────────────────────────────────────

    function parseJsonResponse(resp) {
        var contentType = resp.headers.get('content-type') || '';
        if (!contentType.includes('application/json')) {
            return resp.text().then(function (text) {
                throw new Error('Non-JSON response (HTTP ' + resp.status + '): ' + text.substring(0, 200));
            });
        }
        return resp.json();
    }

    function apiPost(path, body) {
        var headers = Object.assign({ 'Content-Type': 'application/json' }, getAuthHeaders());
        return fetch('/api/' + path, {
            method: 'POST',
            headers: headers,
            body: JSON.stringify(body),
        }).then(handleAuthResponse).then(function (resp) {
            if (resp.status === 401) throw new Error('Authentication required');
            return parseJsonResponse(resp);
        });
    }

    function apiGet(path) {
        var headers = getAuthHeaders();
        return fetch('/api/' + path, { headers: headers }).then(handleAuthResponse).then(function (resp) {
            if (resp.status === 401) throw new Error('Authentication required');
            return parseJsonResponse(resp);
        });
    }

    function apiPatch(path, body) {
        var headers = Object.assign({ 'Content-Type': 'application/json' }, getAuthHeaders());
        return fetch('/api/' + path, {
            method: 'PATCH',
            headers: headers,
            body: JSON.stringify(body),
        }).then(handleAuthResponse).then(function (resp) {
            if (resp.status === 401) throw new Error('Auth required');
            return parseJsonResponse(resp);
        });
    }

    function apiDelete(path) {
        var headers = getAuthHeaders();
        return fetch('/api/' + path, { method: 'DELETE', headers: headers }).then(handleAuthResponse).then(function (resp) {
            if (resp.status === 401) throw new Error('Auth required');
            return parseJsonResponse(resp);
        });
    }

    // ── WebSocket transport ───────────────────────────────────────

    function getWsUrl() {
        var proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
        return proto + '//' + location.host + '/ws';
    }

    function initWebSocket() {
        return new Promise(function (resolve) {
            try {
                var socket = new WebSocket(getWsUrl());
                var authTimeout = setTimeout(function () { socket.close(); resolve(false); }, 5000);

                socket.onopen = function () {
                    // Send JWT as first message instead of query param (avoids token in server logs/URL)
                    socket.send(JSON.stringify({ type: 'auth', token: getToken() }));
                };

                socket.onmessage = function (event) {
                    var msg;
                    try { msg = JSON.parse(event.data); } catch { return; }
                    if (msg.type === 'auth_ok') {
                        clearTimeout(authTimeout);
                        ws = socket;
                        transport = 'ws';
                        wsReconnectAttempts = 0;
                        socket.onmessage = handleWsMessage;
                        socket.onclose = handleWsClose;
                        resolve(true);
                    } else if (msg.type === 'auth_error') {
                        clearTimeout(authTimeout);
                        socket.close();
                        resolve(false);
                    }
                };

                socket.onerror = function () { clearTimeout(authTimeout); resolve(false); };
                socket.onclose = function () { clearTimeout(authTimeout); resolve(false); };
            } catch (e) { resolve(false); }
        });
    }

    function handleWsMessage(event) {
        var msg;
        try { msg = JSON.parse(event.data); } catch { return; }
        var type = msg.type || '';
        var data = msg.data || {};

        if (type === 'error') {
            addErrorMessage(msg.reason || data.reason || 'Unknown WebSocket error');
            // Reset processing state if a task was in flight
            if (isProcessing) {
                isProcessing = false;
                setInputEnabled(true);
            }
            return;
        }

        // Route task events: "task.<id>.<event>"
        var parts = type.split('.');
        if (parts.length >= 3 && parts[0] === 'task') {
            var taskId = parts[1];
            var eventName = parts[2];
            var resolver = wsTaskResolvers[taskId];

            // Adopt pending resolver — map server-assigned task_id to the UI's pending key
            if (!resolver) {
                var pendingKeys = Object.keys(wsTaskResolvers).filter(function (k) { return k.indexOf('pending-') === 0; });
                if (pendingKeys.length > 0) {
                    resolver = wsTaskResolvers[pendingKeys[0]];
                    wsTaskResolvers[taskId] = resolver;
                    delete wsTaskResolvers[pendingKeys[0]];
                }
            }

            if (eventName === 'started' && resolver) {
                updateStatusMessage(resolver.statusId, data.response || 'Planning task...');
            } else if (eventName === 'planned' && resolver) {
                updateStatusMessage(resolver.statusId, 'Executing plan...');
            } else if (eventName === 'approval_requested' && resolver) {
                removeElement(resolver.statusId);
                renderPlan(data.plan_summary || 'Plan ready', data.steps || [], data.approval_id || '');
            } else if (eventName === 'awaiting_confirmation' && resolver) {
                removeElement(resolver.statusId);
                renderConfirmation(data.preview || 'Confirm action?', data.confirmation_id || '', taskId, resolver);
            } else if (eventName === 'step_completed' && resolver) {
                var stepStatus = data.status === 'success' ? 'completed' : data.status;
                updateStatusMessage(resolver.statusId, 'Step ' + (data.step_id || '?') + ' ' + stepStatus);
                // Render step content incrementally as it arrives
                var stepContent = data.content_preview || data.content || '';
                if (stepContent || data.error) {
                    if (!resolver.incrementalStepsId) {
                        resolver.incrementalStepsId = 'incremental-steps-' + taskId;
                        var containerHtml = '<div class="label">Sentinel <span class="msg-time">' + formatTimestamp() + '</span></div><div class="step-results" id="' + resolver.incrementalStepsId + '-inner"></div>';
                        addMessage('system', containerHtml, resolver.incrementalStepsId);
                    }
                    var inner = document.getElementById(resolver.incrementalStepsId + '-inner');
                    if (inner) {
                        var stepHtml = '<div class="step-result ' + escapeHtml(stepStatus) + '">';
                        stepHtml += '<div class="step-result-header">' + escapeHtml(data.step_id || 'Step') + ' — ' + escapeHtml(stepStatus) + '</div>';
                        if (stepContent) stepHtml += '<div class="step-result-content">' + escapeHtml(stepContent) + '</div>';
                        if (data.error) stepHtml += '<div class="step-result-content" style="color:var(--red)">' + escapeHtml(data.error) + '</div>';
                        stepHtml += '</div>';
                        inner.insertAdjacentHTML('beforeend', stepHtml);
                        scrollToBottom();
                    }
                    resolver.hasIncrementalSteps = true;
                }
            } else if (eventName === 'blocked' && resolver) {
                // Fast-path scan block — emitted as "blocked" event (not "completed")
                removeElement(resolver.statusId);
                delete wsTaskResolvers[taskId];
                addErrorMessage('Blocked: ' + (data.reason || 'Policy violation'));
                isProcessing = false;
                setInputEnabled(true);
            } else if (eventName === 'completed' && resolver) {
                removeElement(resolver.statusId);
                delete wsTaskResolvers[taskId];
                if (data.status === 'success') {
                    addSystemMessage(data.response || data.plan_summary || 'Task completed.');
                    if (data.step_results) {
                        // Replace truncated incremental steps with full content
                        if (resolver.hasIncrementalSteps && resolver.incrementalStepsId) {
                            removeElement(resolver.incrementalStepsId);
                        }
                        renderStepResults(data.step_results);
                    }
                } else if (data.status === 'blocked') {
                    addErrorMessage('Blocked: ' + (data.reason || 'Policy violation'));
                } else if (data.status === 'error') {
                    addErrorMessage('Error: ' + (data.reason || 'Task failed'));
                } else {
                    addSystemMessage(data.response || data.plan_summary || 'Task completed.');
                }
                isProcessing = false;
                setInputEnabled(true);
            }
        }

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

        // Routine events (forwarded to routines view)
        if (type === 'routine_event') {
            if (currentView === 'routines') loadRoutines();
        }
    }

    function handleWsClose() {
        ws = null;
        // Clean up any in-flight task resolvers
        var keys = Object.keys(wsTaskResolvers);
        for (var i = 0; i < keys.length; i++) {
            var r = wsTaskResolvers[keys[i]];
            if (r && r.statusId) removeElement(r.statusId);
            delete wsTaskResolvers[keys[i]];
        }
        if (isProcessing) {
            isProcessing = false;
            setInputEnabled(true);
        }
        if (wsReconnectAttempts < WS_MAX_RECONNECT) {
            wsReconnectAttempts++;
            var delay = WS_RECONNECT_BASE_MS * Math.pow(2, wsReconnectAttempts - 1);
            setTimeout(function () {
                initWebSocket().then(function (ok) {
                    if (!ok) { transport = 'http'; updateTransportStatus(); }
                });
            }, delay);
        } else {
            transport = 'http';
            updateTransportStatus();
        }
    }

    function updateTransportStatus() {
        var label = transport === 'ws' ? 'Online (WS)' :
                    transport === 'sse' ? 'Online (SSE)' :
                    'Online (polling)';
        statusText.textContent = label;
    }

    function initTransport() {
        if (getToken()) {
            initWebSocket().then(function (ok) {
                if (ok) { updateTransportStatus(); return; }
                transport = 'http';
                updateTransportStatus();
            });
        } else {
            transport = 'http';
            updateTransportStatus();
        }
    }

    // ── Health check ──────────────────────────────────────────────

    var lastHealthData = null;

    function checkHealth() {
        // Health endpoint is exempt from auth on server — don't use apiGet
        // (which calls getAuthHeaders and redirects to login if no token).
        var headers = {};
        var token = getToken();
        if (token) headers['Authorization'] = 'Bearer ' + token;
        fetch('/api/health', { headers: headers }).then(function (resp) { return resp.json(); }).then(function (data) {
            lastHealthData = data;
            if (data.status === 'ok') {
                statusDot.className = 'status-dot healthy';
                if (!transport) statusText.textContent = 'Online';
                input.disabled = false;
                sendBtn.disabled = false;
                if (!getToken()) {
                    window.location.href = '/login.html';
                } else if (currentView === 'chat') {
                    input.focus();
                }
            } else {
                statusDot.className = 'status-dot error';
                statusText.textContent = 'Unhealthy';
            }
            // Update dashboard if visible
            if (currentView === 'dashboard') updateDashboardHealth(data);
        }).catch(function () {
            statusDot.className = 'status-dot error';
            statusText.textContent = 'Offline';
            lastHealthData = null;
        });
    }

    // ── Dashboard ─────────────────────────────────────────────────

    var metricsWindow = '24h';
    var metricsInterval = null;

    function loadDashboard() {
        if (lastHealthData) updateDashboardHealth(lastHealthData);
        checkHealth();
        loadSessionInfo();
        loadRecentActivity();
        loadMetrics();
        startMetricsPolling();
    }

    function updateDashboardHealth(data) {
        function setVal(id, val, cls) {
            var el = document.getElementById(id);
            if (el) {
                el.textContent = val;
                el.className = 'health-card-value ' + cls;
            }
        }

        setVal('health-status', data.status === 'ok' ? 'Healthy' : 'Unhealthy',
               data.status === 'ok' ? 'ok' : 'fail');
        setVal('health-policy', data.policy_loaded ? 'Loaded' : 'Missing',
               data.policy_loaded ? 'ok' : 'fail');
        setVal('health-pg', data.prompt_guard_loaded ? 'Loaded' : 'Disabled',
               data.prompt_guard_loaded ? 'ok' : 'off');
        setVal('health-cs', data.semgrep_loaded ? 'Loaded' : 'Disabled',
               data.semgrep_loaded ? 'ok' : 'off');
        setVal('health-planner', data.planner_available ? 'Available' : 'Unavailable',
               data.planner_available ? 'ok' : 'fail');
        setVal('health-conv', data.conversation_tracking ? 'Enabled' : 'Disabled',
               data.conversation_tracking ? 'ok' : 'off');

        // Sidecar and Signal can be running/stopped/disabled
        function statusVal(s) {
            if (s === 'running') return ['Running', 'ok'];
            if (s === 'stopped') return ['Stopped', 'warn'];
            return ['Disabled', 'off'];
        }
        var sc = statusVal(data.sidecar);
        setVal('health-sidecar', sc[0], sc[1]);
        var sig = statusVal(data.signal);
        setVal('health-signal', sig[0], sig[1]);
        var tg = statusVal(data.telegram);
        setVal('health-telegram', tg[0], tg[1]);

        // Email and Calendar are config-level (enabled/disabled strings)
        function configVal(s) {
            if (s && s.indexOf('enabled') === 0) return [s.charAt(0).toUpperCase() + s.slice(1), 'ok'];
            return ['Disabled', 'off'];
        }
        var em = configVal(data.email);
        setVal('health-email', em[0], em[1]);
        var cal = configVal(data.calendar);
        setVal('health-calendar', cal[0], cal[1]);

        // Sandbox: enabled/disabled
        setVal('health-sandbox', data.sandbox === 'enabled' ? 'Enabled' : 'Disabled',
               data.sandbox === 'enabled' ? 'ok' : 'off');
    }

    function loadSessionInfo() {
        var sid = getSessionId();
        document.getElementById('session-id-display').textContent = sid.substring(0, 8) + '...';
        // Try to load server-side session data (may not exist if no tasks sent yet)
        apiGet('session/' + sid).then(function (data) {
            if (data.error) return; // Session not found yet
            document.getElementById('session-turns').textContent = data.turn_count || 0;
            var risk = data.cumulative_risk || 0;
            var riskEl = document.getElementById('session-risk');
            riskEl.textContent = risk.toFixed(2);
            riskEl.style.color = risk < 0.3 ? 'var(--green)' : risk < 0.7 ? 'var(--yellow)' : 'var(--red)';
            document.getElementById('session-violations').textContent = data.violation_count || 0;
            document.getElementById('session-lock-status').textContent = data.is_locked ? 'Locked' : 'Active';
        }).catch(function () {
            // No session yet, that's fine
        });
    }

    function loadRecentActivity() {
        var history = loadHistory();
        var container = document.getElementById('recent-activity');
        // Find recent task results (user messages followed by results)
        var activities = [];
        for (var i = history.length - 1; i >= 0 && activities.length < 5; i--) {
            if (history[i].role === 'user') {
                var status = 'unknown';
                // Look ahead for result
                for (var j = i + 1; j < history.length && j < i + 5; j++) {
                    if (history[j].role === 'system') { status = 'success'; break; }
                    if (history[j].role === 'error') { status = 'error'; break; }
                    if (history[j].role === 'results') { status = 'success'; break; }
                }
                activities.push({ text: history[i].text, status: status });
            }
        }

        if (activities.length === 0) {
            container.innerHTML = '<div class="empty-state">No recent activity</div>';
            return;
        }

        var html = '';
        for (var k = 0; k < activities.length; k++) {
            var a = activities[k];
            html += '<div class="activity-item">';
            html += '<span>' + escapeHtml(a.text.substring(0, 60)) + (a.text.length > 60 ? '...' : '') + '</span>';
            html += '<span class="activity-status ' + escapeHtml(a.status) + '">' + escapeHtml(a.status) + '</span>';
            html += '</div>';
        }
        container.innerHTML = html;
    }

    // ── Metrics ─────────────────────────────────────────────────

    function loadMetrics() {
        apiGet('metrics?window=' + metricsWindow).then(function (data) {
            renderMetrics(data);
        }).catch(function () {
            // Metrics not available yet — leave defaults
        });
    }

    function renderMetrics(resp) {
        var d = resp.data;

        // Trust badge
        var badge = document.getElementById('trust-badge');
        if (badge) {
            var tl = resp.trust_level || 0;
            badge.textContent = 'TL' + tl;
            badge.className = 'trust-badge tl-' + tl;
        }

        // Approval funnel
        setMetricVal('m-auto-approved', d.approval_funnel.auto_approved, 'ok');
        setMetricVal('m-manually-approved', d.approval_funnel.manually_approved, 'ok');
        setMetricVal('m-denied', d.approval_funnel.denied, d.approval_funnel.denied > 0 ? 'warn' : '');
        setMetricVal('m-expired', d.approval_funnel.expired, d.approval_funnel.expired > 0 ? 'warn' : '');

        // Task outcomes
        setMetricVal('m-success', d.task_outcomes.success, 'ok');
        setMetricVal('m-blocked', d.task_outcomes.blocked, d.task_outcomes.blocked > 0 ? 'warn' : '');
        setMetricVal('m-error', d.task_outcomes.error, d.task_outcomes.error > 0 ? 'fail' : '');
        setMetricVal('m-refused', d.task_outcomes.refused, d.task_outcomes.refused > 0 ? 'warn' : '');

        // Scanner blocks
        var scannerEl = document.getElementById('scanner-blocks');
        if (scannerEl) {
            if (d.scanner_blocks.length === 0) {
                scannerEl.innerHTML = '<div class="empty-state">No scanner blocks</div>';
            } else {
                var html = '';
                for (var i = 0; i < d.scanner_blocks.length; i++) {
                    var s = d.scanner_blocks[i];
                    html += '<div class="scanner-item">';
                    html += '<span class="scanner-name">' + escapeHtml(s.scanner) + '</span>';
                    html += '<span class="scanner-count">' + s.count + '</span>';
                    html += '</div>';
                }
                scannerEl.innerHTML = html;
            }
        }

        // Routine health
        setMetricVal('m-routine-total', d.routine_health.total, '');
        var successRate = d.routine_health.total > 0
            ? Math.round((d.routine_health.success / d.routine_health.total) * 100) + '%'
            : '--';
        var rateClass = d.routine_health.total > 0
            ? (d.routine_health.success / d.routine_health.total >= 0.9 ? 'ok' : 'warn')
            : '';
        setMetricVal('m-routine-success-rate', successRate, rateClass);
        setMetricVal('m-routine-avg-dur', d.routine_health.avg_duration_s > 0 ? d.routine_health.avg_duration_s + 's' : '--', '');
        setMetricVal('m-routine-errors', d.routine_health.error, d.routine_health.error > 0 ? 'fail' : '');

        // Response times
        setMetricVal('m-rt-avg', d.response_times.count > 0 ? d.response_times.avg_s + 's' : '--', '');
        setMetricVal('m-rt-p95', d.response_times.count > 0 ? d.response_times.p95_s + 's' : '--',
                     d.response_times.p95_s > 30 ? 'warn' : '');
    }

    function setMetricVal(id, val, cls) {
        var el = document.getElementById(id);
        if (el) {
            el.textContent = val;
            el.className = 'metric-value' + (cls ? ' ' + cls : '');
        }
    }

    function setMetricsWindow(w) {
        metricsWindow = w;
        var btns = document.querySelectorAll('.tw-btn');
        btns.forEach(function (b) {
            b.classList.toggle('active', b.getAttribute('data-window') === w);
        });
        loadMetrics();
    }

    function startMetricsPolling() {
        stopMetricsPolling();
        metricsInterval = setInterval(loadMetrics, 60000);
    }

    function stopMetricsPolling() {
        if (metricsInterval) {
            clearInterval(metricsInterval);
            metricsInterval = null;
        }
    }

    // Time window selector click handler
    var twSelector = document.getElementById('time-window-selector');
    if (twSelector) {
        twSelector.addEventListener('click', function (e) {
            var btn = e.target.closest('.tw-btn');
            if (btn) setMetricsWindow(btn.getAttribute('data-window'));
        });
    }

    // ── Memory View ───────────────────────────────────────────────

    var memorySearchInput = document.getElementById('memory-search-input');
    var memoryResults = document.getElementById('memory-results');
    var storeMemoryBtn = document.getElementById('store-memory-btn');
    var memoryStoreForm = document.getElementById('memory-store-form');
    var memorySaveBtn = document.getElementById('memory-save-btn');
    var memoryCancelBtn = document.getElementById('memory-cancel-btn');
    var memorySearchTimer = null;

    function loadMemory() {
        // Load recent chunks if no search query
        if (!memorySearchInput.value.trim()) {
            apiGet('memory/list?limit=20').then(function (data) {
                renderMemoryResults(data.chunks || [], false);
            }).catch(function () {
                memoryResults.innerHTML = '<div class="empty-state">Failed to load memories</div>';
            });
        }
    }

    // Debounced search
    if (memorySearchInput) {
        memorySearchInput.addEventListener('input', function () {
            clearTimeout(memorySearchTimer);
            var query = memorySearchInput.value.trim();
            if (!query) {
                loadMemory();
                return;
            }
            memorySearchTimer = setTimeout(function () {
                apiGet('memory/search?query=' + encodeURIComponent(query)).then(function (data) {
                    renderMemoryResults(data.results || [], true);
                }).catch(function () {
                    memoryResults.innerHTML = '<div class="empty-state">Search failed</div>';
                });
            }, 300);
        });
    }

    function renderMemoryResults(items, isSearch) {
        if (!items || items.length === 0) {
            memoryResults.innerHTML = '<div class="empty-state">' +
                (isSearch ? 'No results found' : 'No memories stored yet') + '</div>';
            return;
        }

        var html = '';
        for (var i = 0; i < items.length; i++) {
            var item = items[i];
            var content = item.content || '';
            var preview = content.length > 200 ? content.substring(0, 200) + '...' : content;
            html += '<div class="memory-card" data-chunk-id="' + escapeHtml(item.chunk_id) + '">';
            html += '<div class="memory-card-header">';
            html += '<span class="memory-card-source">' + escapeHtml(item.source || 'unknown') + '</span>';
            if (item.score !== undefined) {
                html += '<span class="memory-card-score">' + (item.match_type || 'match') + ' (' + item.score.toFixed(3) + ')</span>';
            }
            html += '</div>';
            html += '<div class="memory-card-preview">' + escapeHtml(preview) + '</div>';
            html += '<div class="memory-card-meta">ID: ' + escapeHtml(item.chunk_id) +
                     (item.created_at ? ' &middot; ' + formatTime(item.created_at) : '') + '</div>';
            html += '<div class="memory-card-actions">';
            html += '<button class="btn-sm danger" data-action="delete-memory" data-id="' + escapeHtml(item.chunk_id) + '">Delete</button>';
            html += '</div>';
            html += '</div>';
        }
        memoryResults.innerHTML = html;
        bindMemoryActions();
    }

    function bindMemoryActions() {
        // Expand/collapse cards
        memoryResults.querySelectorAll('.memory-card').forEach(function (card) {
            card.addEventListener('click', function (e) {
                if (e.target.tagName === 'BUTTON') return;
                card.classList.toggle('expanded');
            });
        });

        // Delete buttons
        memoryResults.querySelectorAll('[data-action="delete-memory"]').forEach(function (btn) {
            btn.addEventListener('click', function (e) {
                e.stopPropagation();
                var id = btn.getAttribute('data-id');
                if (!confirm('Delete this memory chunk?')) return;
                apiDelete('memory/' + id).then(function (data) {
                    if (data.status === 'ok') {
                        showToast('Memory chunk deleted', 'success');
                        loadMemory();
                    } else {
                        showToast('Failed to delete: ' + (data.reason || 'Unknown error'), 'error');
                    }
                }).catch(function (err) {
                    showToast('Delete failed: ' + err.message, 'error');
                });
            });
        });
    }

    // Store memory form
    if (storeMemoryBtn) {
        storeMemoryBtn.addEventListener('click', function () {
            memoryStoreForm.style.display = memoryStoreForm.style.display === 'none' ? 'block' : 'none';
        });
    }

    if (memoryCancelBtn) {
        memoryCancelBtn.addEventListener('click', function () {
            memoryStoreForm.style.display = 'none';
            document.getElementById('memory-text').value = '';
        });
    }

    if (memorySaveBtn) {
        memorySaveBtn.addEventListener('click', function () {
            var text = document.getElementById('memory-text').value.trim();
            var source = document.getElementById('memory-source').value.trim() || 'webui';
            if (!text) { showToast('Text is required', 'error'); return; }

            memorySaveBtn.disabled = true;
            apiPost('memory', { text: text, source: source }).then(function (data) {
                memorySaveBtn.disabled = false;
                if (data.status === 'ok') {
                    showToast('Stored ' + data.chunks_stored + ' chunk(s)', 'success');
                    memoryStoreForm.style.display = 'none';
                    document.getElementById('memory-text').value = '';
                    loadMemory();
                } else {
                    showToast('Store failed: ' + (data.reason || 'Unknown error'), 'error');
                }
            }).catch(function (err) {
                memorySaveBtn.disabled = false;
                showToast('Store failed: ' + err.message, 'error');
            });
        });
    }

    // ── Routines View ─────────────────────────────────────────────

    var createRoutineBtn = document.getElementById('create-routine-btn');
    var routineForm = document.getElementById('routine-form');
    var routineSaveBtn = document.getElementById('routine-save-btn');
    var routineCancelBtn = document.getElementById('routine-cancel-btn');
    var routineList = document.getElementById('routine-list');
    var triggerTypeSelect = document.getElementById('routine-trigger-type');
    var triggerHint = document.getElementById('trigger-hint');

    var triggerHints = {
        cron: '5-field cron expression (e.g. 0 9 * * *)',
        event: 'Event topic pattern (e.g. task.*.completed)',
        interval: 'Number of seconds between runs'
    };

    var triggerPlaceholders = { cron: '0 9 * * *', event: 'task.*.completed', interval: '3600' };

    if (triggerTypeSelect) {
        triggerTypeSelect.addEventListener('change', function () {
            var type = triggerTypeSelect.value;
            triggerHint.textContent = triggerHints[type] || '';
            document.getElementById('routine-trigger-value').placeholder = triggerPlaceholders[type] || '';
        });
    }

    if (createRoutineBtn) {
        createRoutineBtn.addEventListener('click', function () {
            routineForm.style.display = routineForm.style.display === 'none' ? 'block' : 'none';
        });
    }

    if (routineCancelBtn) {
        routineCancelBtn.addEventListener('click', function () {
            routineForm.style.display = 'none';
            clearRoutineForm();
        });
    }

    if (routineSaveBtn) {
        routineSaveBtn.addEventListener('click', function () {
            var name = document.getElementById('routine-name').value.trim();
            var triggerType = triggerTypeSelect.value;
            var triggerValue = document.getElementById('routine-trigger-value').value.trim();
            var prompt = document.getElementById('routine-prompt').value.trim();
            var cooldown = parseInt(document.getElementById('routine-cooldown').value) || 0;

            if (!name || !triggerValue || !prompt) {
                showToast('Name, trigger config, and prompt are required', 'error');
                return;
            }

            var triggerConfig = {};
            if (triggerType === 'cron') triggerConfig = { cron: triggerValue };
            else if (triggerType === 'event') triggerConfig = { event: triggerValue };
            else if (triggerType === 'interval') triggerConfig = { seconds: parseInt(triggerValue) || 0 };

            routineSaveBtn.disabled = true;
            apiPost('routine', {
                name: name,
                trigger_type: triggerType,
                trigger_config: triggerConfig,
                action_config: { prompt: prompt, approval_mode: 'auto' },
                cooldown_s: cooldown,
            }).then(function (data) {
                routineSaveBtn.disabled = false;
                if (data.status === 'ok') {
                    showToast('Routine created', 'success');
                    routineForm.style.display = 'none';
                    clearRoutineForm();
                    loadRoutines();
                } else {
                    showToast('Error: ' + (data.reason || JSON.stringify(data)), 'error');
                }
            }).catch(function (err) {
                routineSaveBtn.disabled = false;
                showToast('Failed: ' + err.message, 'error');
            });
        });
    }

    function clearRoutineForm() {
        document.getElementById('routine-name').value = '';
        document.getElementById('routine-trigger-value').value = '';
        document.getElementById('routine-prompt').value = '';
        document.getElementById('routine-cooldown').value = '0';
        if (triggerTypeSelect) triggerTypeSelect.value = 'cron';
        if (triggerHint) triggerHint.textContent = triggerHints.cron;
    }

    function loadRoutines() {
        if (!routineList) return;
        apiGet('routine').then(function (data) {
            if (data.status !== 'ok') {
                routineList.innerHTML = '<div class="empty-state">Failed to load routines</div>';
                return;
            }

            var routines = data.routines || [];

            // Update summary
            var enabled = 0, disabled = 0;
            for (var i = 0; i < routines.length; i++) {
                if (routines[i].enabled) enabled++;
                else disabled++;
            }
            document.getElementById('routines-total').textContent = routines.length;
            document.getElementById('routines-enabled').textContent = enabled;
            document.getElementById('routines-disabled').textContent = disabled;

            if (routines.length === 0) {
                routineList.innerHTML = '<div class="empty-state">No routines yet. Create one to get started.</div>';
                return;
            }

            var html = '';
            for (var j = 0; j < routines.length; j++) {
                html += renderRoutineCard(routines[j]);
            }
            routineList.innerHTML = html;
            bindRoutineActions();
        }).catch(function (err) {
            routineList.innerHTML = '<div class="empty-state">Error: ' + escapeHtml(err.message) + '</div>';
        });
    }

    function renderRoutineCard(r) {
        var triggerLabel = r.trigger_type;
        if (r.trigger_type === 'cron') triggerLabel = r.trigger_config.cron || 'cron';
        else if (r.trigger_type === 'event') triggerLabel = r.trigger_config.event || 'event';
        else if (r.trigger_type === 'interval') triggerLabel = (r.trigger_config.seconds || 0) + 's';

        var statusBadge = r.enabled
            ? '<span class="routine-badge enabled">Enabled</span>'
            : '<span class="routine-badge disabled">Disabled</span>';

        var nextRun = r.next_run_at ? formatTime(r.next_run_at) : 'N/A';
        var lastRun = r.last_run_at ? formatTime(r.last_run_at) : 'Never';

        return '<div class="routine-card" data-routine-id="' + r.routine_id + '">' +
            '<div class="routine-card-header">' +
                '<div>' +
                    '<span class="routine-card-name">' + escapeHtml(r.name) + '</span> ' +
                    statusBadge + ' ' +
                    '<span class="routine-badge trigger">' + escapeHtml(triggerLabel) + '</span>' +
                '</div>' +
                '<div class="routine-card-actions">' +
                    '<label class="toggle" title="Toggle enabled">' +
                        '<input type="checkbox" data-action="toggle" data-id="' + r.routine_id + '"' + (r.enabled ? ' checked' : '') + '>' +
                        '<span class="toggle-slider"></span>' +
                    '</label>' +
                    '<button class="btn-sm" data-action="run" data-id="' + r.routine_id + '">Run Now</button>' +
                    '<button class="btn-sm danger" data-action="delete" data-id="' + r.routine_id + '" data-name="' + escapeHtml(r.name) + '">Delete</button>' +
                '</div>' +
            '</div>' +
            '<div class="routine-card-meta">' +
                '<span>Next: ' + nextRun + '</span>' +
                '<span>Last: ' + lastRun + '</span>' +
                (r.cooldown_s > 0 ? '<span>Cooldown: ' + r.cooldown_s + 's</span>' : '') +
            '</div>' +
            '<div class="routine-history" data-history-id="' + r.routine_id + '">' +
                '<div class="routine-history-title" data-action="history" data-id="' + r.routine_id + '">Execution History</div>' +
                '<div class="routine-history-body" id="history-' + r.routine_id + '" style="display:none"></div>' +
            '</div>' +
        '</div>';
    }

    function formatTime(isoStr) {
        if (!isoStr) return 'N/A';
        try {
            var d = new Date(isoStr);
            return d.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
        } catch { return isoStr; }
    }

    function bindRoutineActions() {
        // Toggle enabled
        routineList.querySelectorAll('[data-action="toggle"]').forEach(function (el) {
            el.addEventListener('change', function () {
                var id = el.getAttribute('data-id');
                apiPatch('routine/' + id, { enabled: el.checked }).then(function () {
                    showToast(el.checked ? 'Routine enabled' : 'Routine disabled', 'success');
                    loadRoutines();
                }).catch(function (err) {
                    showToast('Toggle failed: ' + err.message, 'error');
                    el.checked = !el.checked;
                });
            });
        });

        // Run now
        routineList.querySelectorAll('[data-action="run"]').forEach(function (el) {
            el.addEventListener('click', function () {
                var id = el.getAttribute('data-id');
                el.disabled = true;
                el.textContent = 'Running...';
                apiPost('routine/' + id + '/run', {}).then(function (data) {
                    if (data.status === 'ok') {
                        showToast('Routine triggered', 'success');
                        el.textContent = 'Triggered';
                        setTimeout(function () { el.textContent = 'Run Now'; el.disabled = false; }, 2000);
                    } else {
                        showToast('Error: ' + (data.reason || 'Unknown'), 'error');
                        el.textContent = 'Run Now'; el.disabled = false;
                    }
                }).catch(function (err) {
                    showToast('Run failed: ' + err.message, 'error');
                    el.textContent = 'Run Now'; el.disabled = false;
                });
            });
        });

        // Delete
        routineList.querySelectorAll('[data-action="delete"]').forEach(function (el) {
            el.addEventListener('click', function () {
                var id = el.getAttribute('data-id');
                var name = el.getAttribute('data-name');
                if (!confirm('Delete routine "' + name + '"?')) return;
                apiDelete('routine/' + id).then(function () {
                    showToast('Routine deleted', 'success');
                    loadRoutines();
                }).catch(function (err) {
                    showToast('Delete failed: ' + err.message, 'error');
                });
            });
        });

        // History toggle
        routineList.querySelectorAll('[data-action="history"]').forEach(function (el) {
            el.addEventListener('click', function () {
                var id = el.getAttribute('data-id');
                var body = document.getElementById('history-' + id);
                if (!body) return;
                if (body.style.display === 'none') {
                    body.style.display = 'block';
                    loadExecutionHistory(id, body);
                } else {
                    body.style.display = 'none';
                }
            });
        });
    }

    function loadExecutionHistory(routineId, container) {
        apiGet('routine/' + routineId + '/executions?limit=10').then(function (data) {
            if (!data.executions || data.executions.length === 0) {
                container.innerHTML = '<div style="font-size:12px;color:var(--text-muted);padding:4px 0">No executions yet.</div>';
                return;
            }
            var html = '';
            for (var i = 0; i < data.executions.length; i++) {
                var ex = data.executions[i];
                html += '<div class="execution-row">' +
                    '<span class="execution-status ' + escapeHtml(ex.status) + '">' + escapeHtml(ex.status) + '</span>' +
                    '<span>' + escapeHtml(ex.triggered_by || '') + '</span>' +
                    '<span>' + formatTime(ex.started_at) + '</span>' +
                '</div>';
            }
            container.innerHTML = html;
        }).catch(function () {
            container.innerHTML = '<div style="color:var(--red);font-size:12px">Failed to load history.</div>';
        });
    }

    // ── Core task flow ────────────────────────────────────────────

    function sendTask(text) {
        if (isProcessing) return;
        isProcessing = true;
        setInputEnabled(false);

        // Ensure we're on chat view
        if (currentView !== 'chat') showView('chat');

        addUserMessage(text);
        var statusId = 'status-' + Date.now();
        addStatusMessage('Sending task to planner...', statusId);

        // WebSocket transport
        if (transport === 'ws' && ws && ws.readyState === WebSocket.OPEN) {
            var pendingKey = 'pending-' + statusId;
            wsTaskResolvers[pendingKey] = { statusId: statusId };
            try {
                ws.send(JSON.stringify({ type: 'task', request: text }));
                setTimeout(function () {
                    // BH3-070: 600s (10 min) — tasks can take 5+ min through the planner
                    if (wsTaskResolvers[pendingKey]) {
                        removeElement(statusId);
                        delete wsTaskResolvers[pendingKey];
                        addErrorMessage('Task timed out — no response from server.');
                        isProcessing = false;
                        setInputEnabled(true);
                    }
                }, 600000);
            } catch (err) {
                removeElement(statusId);
                delete wsTaskResolvers[pendingKey];
                addErrorMessage('WebSocket send failed: ' + err.message);
                isProcessing = false;
                setInputEnabled(true);
            }
            return;
        }

        // HTTP transport
        apiPost('task', { request: text, source: 'webui', session_id: getSessionId() }).then(function (data) {
            removeElement(statusId);

            if (data.conversation && data.conversation.warnings && data.conversation.warnings.length > 0) {
                renderWarnings(data.conversation.warnings);
                appendToHistory({ role: 'warnings', warnings: data.conversation.warnings });
            }

            if (data.status === 'awaiting_approval') {
                var approvalId = data.approval_id || data.reason.replace('approval_id:', '');
                addStatusMessage('Waiting for plan...', statusId + '-poll');
                pollApproval(approvalId, statusId + '-poll');
            } else if (data.status === 'success') {
                addSystemMessage(data.response || data.plan_summary || 'Task completed.');
                if (data.step_results) renderStepResults(data.step_results);
            } else if (data.status === 'blocked') {
                addErrorMessage('Blocked: ' + (data.reason || 'Policy violation'));
            } else if (data.status === 'refused') {
                addErrorMessage('Refused: ' + (data.reason || 'Request refused by planner'));
            } else if (data.status === 'error') {
                addErrorMessage('Error: ' + (data.reason || 'Unknown error'));
            } else {
                addSystemMessage('Response: ' + JSON.stringify(data));
            }
            isProcessing = false;
            setInputEnabled(true);
        }).catch(function (err) {
            removeElement(statusId);
            addErrorMessage('Failed to reach controller: ' + err.message);
            isProcessing = false;
            setInputEnabled(true);
        });
    }

    function pollApproval(approvalId, statusElId) {
        apiGet('approval/' + approvalId).then(function (data) {
            if (data.status === 'pending') {
                removeElement(statusElId);
                renderPlan(data.plan_summary || 'Plan ready', data.steps || [], approvalId);
            } else if (data.status === 'approved' || data.status === 'denied' || data.status === 'expired') {
                removeElement(statusElId);
                addSystemMessage('Approval status: ' + data.status + (data.reason ? ' — ' + data.reason : ''));
            } else if (data.status === 'not_found') {
                removeElement(statusElId);
                addErrorMessage('Approval request not found.');
            } else {
                // Keep polling
                setTimeout(function () { pollApproval(approvalId, statusElId); }, POLL_INTERVAL);
            }
        }).catch(function () {
            setTimeout(function () { pollApproval(approvalId, statusElId); }, POLL_INTERVAL);
        });
    }

    // Approval handler (global for button bindings)
    window.handleApproval = function (approvalId, granted) {
        var btnContainer = document.getElementById('approval-' + approvalId);
        if (!btnContainer) return;

        btnContainer.querySelectorAll('button').forEach(function (b) { b.disabled = true; });
        var action = granted ? 'Approved' : 'Denied';
        btnContainer.innerHTML = '<span style="color:var(--text-muted)">' + action + '</span>';

        if (granted) {
            var statusId = 'exec-' + Date.now();
            addStatusMessage('Executing approved plan...', statusId);
            apiPost('approve/' + approvalId, { granted: true, reason: 'Approved via WebUI' }).then(function (data) {
                removeElement(statusId);
                if (data.status === 'success') {
                    addSystemMessage(data.plan_summary || 'Plan executed successfully.');
                    renderStepResults(data.step_results);
                    showToast('Plan executed successfully', 'success');
                } else if (data.status === 'blocked') {
                    addErrorMessage('Execution blocked: ' + (data.reason || 'Policy violation'));
                    renderStepResults(data.step_results);
                } else if (data.status === 'error') {
                    addErrorMessage('Execution error: ' + (data.reason || 'Unknown error'));
                } else {
                    addSystemMessage('Result: ' + JSON.stringify(data));
                }
            }).catch(function (err) {
                removeElement(statusId);
                addErrorMessage('Failed to submit approval: ' + err.message);
            });
        } else {
            apiPost('approve/' + approvalId, { granted: false, reason: 'Denied via WebUI' }).then(function () {
                addSystemMessage('Plan denied.');
                showToast('Plan denied', 'info');
            }).catch(function (err) {
                addErrorMessage('Failed to submit denial: ' + err.message);
            });
        }

        appendToHistory({ role: 'approval', approvalId: approvalId, granted: granted });
    };

    // ── History restore ───────────────────────────────────────────

    function restoreHistory() {
        var history = loadHistory();
        if (history.length > 0) dismissWelcome();
        for (var i = 0; i < history.length; i++) {
            var entry = history[i];
            if (entry.role === 'user') {
                addMessage('user', '<div class="label">You</div>' + escapeHtml(entry.text));
            } else if (entry.role === 'system') {
                if (entry.text != null) {
                    addMessage('system', '<div class="label">Sentinel</div>' + escapeHtml(entry.text));
                } else if (entry.html != null) {
                    addMessage('system', '<div class="label">Sentinel</div>' + escapeHtml(entry.html));
                }
            } else if (entry.role === 'error') {
                addMessage('error', '<div class="label">Error</div>' + escapeHtml(entry.text));
            } else if (entry.role === 'warnings') {
                if (entry.warnings) renderWarnings(entry.warnings);
            } else if (entry.role === 'plan') {
                var html = '<div class="label">Sentinel</div>';
                html += '<div class="plan-summary">' + escapeHtml(entry.planSummary || '') + '</div>';
                html += buildStepsHtml(entry.steps);
                var planMsgEl = addMessage('system', html);
                bindStepToggles(planMsgEl);
            } else if (entry.role === 'results') {
                renderStepResultsStatic(entry.stepResults);
            }
        }
    }

    // ── Helpers ───────────────────────────────────────────────────

    function setInputEnabled(enabled) {
        input.disabled = !enabled;
        sendBtn.disabled = !enabled;
        if (enabled && currentView === 'chat') input.focus();
    }

    // ── Log Viewer ───────────────────────────────────────────────

    var logEntries = document.getElementById('log-entries');
    var logEmpty = document.getElementById('log-empty');
    var logCount = document.getElementById('log-count');
    var logLevelFilter = document.getElementById('log-level-filter');
    var logTaskFilter = document.getElementById('log-task-filter');
    var logPauseBtn = document.getElementById('log-pause-btn');
    var logClearBtn = document.getElementById('log-clear-btn');

    var logAbortController = null;
    var logPaused = false;
    var logEntryCount = 0;
    var LOG_MAX_ENTRIES = 500;
    var logRecentTasks = {}; // task_id → {preview, source, time}

    function initLogView() {
        if (!logPaused && !logAbortController) {
            connectLogStream();
        }
    }

    function connectLogStream() {
        if (logAbortController) {
            logAbortController.abort();
            logAbortController = null;
        }

        var level = logLevelFilter ? logLevelFilter.value : 'INFO';
        var url = '/api/logs/stream?level=' + encodeURIComponent(level);

        logAbortController = new AbortController();
        var signal = logAbortController.signal;

        if (logEmpty) logEmpty.style.display = 'none';

        // Use fetch instead of EventSource so we can send the Authorization header.
        // EventSource API does not support custom headers — the middleware would 401.
        fetch(url, {
            headers: { 'Authorization': 'Bearer ' + getToken() },
            signal: signal,
        }).then(function (resp) {
            if (!resp.ok) {
                throw new Error('Log stream HTTP ' + resp.status);
            }
            var reader = resp.body.getReader();
            var decoder = new TextDecoder();
            var buffer = '';

            function pump() {
                return reader.read().then(function (result) {
                    if (result.done) return;
                    buffer += decoder.decode(result.value, { stream: true });
                    // Normalise CRLF → LF (sse_starlette sends \r\n)
                    buffer = buffer.replace(/\r\n/g, '\n');
                    // Parse SSE lines: "event: log\ndata: {...}\n\n"
                    var parts = buffer.split('\n\n');
                    buffer = parts.pop(); // keep incomplete chunk
                    parts.forEach(function (block) {
                        if (logPaused) return;
                        var dataLine = '';
                        block.split('\n').forEach(function (line) {
                            if (line.indexOf('data: ') === 0) dataLine = line.substring(6);
                        });
                        if (dataLine) {
                            try {
                                appendLogEntry(JSON.parse(dataLine));
                            } catch (err) {
                                // Ignore malformed events
                            }
                        }
                    });
                    return pump();
                });
            }
            return pump();
        }).catch(function (err) {
            if (err.name === 'AbortError') return;
            if (logEmpty) {
                logEmpty.textContent = 'Log stream disconnected. Click Resume to reconnect.';
                logEmpty.style.display = '';
            }
            logAbortController = null;
        });
    }

    function addLogTaskOption(taskId, preview, source) {
        if (!logTaskFilter || logRecentTasks[taskId]) return;
        var short = taskId.substring(0, 8);
        var label = short + ' — ' + (preview || source || 'task').substring(0, 50);
        logRecentTasks[taskId] = { preview: preview, source: source };
        var opt = document.createElement('option');
        opt.value = taskId;
        opt.textContent = label;
        // Insert after "All tasks" but before older entries (newest first)
        if (logTaskFilter.options.length > 1) {
            logTaskFilter.insertBefore(opt, logTaskFilter.options[1]);
        } else {
            logTaskFilter.appendChild(opt);
        }
    }

    function appendLogEntry(entry) {
        if (logEmpty) logEmpty.style.display = 'none';

        var entryTaskId = entry.task_id || '';

        // Track new tasks from task_received events for the dropdown
        if (entry.event === 'task_received' && entryTaskId) {
            addLogTaskOption(entryTaskId, entry.message || '', entry.source || '');
        }

        // Client-side task filter (now a select dropdown)
        var taskFilter = logTaskFilter ? logTaskFilter.value : '';
        if (taskFilter && entryTaskId !== taskFilter) {
            return;
        }

        var row = document.createElement('div');
        row.className = 'log-entry log-' + (entry.level || 'INFO').toLowerCase();
        if (entryTaskId) row.setAttribute('data-task-id', entryTaskId);

        var ts = entry.timestamp ? new Date(entry.timestamp * 1000).toLocaleTimeString(
            undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' }
        ) : '--:--:--';

        // Build task ID badge — clickable to filter
        var taskBadge = '';
        if (entryTaskId) {
            taskBadge = '<span class="log-task-id" title="' + escapeHtml(entryTaskId) +
                '">' + escapeHtml(entryTaskId.substring(0, 8)) + '</span>';
        }

        row.innerHTML =
            '<span class="log-ts">' + ts + '</span>' +
            '<span class="log-level">' + escapeHtml(entry.level || 'INFO') + '</span>' +
            taskBadge +
            '<span class="log-msg">' + escapeHtml(entry.message || '') + '</span>' +
            (entry.event ? '<span class="log-event">' + escapeHtml(entry.event) + '</span>' : '');

        logEntries.appendChild(row);
        logEntryCount++;

        // Cap entries
        while (logEntries.children.length > LOG_MAX_ENTRIES) {
            logEntries.removeChild(logEntries.firstChild);
            logEntryCount--;
        }

        // Auto-scroll
        logEntries.scrollTop = logEntries.scrollHeight;

        if (logCount) logCount.textContent = logEntryCount + ' entries';
    }

    // Click on a task ID badge to filter to that task
    if (logEntries) {
        logEntries.addEventListener('click', function (e) {
            var badge = e.target.closest('.log-task-id');
            if (!badge || !logTaskFilter) return;
            var fullId = badge.getAttribute('title');
            if (!fullId) return;
            // Ensure the task is in the dropdown
            addLogTaskOption(fullId, '', '');
            logTaskFilter.value = fullId;
            filterLogEntries();
        });
    }

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
        if (logEntries) {
            logEntries.innerHTML = '';
            if (logEmpty) {
                logEmpty.textContent = 'Log entries cleared';
                logEmpty.style.display = '';
                logEntries.appendChild(logEmpty);
            }
        }
        logEntryCount = 0;
        if (logCount) logCount.textContent = '0 entries';
    }

    if (logPauseBtn) logPauseBtn.addEventListener('click', toggleLogPause);
    if (logClearBtn) logClearBtn.addEventListener('click', clearLogEntries);
    if (logLevelFilter) {
        logLevelFilter.addEventListener('change', function () {
            clearLogEntries();
            if (!logPaused) connectLogStream();
        });
    }
    if (logTaskFilter) {
        logTaskFilter.addEventListener('change', function () {
            filterLogEntries();
        });
    }

    function filterLogEntries() {
        var filter = logTaskFilter ? logTaskFilter.value : '';
        if (!logEntries) return;
        var rows = logEntries.querySelectorAll('.log-entry');
        var visible = 0;
        for (var i = 0; i < rows.length; i++) {
            var rowTaskId = rows[i].getAttribute('data-task-id') || '';
            var show = !filter || rowTaskId === filter;
            rows[i].style.display = show ? '' : 'none';
            if (show) visible++;
        }
        if (logCount) logCount.textContent = visible + ' entries';
    }

    // ── Chat clear button ────────────────────────────────────────

    var clearChatBtn = document.getElementById('clear-chat-btn');
    if (clearChatBtn) {
        clearChatBtn.addEventListener('click', function () {
            if (confirm('Clear conversation history?')) {
                localStorage.removeItem(STORAGE_KEY);
                messagesEl.innerHTML = '';
                resetSessionId();
                if (chatWelcome) chatWelcome.style.display = '';
                showToast('History cleared', 'info');
            }
        });
    }

    // ── Clear history (legacy shortcut) ──────────────────────────

    // Legacy shortcut: shift+click on nav brand to clear conversation history.
    // Kept as a power-user feature — no UI affordance, intentionally hidden.
    document.querySelector('.nav-brand').addEventListener('click', function (e) {
        if (e.shiftKey) {
            if (confirm('Clear conversation history?')) {
                localStorage.removeItem(STORAGE_KEY);
                messagesEl.innerHTML = '';
                resetSessionId();
                if (chatWelcome) chatWelcome.style.display = '';
                showToast('History cleared', 'info');
            }
        }
    });

    // ── Dark mode toggle ───────────────────────────────────────────

    var THEME_KEY = 'sentinel-theme';
    var themeToggleBtn = document.getElementById('theme-toggle-btn');
    var themeMetaTag = document.querySelector('meta[name="theme-color"]');

    function getPreferredTheme() {
        var stored = localStorage.getItem(THEME_KEY);
        if (stored === 'dark' || stored === 'light') return stored;
        return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    }

    function applyTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        // Swap toggle icons
        var lightIcon = themeToggleBtn.querySelector('.theme-icon-light');
        var darkIcon = themeToggleBtn.querySelector('.theme-icon-dark');
        if (lightIcon && darkIcon) {
            lightIcon.style.display = theme === 'dark' ? 'none' : '';
            darkIcon.style.display = theme === 'dark' ? '' : 'none';
        }
        // Update meta theme-color for browser chrome
        if (themeMetaTag) {
            themeMetaTag.setAttribute('content', theme === 'dark' ? '#171614' : '#2B8585');
        }
    }

    function toggleTheme() {
        var current = document.documentElement.getAttribute('data-theme') || getPreferredTheme();
        var next = current === 'dark' ? 'light' : 'dark';
        localStorage.setItem(THEME_KEY, next);
        applyTheme(next);
    }

    // Listen for OS theme changes (only applies if user hasn't set explicit preference)
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', function (e) {
        if (!localStorage.getItem(THEME_KEY)) {
            applyTheme(e.matches ? 'dark' : 'light');
        }
    });

    if (themeToggleBtn) {
        themeToggleBtn.addEventListener('click', toggleTheme);
    }

    // Apply theme immediately to avoid flash
    applyTheme(getPreferredTheme());

    // ── Init ──────────────────────────────────────────────────────

    form.addEventListener('submit', function (e) {
        e.preventDefault();
        var text = input.value.trim();
        if (!text) return;
        input.value = '';
        sendTask(text);
    });

    // Start on chat view, input bar visible
    restoreHistory();
    checkHealth();
    setTimeout(initTransport, 1000);
    setInterval(checkHealth, 30000);

    // Expose auth helpers for settings.js (loaded after this IIFE)
    window.SentinelAuth = {
        getAuthHeaders: getAuthHeaders,
        handleAuthResponse: handleAuthResponse,
        getToken: getToken,
        clearToken: clearToken
    };
})();
