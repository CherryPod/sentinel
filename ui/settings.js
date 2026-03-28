/**
 * Settings panel — profile, preferences, and admin user management.
 *
 * Depends on window.SentinelAuth (exposed by app.js IIFE):
 *   - getAuthHeaders()  : returns { Authorization: 'Bearer <token>' }
 *   - handleAuthResponse(resp) : handles 401 redirects + token refresh
 */
var Settings = {
    currentTab: 'profile',
    profile: null,  // cached profile from /api/auth/me
    userRole: null,  // fetched from server, NOT localStorage

    // ── Initialisation ──────────────────────────────────────────

    init: function () {
        var self = this;

        // Wire up open/close
        var btn = document.getElementById('settings-btn');
        var closeBtn = document.getElementById('settings-close');
        var overlay = document.getElementById('settings-overlay');

        if (btn) btn.addEventListener('click', function () { self.open(); });
        if (closeBtn) closeBtn.addEventListener('click', function () { self.close(); });
        if (overlay) {
            overlay.addEventListener('click', function (e) {
                if (e.target.id === 'settings-overlay') self.close();
            });
        }

        // Escape key closes settings
        document.addEventListener('keydown', function (e) {
            if (e.key === 'Escape' && overlay && overlay.style.display !== 'none') {
                self.close();
            }
        });

        // Show username in nav from localStorage
        var name = localStorage.getItem('sentinel-display-name');
        var nameEl = document.getElementById('user-display-name');
        if (name && nameEl) nameEl.textContent = name;

        // Fetch role from server so admin tab visibility can't be faked via localStorage
        this.fetchRole();

        // Check must_change_pin on load
        this.checkMustChangePin();
    },

    fetchRole: function () {
        var self = this;
        var auth = window.SentinelAuth;
        if (!auth || !auth.getToken()) return;

        fetch('/api/auth/me', {
            headers: auth.getAuthHeaders()
        }).then(function (resp) {
            auth.handleAuthResponse(resp);
            if (!resp.ok) return;
            return resp.json();
        }).then(function (data) {
            if (data && data.role) {
                self.userRole = data.role;
            }
        }).catch(function () {
            // Silently ignore — userRole stays null, admin tab won't show
        });
    },

    // ── Open / Close ────────────────────────────────────────────

    open: function () {
        var overlay = document.getElementById('settings-overlay');
        if (!overlay) return;
        overlay.style.display = 'flex';
        this.renderTabs();
        this.showTab(this.currentTab);
    },

    close: function () {
        var overlay = document.getElementById('settings-overlay');
        if (overlay) overlay.style.display = 'none';
    },

    // ── Tab rendering ───────────────────────────────────────────

    renderTabs: function () {
        var tabsEl = document.getElementById('settings-tabs');
        if (!tabsEl) return;

        // Use server-fetched role, not localStorage (prevents client-side privilege escalation)
        var role = this.userRole || 'user';
        var tabs = [
            { id: 'profile', label: 'Profile' },
            { id: 'preferences', label: 'Preferences' }
        ];

        // Admin and owner get user management
        if (role === 'admin' || role === 'owner') {
            tabs.push({ id: 'users', label: 'User Management' });
        }

        var self = this;
        tabsEl.innerHTML = '';
        tabs.forEach(function (tab) {
            var btn = document.createElement('button');
            btn.className = 'settings-tab' + (tab.id === self.currentTab ? ' active' : '');
            btn.textContent = tab.label;
            btn.addEventListener('click', function () { self.showTab(tab.id); });
            tabsEl.appendChild(btn);
        });
    },

    showTab: function (name) {
        this.currentTab = name;
        var contentEl = document.getElementById('settings-content');
        if (!contentEl) return;
        contentEl.innerHTML = '';

        // Update active tab styling
        var tabs = document.querySelectorAll('.settings-tab');
        for (var i = 0; i < tabs.length; i++) {
            tabs[i].classList.toggle('active', tabs[i].textContent.toLowerCase().replace(' ', '') ===
                name.replace('users', 'usermanagement'));
        }
        // Simpler: just re-render tabs
        this.renderTabs();

        switch (name) {
            case 'profile':
                this.renderProfile(contentEl);
                break;
            case 'preferences':
                this.renderPreferences(contentEl);
                break;
            case 'users':
                this.renderUserManagement(contentEl);
                break;
        }
    },

    // ── Profile Tab ─────────────────────────────────────────────

    renderProfile: function (el) {
        var self = this;

        el.innerHTML =
            '<div class="settings-section">' +
                '<div class="settings-label">Display Name</div>' +
                '<div class="settings-value" id="profile-name">Loading...</div>' +
            '</div>' +
            '<div class="settings-section">' +
                '<div class="settings-label">Role</div>' +
                '<div class="settings-value" id="profile-role">--</div>' +
            '</div>' +
            '<div class="settings-section">' +
                '<div class="settings-label">Trust Level</div>' +
                '<div class="settings-value" id="profile-trust">--</div>' +
            '</div>' +
            '<div class="settings-section">' +
                '<div class="settings-label">Change PIN</div>' +
                '<div class="pin-change-form">' +
                    '<input type="password" id="pin-current" class="settings-input" placeholder="Current PIN" autocomplete="current-password" maxlength="20">' +
                    '<input type="password" id="pin-new" class="settings-input" placeholder="New PIN" autocomplete="new-password" maxlength="20">' +
                    '<input type="password" id="pin-confirm" class="settings-input" placeholder="Confirm New PIN" autocomplete="new-password" maxlength="20">' +
                    '<button class="settings-btn-primary" id="pin-change-btn">Change PIN</button>' +
                    '<div class="settings-result" id="pin-result"></div>' +
                '</div>' +
            '</div>';

        // Wire up PIN change
        var pinBtn = document.getElementById('pin-change-btn');
        if (pinBtn) {
            pinBtn.addEventListener('click', function () { self.changePin(); });
        }

        // Allow Enter key in PIN fields to submit
        var pinConfirm = document.getElementById('pin-confirm');
        if (pinConfirm) {
            pinConfirm.addEventListener('keydown', function (e) {
                if (e.key === 'Enter') self.changePin();
            });
        }

        // Load profile data
        this.loadProfile();
    },

    loadProfile: function () {
        var self = this;
        var auth = window.SentinelAuth;
        if (!auth) return;

        fetch('/api/auth/me', {
            headers: auth.getAuthHeaders()
        }).then(function (resp) {
            auth.handleAuthResponse(resp);
            return resp.json();
        }).then(function (data) {
            self.profile = data;
            // Keep server-fetched role in sync
            if (data.role) self.userRole = data.role;
            var nameEl = document.getElementById('profile-name');
            var roleEl = document.getElementById('profile-role');
            var trustEl = document.getElementById('profile-trust');

            if (nameEl) nameEl.textContent = data.display_name || '--';
            if (roleEl) roleEl.textContent = (data.role || 'user').charAt(0).toUpperCase() + (data.role || 'user').slice(1);
            if (trustEl) trustEl.textContent = data.trust_level != null ? 'TL' + data.trust_level : 'Default';
        }).catch(function () {
            var nameEl = document.getElementById('profile-name');
            if (nameEl) nameEl.textContent = localStorage.getItem('sentinel-display-name') || '--';
        });
    },

    changePin: function () {
        var auth = window.SentinelAuth;
        if (!auth) return;

        var currentPin = document.getElementById('pin-current');
        var newPin = document.getElementById('pin-new');
        var confirmPin = document.getElementById('pin-confirm');
        var resultEl = document.getElementById('pin-result');
        var btn = document.getElementById('pin-change-btn');

        if (!currentPin || !newPin || !confirmPin || !resultEl) return;

        var current = currentPin.value.trim();
        var next = newPin.value.trim();
        var confirm = confirmPin.value.trim();

        // Validation
        if (!current || !next || !confirm) {
            resultEl.className = 'settings-result error';
            resultEl.textContent = 'All fields are required';
            return;
        }
        if (next !== confirm) {
            resultEl.className = 'settings-result error';
            resultEl.textContent = 'New PINs do not match';
            return;
        }
        if (next.length < 4) {
            resultEl.className = 'settings-result error';
            resultEl.textContent = 'PIN must be at least 4 characters';
            return;
        }

        btn.disabled = true;
        btn.textContent = 'Changing...';
        resultEl.className = 'settings-result';
        resultEl.textContent = '';

        fetch('/api/auth/change-pin', {
            method: 'POST',
            headers: Object.assign({ 'Content-Type': 'application/json' }, auth.getAuthHeaders()),
            body: JSON.stringify({ current_pin: current, new_pin: next })
        }).then(function (resp) {
            auth.handleAuthResponse(resp);
            return resp.json().then(function (body) {
                return { ok: resp.ok, body: body };
            });
        }).then(function (result) {
            if (result.ok) {
                resultEl.className = 'settings-result success';
                resultEl.textContent = 'PIN changed successfully';
                currentPin.value = '';
                newPin.value = '';
                confirmPin.value = '';
                // Hide the must-change banner
                var banner = document.getElementById('pin-banner');
                if (banner) banner.style.display = 'none';
            } else {
                resultEl.className = 'settings-result error';
                resultEl.textContent = result.body.error || result.body.detail || 'Failed to change PIN';
            }
        }).catch(function (err) {
            resultEl.className = 'settings-result error';
            resultEl.textContent = err.message || 'Network error';
        }).finally(function () {
            btn.disabled = false;
            btn.textContent = 'Change PIN';
        });
    },

    // ── Preferences Tab ─────────────────────────────────────────

    renderPreferences: function (el) {
        el.innerHTML =
            '<div class="settings-placeholder">' +
                '<p>Preferences coming soon.</p>' +
                '<p class="settings-hint">Notification settings, default trust level overrides, and display options will appear here.</p>' +
            '</div>';
    },

    // ── User Management Tab (admin/owner only) ──────────────────

    renderUserManagement: function (el) {
        var self = this;

        el.innerHTML =
            '<div class="user-mgmt-subtabs" id="user-mgmt-subtabs">' +
                '<button class="subtab active" data-subtab="users">Users</button>' +
                '<button class="subtab" data-subtab="sessions">Sessions</button>' +
                '<button class="subtab" data-subtab="credentials">Credentials</button>' +
            '</div>' +
            '<div id="user-mgmt-content"></div>';

        var subtabs = el.querySelectorAll('.subtab');
        for (var i = 0; i < subtabs.length; i++) {
            (function (btn) {
                btn.addEventListener('click', function () {
                    // Update active subtab
                    var all = document.querySelectorAll('.subtab');
                    for (var j = 0; j < all.length; j++) all[j].classList.remove('active');
                    btn.classList.add('active');

                    var contentEl = document.getElementById('user-mgmt-content');
                    if (!contentEl) return;

                    var tab = btn.getAttribute('data-subtab');
                    switch (tab) {
                        case 'users': self.loadUsers(contentEl); break;
                        case 'sessions': self.loadSessions(contentEl); break;
                        case 'credentials': self.loadCredentials(contentEl); break;
                    }
                });
            })(subtabs[i]);
        }

        // Load users by default
        var contentEl = document.getElementById('user-mgmt-content');
        if (contentEl) this.loadUsers(contentEl);
    },

    loadUsers: function (el) {
        var self = this;
        var auth = window.SentinelAuth;
        if (!auth) return;

        el.innerHTML = '<div class="settings-placeholder">Loading users...</div>';

        fetch('/api/users?active_only=false', {
            headers: auth.getAuthHeaders()
        }).then(function (resp) {
            auth.handleAuthResponse(resp);
            if (!resp.ok) throw new Error('Failed to load users');
            return resp.json();
        }).then(function (users) {
            var html =
                '<div class="users-header">' +
                    '<button class="settings-btn-primary" id="new-user-btn">+ New User</button>' +
                '</div>' +
                '<div id="create-user-area"></div>' +
                '<table class="users-table">' +
                    '<thead><tr>' +
                        '<th>Name</th><th>Role</th><th>Trust</th><th>Status</th><th>Actions</th>' +
                    '</tr></thead>' +
                    '<tbody>';

            users.forEach(function (u) {
                var status = u.is_active ? 'Active' : 'Inactive';
                var statusClass = u.is_active ? 'active' : 'inactive';
                var trust = u.trust_level != null ? 'TL' + u.trust_level : '--';
                var role = (u.role || 'user').charAt(0).toUpperCase() + (u.role || 'user').slice(1);

                html += '<tr>' +
                    '<td>' + self.escapeHtml(u.display_name) + '</td>' +
                    '<td>' + self.escapeHtml(role) + '</td>' +
                    '<td>' + trust + '</td>' +
                    '<td><span class="user-status ' + self.escapeHtml(statusClass) + '">' + self.escapeHtml(status) + '</span></td>' +
                    '<td>' +
                        '<button class="action-btn" data-action="revoke" data-user-id="' + self.escapeHtml(String(u.user_id)) + '" title="Revoke all sessions">Revoke Sessions</button>' +
                    '</td>' +
                '</tr>';
            });

            html += '</tbody></table>';
            el.innerHTML = html;

            // Wire up New User button
            var newBtn = document.getElementById('new-user-btn');
            if (newBtn) {
                newBtn.addEventListener('click', function () {
                    var area = document.getElementById('create-user-area');
                    if (area) self.showCreateUserForm(area);
                });
            }

            // Wire up action buttons
            var actionBtns = el.querySelectorAll('.action-btn');
            for (var i = 0; i < actionBtns.length; i++) {
                (function (btn) {
                    btn.addEventListener('click', function () {
                        var action = btn.getAttribute('data-action');
                        var userId = btn.getAttribute('data-user-id');
                        self.handleUserAction(action, userId, btn);
                    });
                })(actionBtns[i]);
            }
        }).catch(function (err) {
            el.innerHTML = '<div class="settings-result error">' + (err.message || 'Failed to load users') + '</div>';
        });
    },

    showCreateUserForm: function (el) {
        var self = this;

        el.innerHTML =
            '<div class="create-user-form">' +
                '<h3>Create User</h3>' +
                '<div class="form-row">' +
                    '<label>Username</label>' +
                    '<input type="text" id="new-user-name" class="settings-input" placeholder="Display name" autocomplete="off">' +
                '</div>' +
                '<div class="form-row">' +
                    '<label>Temporary PIN</label>' +
                    '<input type="password" id="new-user-pin" class="settings-input" placeholder="Initial PIN (optional)" autocomplete="new-password" maxlength="20">' +
                '</div>' +
                '<div class="form-row">' +
                    '<label>Role</label>' +
                    '<select id="new-user-role" class="settings-input">' +
                        '<option value="user">User</option>' +
                        '<option value="admin">Admin</option>' +
                    '</select>' +
                '</div>' +
                '<div class="form-row create-user-actions">' +
                    '<button class="settings-btn-primary" id="create-user-submit">Create</button>' +
                    '<button class="settings-btn-secondary" id="create-user-cancel">Cancel</button>' +
                '</div>' +
                '<div class="settings-result" id="create-user-result"></div>' +
            '</div>';

        var submitBtn = document.getElementById('create-user-submit');
        var cancelBtn = document.getElementById('create-user-cancel');

        if (submitBtn) submitBtn.addEventListener('click', function () { self.createUser(); });
        if (cancelBtn) cancelBtn.addEventListener('click', function () { el.innerHTML = ''; });
    },

    createUser: function () {
        var auth = window.SentinelAuth;
        if (!auth) return;

        var nameInput = document.getElementById('new-user-name');
        var pinInput = document.getElementById('new-user-pin');
        var roleInput = document.getElementById('new-user-role');
        var resultEl = document.getElementById('create-user-result');
        var submitBtn = document.getElementById('create-user-submit');

        if (!nameInput || !resultEl) return;

        var name = nameInput.value.trim();
        if (!name) {
            resultEl.className = 'settings-result error';
            resultEl.textContent = 'Username is required';
            return;
        }

        var body = { display_name: name };
        if (pinInput && pinInput.value.trim()) {
            body.pin = pinInput.value.trim();
        }

        submitBtn.disabled = true;
        submitBtn.textContent = 'Creating...';
        resultEl.className = 'settings-result';
        resultEl.textContent = '';

        var self = this;
        fetch('/api/users', {
            method: 'POST',
            headers: Object.assign({ 'Content-Type': 'application/json' }, auth.getAuthHeaders()),
            body: JSON.stringify(body)
        }).then(function (resp) {
            auth.handleAuthResponse(resp);
            return resp.json().then(function (data) {
                return { ok: resp.ok, body: data };
            });
        }).then(function (result) {
            if (result.ok) {
                resultEl.className = 'settings-result success';
                resultEl.textContent = 'User "' + name + '" created successfully';
                // Refresh user list after a brief delay
                setTimeout(function () {
                    var contentEl = document.getElementById('user-mgmt-content');
                    if (contentEl) self.loadUsers(contentEl);
                }, 1000);
            } else {
                resultEl.className = 'settings-result error';
                resultEl.textContent = result.body.detail || result.body.error || 'Failed to create user';
            }
        }).catch(function (err) {
            resultEl.className = 'settings-result error';
            resultEl.textContent = err.message || 'Network error';
        }).finally(function () {
            submitBtn.disabled = false;
            submitBtn.textContent = 'Create';
        });
    },

    handleUserAction: function (action, userId, btn) {
        var auth = window.SentinelAuth;
        if (!auth) return;

        if (action === 'revoke') {
            if (!confirm('Revoke all sessions for user ' + userId + '? They will need to log in again.')) return;

            btn.disabled = true;
            btn.textContent = 'Revoking...';

            fetch('/api/auth/revoke-sessions/' + userId, {
                method: 'POST',
                headers: auth.getAuthHeaders()
            }).then(function (resp) {
                auth.handleAuthResponse(resp);
                if (!resp.ok) throw new Error('Failed to revoke sessions');
                return resp.json();
            }).then(function () {
                btn.textContent = 'Revoked';
                setTimeout(function () {
                    btn.disabled = false;
                    btn.textContent = 'Revoke Sessions';
                }, 2000);
            }).catch(function (err) {
                btn.disabled = false;
                btn.textContent = 'Revoke Sessions';
                btn.textContent = err.message || 'Failed to revoke sessions';
                setTimeout(function () { btn.textContent = 'Revoke Sessions'; }, 3000);
            });
        }
    },

    loadSessions: function (el) {
        el.innerHTML =
            '<div class="settings-placeholder">' +
                '<p>Session management coming soon.</p>' +
                '<p class="settings-hint">View active sessions, IP addresses, and expiry times.</p>' +
            '</div>';
    },

    loadCredentials: function (el) {
        el.innerHTML =
            '<div class="settings-placeholder">' +
                '<p>Credential management coming soon.</p>' +
                '<p class="settings-hint">Manage API keys and service credentials.</p>' +
            '</div>';
    },

    // ── must_change_pin check ───────────────────────────────────

    checkMustChangePin: function () {
        var auth = window.SentinelAuth;
        if (!auth || !auth.getToken()) return;

        fetch('/api/auth/me', {
            headers: auth.getAuthHeaders()
        }).then(function (resp) {
            auth.handleAuthResponse(resp);
            if (!resp.ok) return;
            return resp.json();
        }).then(function (data) {
            if (!data) return;
            var banner = document.getElementById('pin-banner');
            if (banner && data.must_change_pin) {
                banner.style.display = 'block';
            }
        }).catch(function () {
            // Silently ignore — banner stays hidden
        });
    },

    // ── Utility ─────────────────────────────────────────────────

    escapeHtml: function (str) {
        var div = document.createElement('div');
        div.textContent = str || '';
        return div.innerHTML;
    }
};

document.addEventListener('DOMContentLoaded', function () {
    Settings.init();
});
