/**
 * Settings — User Management tab (admin/owner only).
 *
 * Lazy-loaded by the settings shell via dynamic import() on first
 * access to the "Users" tab. Never downloaded for non-admin users.
 */

import { confirmDialog } from '../../components/confirm-dialog.js';
import { apiGet, apiPost, ENDPOINTS } from '../../core/api.js';
import { BUTTON_RESET_DELAY_MS } from '../../core/constants.js';
import { capture } from '../../core/errors.js';
import { escapeHtml } from '../../core/ui-helpers.js';

// ── User Management Tab ────────────────────────────────────

function buildUserManagementHtml() {
  return (
    '<div class="user-mgmt-subtabs" id="user-mgmt-subtabs" role="tablist">' +
    '<button class="subtab active" data-subtab="users" role="tab" aria-selected="true">Users</button>' +
    '<button class="subtab" data-subtab="sessions" role="tab" aria-selected="false">Sessions</button>' +
    '<button class="subtab" data-subtab="credentials" role="tab" aria-selected="false">Credentials</button>' +
    '</div>' +
    '<div id="user-mgmt-content" role="tabpanel"></div>'
  );
}

function bindUserManagementEvents(el) {
  const subtabs = el.querySelectorAll('.subtab');
  for (let i = 0; i < subtabs.length; i++) {
    ((btn) => {
      btn.addEventListener('click', () => {
        const all = el.querySelectorAll('.subtab');
        for (let j = 0; j < all.length; j++) {
          all[j].classList.remove('active');
          all[j].setAttribute('aria-selected', 'false');
        }
        btn.classList.add('active');
        btn.setAttribute('aria-selected', 'true');

        const contentEl = document.getElementById('user-mgmt-content');
        if (!contentEl) return;

        const tab = btn.getAttribute('data-subtab');
        switch (tab) {
          case 'users':
            loadUsers(contentEl);
            break;
          case 'sessions':
            loadSessions(contentEl);
            break;
          case 'credentials':
            loadCredentials(contentEl);
            break;
        }
      });
    })(subtabs[i]);
  }

  // Load users by default
  const contentEl = document.getElementById('user-mgmt-content');
  if (contentEl) loadUsers(contentEl);
}

export function renderUserManagement(el) {
  el.innerHTML = buildUserManagementHtml();
  bindUserManagementEvents(el);
}

function buildUserTableHtml(users) {
  let html =
    '<div class="users-header">' +
    '<button class="btn btn-primary" id="new-user-btn">+ New User</button>' +
    '</div>' +
    '<div id="create-user-area"></div>' +
    '<table class="users-table">' +
    '<thead><tr>' +
    '<th>Name</th><th>Role</th><th>Trust</th><th>Status</th><th>Actions</th>' +
    '</tr></thead>' +
    '<tbody>';

  users.forEach((u) => {
    const status = u.is_active ? 'Active' : 'Inactive';
    const statusClass = u.is_active ? 'active' : 'inactive';
    const trust = u.trust_level != null ? `TL${u.trust_level}` : '--';
    const role = (u.role || 'user').charAt(0).toUpperCase() + (u.role || 'user').slice(1);

    html +=
      '<tr>' +
      '<td>' +
      escapeHtml(u.display_name) +
      '</td>' +
      '<td>' +
      escapeHtml(role) +
      '</td>' +
      '<td>' +
      trust +
      '</td>' +
      '<td><span class="user-status ' +
      escapeHtml(statusClass) +
      '">' +
      escapeHtml(status) +
      '</span></td>' +
      '<td>' +
      '<button class="action-btn" data-action="revoke" data-user-id="' +
      escapeHtml(String(u.user_id)) +
      '" title="Revoke all sessions">Revoke Sessions</button>' +
      '</td>' +
      '</tr>';
  });

  html += '</tbody></table>';
  return html;
}

function bindUserTableEvents(el) {
  const newBtn = document.getElementById('new-user-btn');
  if (newBtn) {
    newBtn.addEventListener('click', () => {
      const area = document.getElementById('create-user-area');
      if (area) showCreateUserForm(area);
    });
  }

  const actionBtns = el.querySelectorAll('.action-btn');
  for (let i = 0; i < actionBtns.length; i++) {
    ((btn) => {
      btn.addEventListener('click', () => {
        const action = btn.getAttribute('data-action');
        const userId = btn.getAttribute('data-user-id');
        handleUserAction(action, userId, btn);
      });
    })(actionBtns[i]);
  }
}

function loadUsers(el) {
  el.innerHTML = '<div class="settings-placeholder">Loading users...</div>';

  apiGet(`${ENDPOINTS.users}?active_only=false`)
    .then((users) => {
      el.innerHTML = buildUserTableHtml(users);
      bindUserTableEvents(el);
    })
    .catch((err) => {
      el.innerHTML = `<div class="settings-result error">${escapeHtml(err.message || 'Failed to load users')}</div>`;
      capture({ component: 'settings.admin', action: 'loadUsers', error: err });
    });
}

function showCreateUserForm(el) {
  el.innerHTML =
    '<div class="create-user-form">' +
    '<h3>Create User</h3>' +
    '<div class="form-row">' +
    '<label for="new-user-name">Username</label>' +
    '<input type="text" id="new-user-name" class="settings-input" placeholder="Display name" autocomplete="off">' +
    '</div>' +
    '<div class="form-row">' +
    '<label for="new-user-pin">Temporary PIN</label>' +
    '<input type="password" id="new-user-pin" class="settings-input" placeholder="Initial PIN (optional)" autocomplete="new-password" maxlength="20">' +
    '</div>' +
    '<div class="form-row">' +
    '<label for="new-user-role">Role</label>' +
    '<select id="new-user-role" class="settings-input">' +
    '<option value="user">User</option>' +
    '<option value="admin">Admin</option>' +
    '</select>' +
    '</div>' +
    '<div class="form-row create-user-actions">' +
    '<button class="btn btn-primary" id="create-user-submit">Create</button>' +
    '<button class="btn btn-secondary" id="create-user-cancel">Cancel</button>' +
    '</div>' +
    '<div class="settings-result" id="create-user-result" aria-live="polite"></div>' +
    '</div>';

  const submitBtn = document.getElementById('create-user-submit');
  const cancelBtn = document.getElementById('create-user-cancel');

  if (submitBtn)
    submitBtn.addEventListener('click', () => {
      createUser();
    });
  if (cancelBtn)
    cancelBtn.addEventListener('click', () => {
      el.innerHTML = '';
    });
}

/**
 * Validate create-user form inputs. Returns { name, body } on success,
 * or null if validation fails (shows error in resultEl).
 */
function validateUserInputs(nameInput, pinInput, roleInput, resultEl) {
  const name = nameInput.value.trim();
  if (!name) {
    resultEl.className = 'settings-result error';
    resultEl.textContent = 'Username is required';
    return null;
  }

  const body = { display_name: name };
  if (pinInput?.value.trim()) {
    body.pin = pinInput.value.trim();
  }
  if (roleInput?.value) {
    body.role = roleInput.value;
  }
  return { name, body };
}

/**
 * Submit the create-user request and update the UI with the result.
 * Handles fetch, auth response check, success/error display, and button reset.
 */
function submitCreateUser(body, name, resultEl, submitBtn) {
  submitBtn.disabled = true;
  submitBtn.textContent = 'Creating...';
  resultEl.className = 'settings-result';
  resultEl.textContent = '';

  apiPost(ENDPOINTS.users, body)
    .then((data) => {
      if (data.detail || data.error) {
        resultEl.className = 'settings-result error';
        resultEl.textContent = data.detail || data.error || 'Failed to create user';
      } else {
        resultEl.className = 'settings-result success';
        resultEl.textContent = `User "${name}" created successfully`;
        // Refresh user list after a brief delay
        setTimeout(() => {
          const contentEl = document.getElementById('user-mgmt-content');
          if (contentEl) loadUsers(contentEl);
        }, 1000);
      }
    })
    .catch((err) => {
      resultEl.className = 'settings-result error';
      resultEl.textContent = err.message || 'Network error';
      capture({ component: 'settings.admin', action: 'createUser', error: err });
    })
    .finally(() => {
      submitBtn.disabled = false;
      submitBtn.textContent = 'Create';
    });
}

function createUser() {
  const nameInput = document.getElementById('new-user-name');
  const pinInput = document.getElementById('new-user-pin');
  const roleInput = document.getElementById('new-user-role');
  const resultEl = document.getElementById('create-user-result');
  const submitBtn = document.getElementById('create-user-submit');

  if (!nameInput || !resultEl) return;

  const validated = validateUserInputs(nameInput, pinInput, roleInput, resultEl);
  if (!validated) return;

  submitCreateUser(validated.body, validated.name, resultEl, submitBtn);
}

// ── User action handler registry ────────────────────────────
// Map of action name → handler. New user actions register a handler
// instead of adding an if/else branch to handleUserAction.

const userActions = new Map();

function registerUserAction(actionName, fn) {
  userActions.set(actionName, fn);
}

registerUserAction('revoke', async (userId, btn) => {
  if (
    !(await confirmDialog(`Revoke all sessions for user ${userId}? They will need to log in again.`, {
      danger: true,
      confirmText: 'Revoke',
    }))
  )
    return;

  btn.disabled = true;
  btn.textContent = 'Revoking...';

  apiPost(`auth/revoke-sessions/${userId}`, {})
    .then(() => {
      btn.textContent = 'Revoked';
      setTimeout(() => {
        btn.disabled = false;
        btn.textContent = 'Revoke Sessions';
      }, BUTTON_RESET_DELAY_MS);
    })
    .catch((err) => {
      btn.disabled = false;
      btn.textContent = err.message || 'Failed to revoke sessions';
      capture({ component: 'settings.admin', action: 'revokeSession', error: err, context: { userId: userId } });
      setTimeout(() => {
        btn.textContent = 'Revoke Sessions';
      }, 3000);
    });
});

function handleUserAction(action, userId, btn) {
  const handler = userActions.get(action);
  if (handler) handler(userId, btn);
}

function loadSessions(el) {
  el.innerHTML =
    '<div class="settings-placeholder">' +
    '<p>Session management coming soon.</p>' +
    '<p class="settings-hint">View active sessions, IP addresses, and expiry times.</p>' +
    '</div>';
}

function loadCredentials(el) {
  el.innerHTML =
    '<div class="settings-placeholder">' +
    '<p>Credential management coming soon.</p>' +
    '<p class="settings-hint">Manage API keys and service credentials.</p>' +
    '</div>';
}
