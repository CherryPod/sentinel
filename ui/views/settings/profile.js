/**
 * Settings — Profile tab, PIN change, Preferences tab, must-change-PIN banner.
 *
 * Imported by the settings shell (settings.js). All rendering functions
 * receive the container element from the shell's tab router.
 */

import { handleAuthResponse, logout } from '../../core/auth.js';
import { capture } from '../../core/errors.js';
import { isPrecise, setPrecise } from '../../core/precise.js';
import { setUserRole } from './settings.js';

// ── Cached state ───────────────────────────────────────────
let _profile = null;

// ── Profile Tab ────────────────────────────────────────────

function buildProfileHtml() {
  return (
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
    '<div class="settings-label" id="pin-change-heading">Change PIN</div>' +
    '<div class="pin-change-form" role="group" aria-labelledby="pin-change-heading">' +
    '<label for="pin-current" class="sr-only">Current PIN</label>' +
    '<input type="password" id="pin-current" class="settings-input" placeholder="Current PIN" autocomplete="current-password" maxlength="20">' +
    '<label for="pin-new" class="sr-only">New PIN</label>' +
    '<input type="password" id="pin-new" class="settings-input" placeholder="New PIN" autocomplete="new-password" maxlength="20">' +
    '<label for="pin-confirm" class="sr-only">Confirm New PIN</label>' +
    '<input type="password" id="pin-confirm" class="settings-input" placeholder="Confirm New PIN" autocomplete="new-password" maxlength="20">' +
    '<button class="btn btn-primary" id="pin-change-btn">Change PIN</button>' +
    '<div class="settings-result" id="pin-result" aria-live="polite"></div>' +
    '</div>' +
    '</div>' +
    '<div class="settings-section settings-logout">' +
    '<button class="btn btn-deny" id="logout-btn">Log Out</button>' +
    '</div>'
  );
}

function bindProfileEvents() {
  const pinBtn = document.getElementById('pin-change-btn');
  if (pinBtn) {
    pinBtn.addEventListener('click', () => {
      changePin();
    });
  }

  const logoutBtn = document.getElementById('logout-btn');
  if (logoutBtn) {
    logoutBtn.addEventListener('click', () => {
      logout();
    });
  }

  const pinConfirm = document.getElementById('pin-confirm');
  if (pinConfirm) {
    pinConfirm.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') changePin();
    });
  }

  loadProfile();
}

export function renderProfile(el) {
  el.innerHTML = buildProfileHtml();
  bindProfileEvents();
}

function renderProfileData(data) {
  const nameEl = document.getElementById('profile-name');
  const roleEl = document.getElementById('profile-role');
  const trustEl = document.getElementById('profile-trust');

  if (nameEl) nameEl.textContent = data.display_name || '--';
  if (roleEl) roleEl.textContent = (data.role || 'user').charAt(0).toUpperCase() + (data.role || 'user').slice(1);
  if (trustEl) trustEl.textContent = data.trust_level != null ? `TL${data.trust_level}` : 'Default';
}

function loadProfile() {
  // Use cached data from fetchAuthMe if available
  if (_profile) {
    renderProfileData(_profile);
    return;
  }
  // Fallback: fetch directly (shouldn't happen in normal flow)
  fetch('/api/auth/me')
    .then(handleAuthResponse)
    .then((resp) => {
      if (!resp.ok) return null;
      return resp.json();
    })
    .then((data) => {
      if (!data) return;
      _profile = data;
      if (data.role) setUserRole(data.role);
      renderProfileData(data);
    })
    .catch((err) => {
      const nameEl = document.getElementById('profile-name');
      if (nameEl) nameEl.textContent = localStorage.getItem('sentinel-display-name') || '--';
      capture({ component: 'settings.profile', action: 'loadProfile', error: err });
    });
}

/**
 * Validate PIN change inputs. Returns an error message string if
 * validation fails, or null if all inputs are valid.
 */
function validatePinInputs(current, newPin, confirm) {
  if (!current || !newPin || !confirm) return 'All fields are required';
  if (newPin !== confirm) return 'New PINs do not match';
  if (newPin.length < 4) return 'PIN must be at least 4 characters';
  return null;
}

/**
 * Submit the PIN change request and update the UI with the result.
 * Handles fetch, auth response check, success/error display, and cleanup.
 */
function submitPinChange(current, newPin, els) {
  els.btn.disabled = true;
  els.btn.textContent = 'Changing...';
  els.resultEl.className = 'settings-result';
  els.resultEl.textContent = '';

  fetch('/api/auth/change-pin', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ current_pin: current, new_pin: newPin }),
  })
    .then((resp) => {
      return handleAuthResponse(resp);
    })
    .then((resp) => {
      return resp.json().then((body) => ({ ok: resp.ok, body: body }));
    })
    .then((result) => {
      if (result.ok) {
        els.resultEl.className = 'settings-result success';
        els.resultEl.textContent = 'PIN changed successfully';
        els.currentPin.value = '';
        els.newPin.value = '';
        els.confirmPin.value = '';
        // Hide the must-change banner
        const banner = document.getElementById('pin-banner');
        if (banner) banner.style.display = 'none';
      } else {
        els.resultEl.className = 'settings-result error';
        els.resultEl.textContent = result.body.error || result.body.detail || 'Failed to change PIN';
      }
    })
    .catch((err) => {
      els.resultEl.className = 'settings-result error';
      els.resultEl.textContent = err.message || 'Network error';
      capture({ component: 'settings.profile', action: 'changePin', error: err });
    })
    .finally(() => {
      els.btn.disabled = false;
      els.btn.textContent = 'Change PIN';
    });
}

function changePin() {
  const currentPin = document.getElementById('pin-current');
  const newPin = document.getElementById('pin-new');
  const confirmPin = document.getElementById('pin-confirm');
  const resultEl = document.getElementById('pin-result');
  const btn = document.getElementById('pin-change-btn');

  if (!currentPin || !newPin || !confirmPin || !resultEl) return;

  const current = currentPin.value.trim();
  const next = newPin.value.trim();
  const confirm = confirmPin.value.trim();

  const error = validatePinInputs(current, next, confirm);
  if (error) {
    resultEl.className = 'settings-result error';
    resultEl.textContent = error;
    return;
  }

  submitPinChange(current, next, { btn, resultEl, currentPin, newPin, confirmPin });
}

// ── Preferences Tab ────────────────────────────────────────

export function renderPreferences(el) {
  el.innerHTML =
    '<div class="form-group">' +
    '<label for="pref-precise-mode">Precise mode</label>' +
    '<label class="toggle"><input type="checkbox" id="pref-precise-mode"><span class="toggle-slider"></span></label>' +
    '<small class="form-hint">Show operator detail everywhere: raw values, risk scores, trust-level codes, session internals.</small>' +
    '</div>';

  const preciseToggle = document.getElementById('pref-precise-mode');
  if (preciseToggle instanceof HTMLInputElement) {
    preciseToggle.checked = isPrecise();
    preciseToggle.addEventListener('change', () => {
      setPrecise(preciseToggle.checked);
    });
  }
}

// ── Auth/me data receiver (called by settings.js fetchAuthMe) ──

export function onAuthMeLoaded(data) {
  if (!data) return;
  _profile = data;
  if (data.role) setUserRole(data.role);
  renderProfileData(data);
}
