/**
 * Settings shell — modal open/close, tab router, ARIA dialog, focus trap.
 *
 * Tab content is delegated to sub-modules:
 *   - profile.js  — Profile + Preferences tabs
 *   - admin-users.js — User Management tab (lazy-loaded, admin/owner only)
 */

import { handleAuthResponse, isAuthenticated } from '../../core/auth.js';
import { capture } from '../../core/errors.js';
import { set as setState } from '../../core/state.js';
import { onAuthMeLoaded, renderPreferences, renderProfile } from './profile.js';

// ── State ──────────────────────────────────────────────────
let currentTab = 'profile';
let userRole = null; // fetched from server, NOT localStorage
let adminModule = null; // lazy-loaded on first Users tab click
let previousFocus = null; // element that had focus before modal opened

// ── Initialisation ─────────────────────────────────────────

function init() {
  const btn = document.getElementById('settings-btn');
  const closeBtn = document.getElementById('settings-close');
  const overlay = document.getElementById('settings-overlay');

  if (btn)
    btn.addEventListener('click', () => {
      open();
    });
  if (closeBtn)
    closeBtn.addEventListener('click', () => {
      close();
    });
  if (overlay) {
    overlay.addEventListener('click', (e) => {
      if (e.target.id === 'settings-overlay') close();
    });
  }

  // Escape key closes settings
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && overlay && overlay.style.display !== 'none') {
      close();
    }
  });

  // Show username in nav from localStorage
  const name = localStorage.getItem('sentinel-display-name');
  const nameEl = document.getElementById('user-display-name');
  if (name && nameEl) nameEl.textContent = name;

  // Single fetch for role, PIN banner, and profile data
  fetchAuthMe();
}

function fetchAuthMe() {
  if (!isAuthenticated()) return;

  fetch('/api/auth/me')
    .then(handleAuthResponse)
    .then((resp) => {
      if (!resp.ok) return null;
      return resp.json();
    })
    .then((data) => {
      if (!data) return;
      // Role (was fetchRole)
      if (data.role) {
        userRole = data.role;
        setState('userRole', data.role);
      }
      // PIN change banner (was checkMustChangePin)
      const banner = document.getElementById('pin-banner');
      if (banner) banner.style.display = data.must_change_pin ? 'block' : 'none';
      // Forward to profile module (was loadProfile)
      onAuthMeLoaded(data);
    })
    .catch((err) => {
      capture({ component: 'settings', action: 'fetchAuthMe', error: err });
    });
}

// ── Open / Close ───────────────────────────────────────────

function open() {
  const overlay = document.getElementById('settings-overlay');
  if (!overlay) return;

  // Save focus for restoration on close
  previousFocus = document.activeElement;

  overlay.style.display = 'flex';
  renderTabs();
  showTab(currentTab);

  // Set initial focus to the close button (first focusable element in dialog)
  const closeBtn = document.getElementById('settings-close');
  if (closeBtn) closeBtn.focus();

  // Install focus trap
  overlay.addEventListener('keydown', trapFocus);
}

function close() {
  const overlay = document.getElementById('settings-overlay');
  if (!overlay) return;

  overlay.style.display = 'none';

  // Remove focus trap
  overlay.removeEventListener('keydown', trapFocus);

  // Restore focus to the element that opened the dialog
  if (previousFocus && typeof previousFocus.focus === 'function') {
    previousFocus.focus();
  }
  previousFocus = null;
}

// ── Focus Trap ─────────────────────────────────────────────

function trapFocus(e) {
  if (e.key !== 'Tab') return;

  const panel = document.querySelector('.settings-panel');
  if (!panel) return;

  const focusable = panel.querySelectorAll('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])');
  if (focusable.length === 0) return;

  const first = focusable[0];
  const last = focusable[focusable.length - 1];

  if (e.shiftKey) {
    // Shift+Tab: wrap from first to last
    if (document.activeElement === first) {
      e.preventDefault();
      last.focus();
    }
  } else {
    // Tab: wrap from last to first
    if (document.activeElement === last) {
      e.preventDefault();
      first.focus();
    }
  }
}

// ── Tab rendering ──────────────────────────────────────────

function getTabDefinitions() {
  const role = userRole || 'user';
  const tabs = [
    { id: 'profile', label: 'Profile' },
    { id: 'preferences', label: 'Preferences' },
  ];
  if (role === 'admin' || role === 'owner') {
    tabs.push({ id: 'users', label: 'User Management' });
  }
  return tabs;
}

function renderTabs() {
  const tabsEl = document.getElementById('settings-tabs');
  if (!tabsEl) return;

  tabsEl.innerHTML = '';
  for (const tab of getTabDefinitions()) {
    const btn = document.createElement('button');
    btn.className = `settings-tab${tab.id === currentTab ? ' active' : ''}`;
    btn.textContent = tab.label;
    btn.setAttribute('role', 'tab');
    btn.setAttribute('aria-selected', tab.id === currentTab ? 'true' : 'false');
    btn.setAttribute('aria-controls', 'settings-content');
    btn.addEventListener('click', () => {
      showTab(tab.id);
    });
    tabsEl.appendChild(btn);
  }
}

function showTab(name) {
  currentTab = name;
  const contentEl = document.getElementById('settings-content');
  if (!contentEl) return;
  contentEl.innerHTML = '';

  renderTabs();

  switch (name) {
    case 'profile':
      renderProfile(contentEl);
      break;
    case 'preferences':
      renderPreferences(contentEl);
      break;
    case 'users':
      loadAdminModule(contentEl);
      break;
  }
}

// ── Lazy-load admin module ─────────────────────────────────

function loadAdminModule(contentEl) {
  if (adminModule) {
    adminModule.renderUserManagement(contentEl);
    return;
  }

  contentEl.innerHTML = '<div class="settings-placeholder">Loading...</div>';

  import('./admin-users.js')
    .then((mod) => {
      adminModule = mod;
      mod.renderUserManagement(contentEl);
    })
    .catch((err) => {
      contentEl.innerHTML = '<div class="settings-result error">Failed to load user management</div>';
      capture({ component: 'settings', action: 'loadAdminModule', error: err });
    });
}

// ── Role setter (called by profile.js when /api/auth/me returns) ──

function setUserRole(role) {
  userRole = role;
}

// ── Exports (for testing / external access if needed) ──────

export { close, fetchAuthMe, open, setUserRole };

// ES modules are deferred — DOM is ready when this runs
init();
