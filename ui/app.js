/**
 * Sentinel UI — application shell.
 *
 * Bootstraps the router, health check, dark mode, and form submission.
 * All view-specific logic lives in views/ modules that self-register
 * with the router on import.
 *
 * Phase 2b: chat view extracted to views/chat/. app.js is now the
 * shell — theme, health, input delegation, init.
 */

import { updateThemeColor } from './brand.js';
import { isAuthenticated } from './core/auth.js';
import { HEALTH_CHECK_INTERVAL_MS, THEME_KEY } from './core/constants.js';
import { capture } from './core/errors.js';
import { applyPrecise } from './core/precise.js';
import { initRouter, registerView } from './core/router.js';
import { get as getState, set as setState, subscribe } from './core/state.js';
import { getTransportType, scheduleInit } from './core/transport.js';

// Import view modules — each self-registers with the router on load
import './views/dashboard/dashboard.js';
import { sendTask } from './views/chat/chat.js';
import './views/memory/memory.js';
import './views/routines/routines.js';
import './views/logs/logs.js';
import './views/activity/activity.js';

// Lazy-loaded, role-gated views — registered with metadata only, module
// fetched via dynamic import() on first navigation. Not downloaded for
// users who lack the required role.
registerView({
  id: 'admin',
  label: 'Admin',
  icon:
    '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2">' +
    '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>' +
    '<path d="M9 12l2 2 4-4"/>' +
    '</svg>',
  navOrder: 7,
  roles: ['admin', 'owner'],
  lazy: '/views/admin/admin.js',
});

// ── DOM references ──────────────────────────────────────────
const form = document.getElementById('input-form');
const input = document.getElementById('task-input');
const sendBtn = document.getElementById('send-btn');
const statusDot = document.getElementById('status-dot');
const statusText = document.getElementById('status-text');

// ── Connection status (shell indicator) ─────────────────────
// Single subscriber for the connectionStatus state key — both transport
// layer and health check update this key, and this subscriber renders
// the status dot/text. Replaces two independent writers that could race.

subscribe('connectionStatus', (status) => {
  const label =
    status === 'ws'
      ? 'Online (WS)'
      : status === 'sse'
        ? 'Online (SSE)'
        : status === 'http'
          ? 'Online (polling)'
          : status === 'unhealthy'
            ? 'Unhealthy'
            : 'Offline';
  statusText.textContent = label;
  statusDot.className = `status-dot ${status === 'ws' || status === 'sse' || status === 'http' ? 'healthy' : 'error'}`;
});

// ── Health check ────────────────────────────────────────────

function checkHealth() {
  // Health endpoint is exempt from auth on server — cookie sent automatically.
  fetch('/api/health')
    .then((resp) => resp.json())
    .then((data) => {
      setState('lastHealthData', data);
      if (data.status === 'ok') {
        if (!isAuthenticated()) {
          window.location.href = '/login.html';
          return;
        }
        // If transport hasn't established yet, show generic 'Online' via 'http'.
        // If transport is already 'ws', don't downgrade the status.
        if (!getTransportType()) setState('connectionStatus', 'http');
        if (!getState('isProcessing')) {
          input.disabled = false;
          sendBtn.disabled = false;
        }
        if (!getState('isProcessing') && getState('currentView') === 'chat') {
          input.focus();
        }
      } else {
        setState('connectionStatus', 'unhealthy');
      }
      // Dashboard subscribes to lastHealthData state changes
    })
    .catch((err) => {
      setState('connectionStatus', 'offline');
      setState('lastHealthData', null);
      capture({ component: 'health', action: 'checkHealth', error: err });
    });
}

// ── Dark mode toggle ────────────────────────────────────────

const themeToggleBtn = document.getElementById('theme-toggle-btn');

function getPreferredTheme() {
  const stored = localStorage.getItem(THEME_KEY);
  if (stored === 'dark' || stored === 'light') return stored;
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  // Swap toggle icons
  const lightIcon = themeToggleBtn.querySelector('.theme-icon-light');
  const darkIcon = themeToggleBtn.querySelector('.theme-icon-dark');
  if (lightIcon && darkIcon) {
    lightIcon.style.display = theme === 'dark' ? 'none' : '';
    darkIcon.style.display = theme === 'dark' ? '' : 'none';
  }
  // Update meta theme-color for mobile browser chrome
  updateThemeColor();
}

function toggleTheme() {
  const current = document.documentElement.getAttribute('data-theme') || getPreferredTheme();
  const next = current === 'dark' ? 'light' : 'dark';
  localStorage.setItem(THEME_KEY, next);
  applyTheme(next);
}

// Listen for OS theme changes (only applies if user hasn't set explicit preference)
window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
  if (!localStorage.getItem(THEME_KEY)) {
    applyTheme(e.matches ? 'dark' : 'light');
  }
});

if (themeToggleBtn) {
  themeToggleBtn.addEventListener('click', toggleTheme);
}

// Apply theme immediately to avoid flash
applyTheme(getPreferredTheme());

// Apply precise-mode body class from localStorage (presentation only)
applyPrecise();

// ── Init ────────────────────────────────────────────────────

// Form submit delegates to the chat view's sendTask
form.addEventListener('submit', (e) => {
  e.preventDefault();
  const text = input.value.trim();
  if (!text) return;
  if (getState('isProcessing')) return;
  input.value = '';
  sendTask(text);
});

// Initialise router — views are already registered via import side effects.
// Default view is 'chat'; hash routing overrides if present.
initRouter({ defaultView: 'chat' });
checkHealth();
scheduleInit();
const _healthIntervalId = setInterval(checkHealth, HEALTH_CHECK_INTERVAL_MS);
