/**
 * Login page — authenticates via POST, server sets HttpOnly session cookie.
 *
 * The server response sets two cookies:
 *   - `session` (HttpOnly) — the JWT, not readable by JS
 *   - `sentinel_auth` (non-HttpOnly) — flag for client-side routing
 *
 * The response body contains display_name for the nav bar (stored in
 * localStorage for display only — not used for auth).
 */

import { cherrySvg } from './assets/cherry.js';
import { isAuthenticated } from './core/auth.js';

// If already authenticated, redirect to main UI
if (isAuthenticated()) {
  window.location.href = '/';
}

const form = document.getElementById('login-form');
const usernameInput = document.getElementById('username');
const pinInput = document.getElementById('pin');
const loginBtn = document.getElementById('login-btn');
const errorEl = document.getElementById('login-error');
const loginCherry = document.getElementById('login-cherry');

if (loginCherry) {
  loginCherry.innerHTML = cherrySvg('idle', 72);
}

form.addEventListener('submit', (e) => {
  e.preventDefault();
  errorEl.textContent = '';

  const username = usernameInput.value.trim();
  const pin = pinInput.value;

  if (!username) {
    errorEl.textContent = 'Username is required';
    usernameInput.focus();
    return;
  }
  if (!pin) {
    errorEl.textContent = 'PIN is required';
    pinInput.focus();
    return;
  }

  loginBtn.disabled = true;
  loginBtn.textContent = 'Signing in...';

  fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: username, pin: pin }),
  })
    .then((resp) => {
      if (resp.ok) return resp.json();
      return resp.json().then((body) => {
        throw new Error(body.reason || body.detail || 'Invalid credentials');
      });
    })
    .then((data) => {
      // Server set the session cookie via Set-Cookie header.
      // Store display_name in localStorage for the nav bar (display only).
      if (data?.display_name) {
        localStorage.setItem('sentinel-display-name', data.display_name);
      }
      window.location.href = '/';
    })
    .catch((err) => {
      const msg = err.message || 'Login failed';
      errorEl.textContent = msg;
      console.error('Login error:', msg, err);
      loginBtn.disabled = false;
      loginBtn.textContent = 'Sign in';
    });
});

usernameInput.focus();
