/**
 * Auth module — HttpOnly cookie authentication.
 *
 * The JWT lives in an HttpOnly cookie (set by the server, not readable by JS).
 * A companion `sentinel_auth` cookie (non-HttpOnly) indicates login status
 * for client-side routing decisions. The real auth is always the server-side
 * cookie check — the flag is a UX hint only.
 *
 * Phase 1c: replaces the localStorage-based token management from Phase 1a.
 */

import { capture } from './errors.js';

const AUTH_FLAG = 'sentinel_auth';

/**
 * Check if the user appears to be logged in (non-HttpOnly flag cookie).
 * This is a UX hint — the server enforces real auth via the HttpOnly cookie.
 */
export function isAuthenticated() {
  return document.cookie.split(';').some((c) => c.trim().startsWith(`${AUTH_FLAG}=`));
}

/**
 * Clear the client-readable auth flag and display data.
 * The server clears the HttpOnly session cookie via Set-Cookie on logout.
 */
export function clearAuth() {
  // biome-ignore lint/suspicious/noDocumentCookie: intentional — clearing auth flag cookie
  document.cookie = `${AUTH_FLAG}=; Path=/; Max-Age=0`;
  localStorage.removeItem('sentinel-display-name');
}

/**
 * Log out: revoke the session on the server, clear client auth state,
 * and redirect to login. Falls back to client-only logout if the
 * server request fails (e.g. network error).
 */
export function logout() {
  fetch('/api/auth/logout', { method: 'POST' })
    .catch((err) => {
      capture({
        component: 'auth',
        action: 'logout',
        error: err,
        context: { detail: 'server unreachable, proceeding with client-only logout' },
      });
    })
    .finally(() => {
      clearAuth();
      window.location.href = '/login.html';
    });
}

/**
 * Handle 401 responses by clearing auth state and redirecting to login.
 * With HttpOnly cookies, there is no token refresh to handle client-side —
 * the server slides the cookie automatically via Set-Cookie.
 */
export function handleAuthResponse(resp) {
  if (resp.status === 401) {
    clearAuth();
    window.location.href = '/login.html';
    // Suspend the promise chain while the page navigates away —
    // prevents downstream .then() from running on the 401 body.
    return new Promise(() => {});
  }
  return resp;
}
