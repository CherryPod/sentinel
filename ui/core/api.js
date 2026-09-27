/**
 * API client — centralised fetch helpers with auth and error handling.
 *
 * Call sites use apiGet('path'), apiPost('path', body) etc.
 * The '/api/' prefix is added automatically.
 *
 * Auth is handled via HttpOnly session cookies — the browser sends them
 * automatically on same-origin requests. No explicit auth headers needed.
 */

export const ENDPOINTS = {
  health: 'health',
  authLogin: 'auth/login',
  authLogout: 'auth/logout',
  authMe: 'auth/me',
  authChangePin: 'auth/change-pin',
  task: 'task',
  memory: 'memory',
  routine: 'routine',
  settings: 'settings',
  users: 'users',
  metrics: 'metrics',
  session: 'session',
  confirm: 'confirm',
  approve: 'approve',
  approval: 'approval',
};

import { handleAuthResponse } from './auth.js';

export class ApiError extends Error {
  constructor(status, body) {
    const reason = body && (body.reason || body.detail || body.error);
    super(reason || `Request failed (HTTP ${status})`);
    this.name = 'ApiError';
    this.status = status;
    this.body = body;
  }
}

export function rejectOnError(resp) {
  if (resp.ok) return resp;
  const contentType = resp.headers.get('content-type') || '';
  if (contentType.includes('application/json')) {
    return resp.json().then((body) => {
      throw new ApiError(resp.status, body);
    });
  }
  return resp.text().then((text) => {
    throw new ApiError(resp.status, { reason: text.substring(0, 200) });
  });
}

function parseJsonResponse(resp) {
  const contentType = resp.headers.get('content-type') || '';
  if (!contentType.includes('application/json')) {
    return resp.text().then((text) => {
      throw new Error(`Non-JSON response (HTTP ${resp.status}): ${text.substring(0, 200)}`);
    });
  }
  return resp.json();
}

export function apiPost(path, body) {
  return fetch(`/api/${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
    .then(handleAuthResponse)
    .then(rejectOnError)
    .then(parseJsonResponse);
}

export function apiGet(path) {
  return fetch(`/api/${path}`).then(handleAuthResponse).then(rejectOnError).then(parseJsonResponse);
}

export function apiPatch(path, body) {
  return fetch(`/api/${path}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
    .then(handleAuthResponse)
    .then(rejectOnError)
    .then(parseJsonResponse);
}

export function apiDelete(path) {
  return fetch(`/api/${path}`, { method: 'DELETE' })
    .then(handleAuthResponse)
    .then(rejectOnError)
    .then(parseJsonResponse);
}
