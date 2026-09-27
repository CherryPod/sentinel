/**
 * Named constants — replaces magic numbers scattered across app.js.
 * Import individual constants where needed; don't import the whole module.
 */

// Storage keys
export const STORAGE_KEY = 'sentinel-history';
export const SESSION_KEY = 'sentinel-session-id';
export const THEME_KEY = 'sentinel-theme';

// WebSocket
export const WS_AUTH_TIMEOUT_MS = 5000;
export const WS_MAX_RECONNECT = 5;
export const WS_RECONNECT_BASE_MS = 1000;
export const WS_TASK_TIMEOUT_MS = 600000; // 10 min — tasks can take 5+ min through the planner

// Polling
export const POLL_INTERVAL_MS = 2000;
export const POLL_MAX_ATTEMPTS = 150; // 5 minutes at 2s intervals
export const METRICS_POLL_INTERVAL_MS = 60000;
export const HEALTH_CHECK_INTERVAL_MS = 30000;

// UI limits
export const MAX_HISTORY_ENTRIES = 100;
export const MAX_VISIBLE_TOASTS = 3;
export const TOAST_AUTO_DISMISS_MS = 4000;
export const TOAST_ANIMATION_DELAY_MS = 300;
export const MEMORY_PREVIEW_CHARS = 200;
export const MEMORY_PAGE_SIZE = 20;
export const MEMORY_SEARCH_DEBOUNCE_MS = 300;
export const ROUTINE_HISTORY_LIMIT = 10;
export const UUID_DISPLAY_LENGTH = 8;
export const BUTTON_RESET_DELAY_MS = 2000;
export const TRANSPORT_INIT_DELAY_MS = 1000;
export const LOG_MAX_ENTRIES = 500;
