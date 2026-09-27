/**
 * Structured error capture — console + optional backend telemetry.
 *
 * Every catch block should call errors.capture() with context instead
 * of bare console.error(). This centralises error formatting and
 * allows wiring a backend endpoint later without touching call sites.
 */

/**
 * Capture a structured error.
 *
 * @param {Object} opts
 * @param {string} opts.component - Module or view that caught the error (e.g. 'chat', 'api')
 * @param {string} opts.action - What was being attempted (e.g. 'sendTask', 'loadMemory')
 * @param {Error|string} opts.error - The caught error
 * @param {Object} [opts.context] - Additional context (task ID, endpoint, etc.)
 */
export function capture({ component, action, error, context }) {
  const message = error instanceof Error ? error.message : String(error);
  const stack = error instanceof Error ? error.stack : undefined;

  const entry = {
    component: component,
    action: action,
    message: message,
    context: context || {},
    timestamp: new Date().toISOString(),
  };

  // Always log to console with full detail
  console.error(`[${component}.${action}]`, message, entry);
  if (stack) console.debug(`[${component}.${action}] stack:`, stack);

  // Future: POST to /api/telemetry/error for backend aggregation
  // This is a stub — wired when the backend endpoint exists.
}

/**
 * Wrap a promise chain with structured error capture.
 * Returns the original promise — errors are captured but still propagate.
 */
export function wrapAsync(component, action, promise) {
  return promise.catch((err) => {
    capture({ component: component, action: action, error: err });
    throw err;
  });
}
