// @ts-check
/**
 * HTML-escape text for safe innerHTML interpolation.
 *
 * DOM-compatible by contract: reproduces the exact output of the legacy
 * `div.textContent = str; div.innerHTML` approach — escapes ONLY & < >
 * (NOT quotes), maps null/undefined to ''. Verified against Chromium.
 * Do NOT add quote-escaping here: that is a behaviour change to the XSS
 * primitive, tracked separately (escapeAttr / token allowlists) in the
 * plan's Appendix B. It would also alter the double-escape call sites at
 * plan-gate.js (~275) and chat.js (~464).
 *
 * @param {*} str - value to escape (coerced to string; null/undefined → '')
 * @returns {string} HTML-escaped text
 */
export function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

// C0 controls, space (0x20), and DEL (0x7F) — stripped before scheme check.
const UNSAFE_URL_CHARS_RE = /[\x00-\x20\x7F]/g;

/**
 * Return true if rawUrl is safe to use in an href attribute.
 *
 * Strips ASCII control characters and whitespace, then checks the URL
 * scheme against an allowlist (http, https, mailto). Relative paths,
 * fragment-only URLs, empty strings, and protocol-relative URLs (//)
 * are also accepted. Everything else — javascript:, data:, blob:, etc. —
 * is rejected.
 *
 * Requires a decoded URL string (e.g. from el.getAttribute('href')).
 * Does NOT perform HTML entity or percent-decoding itself.
 * Throws TypeError on non-string input (fail-closed on programmer error).
 *
 * @param {string} rawUrl - decoded URL string
 * @returns {boolean}
 */
export function isSafeUrl(rawUrl) {
  const url = rawUrl.replace(UNSAFE_URL_CHARS_RE, '');
  if (url === '' || url.startsWith('#')) return true;
  const colonIdx = url.indexOf(':');
  if (colonIdx < 0) return true;
  const preColon = url.slice(0, colonIdx);
  if (/[/?#]/.test(preColon)) return true;
  const scheme = preColon.toLowerCase();
  return scheme === 'http' || scheme === 'https' || scheme === 'mailto';
}

/**
 * HTML-escape a value for use inside a quoted HTML attribute.
 *
 * Escapes & < > " ' — the five characters that are meaningful in HTML
 * attribute values. Safe for double-quoted or single-quoted attributes.
 * NOT safe for unquoted attribute values (whitespace, backtick, = can
 * also break out there).
 *
 * @param {*} str - value to escape (coerced to string; null/undefined → '')
 * @returns {string} attribute-safe HTML-escaped string
 */
export function escapeAttr(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}
