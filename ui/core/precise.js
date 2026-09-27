// @ts-check
/**
 * Precise mode — progressive disclosure of operator data (raw values,
 * risk scores, TL codes, session internals). PRESENTATION ONLY: server
 * authz is unchanged; anything precise mode reveals was already in the
 * payloads. Persisted per-browser in localStorage.
 */

const KEY = 'sentinel-precise-mode';

/** @returns {boolean} */
export function isPrecise() {
  return localStorage.getItem(KEY) === '1';
}

/** @param {boolean} on */
export function setPrecise(on) {
  localStorage.setItem(KEY, on ? '1' : '0');
  applyPrecise();
}

/** Apply the body class that .precise-only CSS keys on. */
export function applyPrecise() {
  document.body.classList.toggle('precise', isPrecise());
}
