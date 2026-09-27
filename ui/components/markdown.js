/**
 * Markdown renderer with defence-in-depth sanitisation.
 *
 * Uses marked.js (loaded as a global <script>) for parsing, then walks
 * the resulting DOM to strip dangerous elements and attributes.  The
 * worker LLM is assumed hostile — crafted class/id values could
 * overlay approval buttons via CSS hijacking, so those attributes are
 * removed unconditionally.
 */

import { capture } from '../core/errors.js';
import { escapeHtml, isSafeUrl } from '../core/text.js';

// Tags allowed in rendered markdown — everything else is stripped
const SAFE_TAGS =
  /^(p|br|strong|em|b|i|code|pre|ul|ol|li|h[1-6]|blockquote|a|hr|table|thead|tbody|tr|th|td|del|sup|sub|span|div)$/i;

// Per-tag attribute allowlist. Tags absent from this map have no allowed attributes.
// target and rel on <a> are set programmatically after the allowlist pass.
// div and span are allowed for structural nesting only — no attributes permitted.
// Do NOT add class/style/id here: crafted values can overlay approval buttons via CSS.
// align on th/td: deprecated HTML4 layout hint; marked emits it for GFM column alignment.
//   Values are coerced by browsers to left/center/right/justify/char or treated as absent.
// start on ol: marked emits it when a list begins at a non-1 index; browsers parse as int.
// title on a: marked emits it for [text](url "title") syntax; rendered as tooltip text only.
//   Not an execution context. A hostile worker could craft a deceptive tooltip string but
//   this is a UI-deception risk (lower severity than XSS), not a code-execution vector.
const ATTR_ALLOWLIST = {
  a:  new Set(['href', 'title']),
  ol: new Set(['start']),
  td: new Set(['colspan', 'rowspan', 'align']),
  th: new Set(['colspan', 'rowspan', 'align']),
};

/**
 * Parse markdown text to raw HTML using marked.js.
 * Returns null if marked is unavailable or parsing fails.
 */
function parseMarkdown(text) {
  if (typeof marked === 'undefined' || !marked.parse) return null;
  try {
    return marked.parse(text, { breaks: true, gfm: true });
  } catch (e) {
    capture({ component: 'markdown', action: 'parseMarkdown', error: e });
    return null;
  }
}

/**
 * Remove dangerous elements from a DOM container.
 * Eagerly removes script, style, iframe, object, embed, svg, math, link,
 * meta, base, form, interactive form elements, noscript, template, and all
 * resource-bearing media elements (img, video, audio, source, track).
 * Elements not matching SAFE_TAGS are replaced with their text content.
 */
function stripDangerousElements(container) {
  const dangerous = container.querySelectorAll(
    'script,style,iframe,object,embed,svg,math,link,meta,base,form,input,textarea,select,button,noscript,template,img,video,audio,source,track',
  );
  for (let i = dangerous.length - 1; i >= 0; i--) {
    dangerous[i].remove();
  }

  const all = container.querySelectorAll('*');
  for (let j = 0; j < all.length; j++) {
    const el = all[j];
    if (!SAFE_TAGS.test(el.tagName.toLowerCase())) {
      el.replaceWith(el.ownerDocument.createTextNode(el.textContent));
    }
  }
}

/**
 * Enforce attribute allowlist on all elements in a container.
 * Only explicitly allowed attributes survive (ATTR_ALLOWLIST).
 * Sanitises href values via isSafeUrl; forces safe link attrs.
 */
function sanitiseAttributes(container) {
  const all = container.querySelectorAll('*');
  for (let j = 0; j < all.length; j++) {
    const el = all[j];
    const tag = el.tagName.toLowerCase();
    const allowed = ATTR_ALLOWLIST[tag] || null;
    const attrs = el.attributes;
    for (let k = attrs.length - 1; k >= 0; k--) {
      const name = attrs[k].name.toLowerCase();
      if (!allowed || !allowed.has(name)) {
        el.removeAttribute(attrs[k].name);
      }
    }
    if (tag === 'a') {
      const href = el.getAttribute('href');
      if (href !== null && !isSafeUrl(href)) {
        el.setAttribute('href', '#');
      }
      el.setAttribute('target', '_blank');
      el.setAttribute('rel', 'noopener noreferrer');
    }
  }
}

/**
 * Render markdown text to sanitised HTML.
 * Falls back to escaped plaintext if marked.js is unavailable.
 */
export function renderMarkdown(text) {
  const html = parseMarkdown(text);
  if (html === null) return escapeHtml(text);
  const doc = new DOMParser().parseFromString(html, 'text/html');
  stripDangerousElements(doc.body);
  sanitiseAttributes(doc.body);
  return doc.body.innerHTML;
}
