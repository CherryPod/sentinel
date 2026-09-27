// @ts-check
/**
 * <cherry-empty-state pose="sleeping" message="Nothing here yet."></cherry-empty-state>
 * Reusable empty state: Cherry pose plus one warm sentence.
 */

import { cherrySvg } from '../../assets/cherry.js';
import { css, html, LitElement } from '../../vendor/lit.js';

const VALID_POSES = new Set(['idle', 'alert', 'working', 'sleeping']);

/**
 * @param {string} pose
 * @returns {'idle' | 'alert' | 'working' | 'sleeping'}
 */
function normalizePose(pose) {
  return VALID_POSES.has(pose) ? /** @type {'idle' | 'alert' | 'working' | 'sleeping'} */ (pose) : 'sleeping';
}

export class CherryEmptyState extends LitElement {
  static properties = {
    pose: { type: String },
    message: { type: String },
  };

  static styles = css`
    :host {
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 16px;
      padding: 40px 20px;
      color: var(--color-brand-mark);
      text-align: center;
    }

    #cherry {
      line-height: 0;
    }

    p {
      max-width: 320px;
      margin: 0;
      color: var(--text-muted);
      font-size: var(--text-base);
    }
  `;

  constructor() {
    super();
    this.pose = 'sleeping';
    this.message = 'Nothing here yet.';
  }

  render() {
    // The public `pose` attribute is allowlisted (normalizePose) BEFORE it
    // reaches the innerHTML sink; cherrySvg applies the same closed-set
    // validation as a second layer. Built inside render() (not updated()) so
    // the SVG lives in the Lit render path — no timing dependency, no
    // re-injection on unrelated property changes.
    const tpl = document.createElement('template');
    tpl.innerHTML = cherrySvg(normalizePose(this.pose), 72);
    return html`<span aria-hidden="true">${tpl.content}</span><p>${this.message}</p>`;
  }
}

customElements.define('cherry-empty-state', CherryEmptyState);
