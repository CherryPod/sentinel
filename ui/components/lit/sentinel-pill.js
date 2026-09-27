// @ts-check
/**
 * <sentinel-pill status="ok|warn|fail|off|info">Healthy</sentinel-pill>
 *
 * Lit exemplar component. Styles are co-located so the class-drift bug class
 * cannot occur here. CSS custom properties still inherit through shadow DOM.
 */

import { css, html, LitElement } from '../../vendor/lit.js';

export class SentinelPill extends LitElement {
  static properties = {
    status: { type: String },
  };

  static styles = css`
    :host {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 2px 12px;
      border-radius: 9999px;
      background: var(--bg-tertiary);
      color: var(--text-secondary);
      font-size: var(--text-sm);
      font-weight: 600;
    }

    :host::before {
      content: '';
      width: 7px;
      height: 7px;
      flex-shrink: 0;
      border-radius: 50%;
      background: currentColor;
    }

    :host([status='ok']) {
      background: var(--green-bg);
      color: var(--green-text);
    }

    :host([status='warn']) {
      background: var(--yellow-bg);
      color: var(--yellow-text);
    }

    :host([status='fail']) {
      background: var(--red-bg);
      color: var(--red);
    }

    :host([status='off']) {
      background: var(--bg-tertiary);
      color: var(--pill-off-text);
    }

    :host([status='info']) {
      background: var(--peri-bg);
      color: var(--peri-text);
    }
  `;

  constructor() {
    super();
    this.status = 'off';
  }

  render() {
    return html`<slot></slot>`;
  }
}

customElements.define('sentinel-pill', SentinelPill);
