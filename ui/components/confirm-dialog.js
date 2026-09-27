/**
 * Accessible confirmation dialog — replaces native confirm().
 *
 * Returns a Promise<boolean> so callers can await the user's choice.
 * Supports focus trapping, Escape to cancel, overlay click to cancel,
 * and danger styling for destructive actions.
 */

/**
 * Show a confirmation dialog and resolve with the user's choice.
 *
 * @param {string} message - The question to display.
 * @param {object} [options]
 * @param {string} [options.confirmText='Confirm'] - Label for the confirm button.
 * @param {string} [options.cancelText='Cancel'] - Label for the cancel button.
 * @param {boolean} [options.danger=false] - When true, styles the confirm button red.
 * @returns {Promise<boolean>} true if confirmed, false if cancelled.
 */
export function confirmDialog(message, options = {}) {
  const confirmText = options.confirmText || 'Confirm';
  const cancelText = options.cancelText || 'Cancel';
  const danger = options.danger || false;

  return new Promise((resolve) => {
    // Build DOM
    const overlay = document.createElement('div');
    overlay.className = 'confirm-overlay';

    const msgId = `confirm-msg-${Date.now()}`;

    const dialog = document.createElement('div');
    dialog.className = 'confirm-dialog';
    dialog.setAttribute('role', 'alertdialog');
    dialog.setAttribute('aria-modal', 'true');
    dialog.setAttribute('aria-label', 'Confirmation');
    dialog.setAttribute('aria-describedby', msgId);
    const msg = document.createElement('p');
    msg.className = 'confirm-message';
    msg.id = msgId;
    msg.textContent = message;

    const actions = document.createElement('div');
    actions.className = 'confirm-actions';

    const cancelBtn = document.createElement('button');
    cancelBtn.className = 'confirm-btn confirm-btn-cancel';
    cancelBtn.textContent = cancelText;

    const confirmBtn = document.createElement('button');
    confirmBtn.className = `confirm-btn ${danger ? 'confirm-btn-danger' : 'confirm-btn-confirm'}`;
    confirmBtn.textContent = confirmText;

    actions.appendChild(cancelBtn);
    actions.appendChild(confirmBtn);
    dialog.appendChild(msg);
    dialog.appendChild(actions);
    overlay.appendChild(dialog);
    document.body.appendChild(overlay);

    // Focus the confirm button on open
    confirmBtn.focus();

    // Cleanup helper — removes DOM and all listeners
    function cleanup() {
      overlay.removeEventListener('click', onOverlayClick);
      document.removeEventListener('keydown', onKeydown);
      overlay.remove();
    }

    function close(result) {
      cleanup();
      resolve(result);
    }

    // Button clicks
    confirmBtn.addEventListener('click', () => close(true));
    cancelBtn.addEventListener('click', () => close(false));

    // Overlay click (outside dialog) → cancel
    function onOverlayClick(e) {
      if (e.target === overlay) close(false);
    }
    overlay.addEventListener('click', onOverlayClick);

    // Keyboard: Escape → cancel, Tab → focus trap
    function onKeydown(e) {
      if (e.key === 'Escape') {
        e.preventDefault();
        close(false);
        return;
      }

      // Focus trap between cancel and confirm buttons
      if (e.key === 'Tab') {
        const focusable = [cancelBtn, confirmBtn];
        const active = document.activeElement;
        const idx = focusable.indexOf(active);

        if (e.shiftKey) {
          // Shift+Tab: move backwards, wrap to end
          e.preventDefault();
          const prev = idx <= 0 ? focusable.length - 1 : idx - 1;
          focusable[prev].focus();
        } else {
          // Tab: move forwards, wrap to start
          e.preventDefault();
          const next = idx >= focusable.length - 1 ? 0 : idx + 1;
          focusable[next].focus();
        }
      }
    }
    document.addEventListener('keydown', onKeydown);
  });
}
