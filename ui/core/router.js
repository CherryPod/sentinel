/**
 * View registry and router.
 *
 * Views self-register via registerView(). The router manages:
 *   - Nav rail generation from registered views
 *   - View switching (active class, load/unload lifecycle)
 *   - Keyboard shortcuts (Ctrl+1-9, Escape → chat)
 *   - Hash-based deep linking (#dashboard, #memory, etc.)
 *
 * Adding a new view = calling registerView() in the view module.
 * Zero changes to this file or index.html.
 *
 * Usage:
 *   import { registerView, showView } from './core/router.js';
 *   registerView({
 *       id: 'dashboard',
 *       label: 'Dashboard',
 *       icon: '<svg>...</svg>',
 *       navOrder: 1,
 *       render(container) { container.innerHTML = '...'; },
 *       load() { // called each time view becomes active },
 *       unload() { // cleanup — abort controllers, clear intervals },
 *   });
 */

import { capture } from './errors.js';
import { get as getState, set as setState, subscribe } from './state.js';

// ── Registry ─────────────────────────────────────────────────

const views = new Map();
let viewContainer = null;
let navItemsContainer = null;
let inputBar = null;
const rendered = new Set();
let routerInitialised = false;

/**
 * Register a view module.
 *
 * @param {Object} opts
 * @param {string} opts.id - Unique view identifier (used in URL hash and data attributes)
 * @param {string} opts.label - Display label for nav rail
 * @param {string} opts.icon - SVG string for nav icon
 * @param {number} opts.navOrder - Sort order in nav rail (lower = higher)
 * @param {string[]} [opts.roles] - Required roles (empty = all users)
 * @param {Function} opts.render - Called once: render(container) populates the view's DOM
 * @param {Function} [opts.load] - Called each time the view becomes active (refresh data)
 * @param {Function} [opts.unload] - Called when leaving the view (cleanup)
 */
export function registerView(opts) {
  views.set(opts.id, opts);
}

/**
 * Get a registered view definition by id.
 * @param {string} id
 * @returns {Object|undefined}
 */
export function getView(id) {
  return views.get(id);
}

// ── Helpers ──────────────────────────────────────────────────

/**
 * Get views visible to the current user, sorted by navOrder.
 * Filters out views without navOrder and views requiring roles
 * the current user doesn't have.
 */
function getVisibleViews() {
  const userRole = getState('userRole') || 'user';
  return Array.from(views.values())
    .filter((v) => {
      if (v.navOrder == null) return false;
      if (v.roles && v.roles.length > 0) {
        return v.roles.indexOf(userRole) !== -1;
      }
      return true;
    })
    .sort((a, b) => a.navOrder - b.navOrder);
}

// ── Nav rail ─────────────────────────────────────────────────

function buildNav() {
  if (!navItemsContainer) return;

  const sorted = getVisibleViews();

  // Clear existing nav items (but keep footer items like settings, theme, status)
  navItemsContainer.innerHTML = '';

  for (let i = 0; i < sorted.length; i++) {
    const v = sorted[i];
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'nav-item';
    btn.setAttribute('data-view', v.id);
    btn.setAttribute('title', `${v.label} (Ctrl+${i + 1})`);
    // v.icon is trusted inline SVG from view registration; v.label uses textContent to prevent XSS
    btn.innerHTML = v.icon;
    const navLabel = document.createElement('span');
    navLabel.className = 'nav-label';
    navLabel.textContent = v.label;
    btn.appendChild(navLabel);
    btn.addEventListener(
      'click',
      ((id) => () => {
        showView(id);
      })(v.id),
    );
    navItemsContainer.appendChild(btn);
  }

  // Re-highlight active view in rebuilt nav
  const current = getState('currentView');
  if (current) {
    const activeBtn = navItemsContainer.querySelector(`[data-view="${current}"]`);
    if (activeBtn) {
      activeBtn.classList.add('active');
      activeBtn.setAttribute('aria-current', 'page');
    }
  }
}

// ── View switching ───────────────────────────────────────────

/**
 * Switch to a view by id.
 * Calls unload() on the previous view and load() on the new view.
 * @param {string} viewName
 */
export function showView(viewName) {
  const view = views.get(viewName);
  if (!view) return;

  // Role gate — prevent navigation to role-restricted views via hash,
  // console, or any path that bypasses the nav rail. Defence-in-depth:
  // server-side endpoints also enforce role checks.
  if (view.roles && view.roles.length > 0) {
    const userRole = getState('userRole') || 'user';
    if (view.roles.indexOf(userRole) === -1) return;
  }

  // Lazy views: dynamically import module on first navigation,
  // then re-enter showView once lifecycle hooks are available.
  if (view.lazy && !view.render) {
    loadLazyView(view, viewName);
    return;
  }

  activateView(viewName, view);
}

/**
 * Dynamically import a lazy view module and wire its lifecycle hooks.
 * Shows a loading indicator in the view container while fetching.
 */
function loadLazyView(view, viewName) {
  // Guard against double-import if user navigates to same lazy view twice before first resolves
  if (view._loading) return;
  view._loading = true;

  // Create container early so the user sees a loading state
  const section = ensureViewContainer(viewName);
  if (section) {
    section.classList.add('active');
    section.innerHTML = '<div class="view-loading">Loading...</div>';
  }

  // Hide other views while loading
  const allSections = viewContainer ? viewContainer.querySelectorAll('.view') : [];
  allSections.forEach((s) => {
    if (s.id !== `view-${viewName}`) s.classList.remove('active');
  });

  import(view.lazy)
    .then((mod) => {
      // Wire lifecycle hooks from the loaded module into the view registration
      view.render = mod.render;
      view.load = mod.load || null;
      view.unload = mod.unload || null;

      // Clear loading indicator and activate normally
      if (section) section.innerHTML = '';
      activateView(viewName, view);
    })
    .catch((err) => {
      if (section) {
        section.innerHTML = '<div class="view-loading view-error">Failed to load module</div>';
      }
      capture({ component: 'router', action: 'loadLazyView', error: err, context: { viewName: viewName } });
    })
    .finally(() => {
      view._loading = false;
    });
}

/**
 * Create a view container section if it doesn't exist yet.
 * Inserts before the input bar footer to preserve DOM order.
 */
function ensureViewContainer(viewName) {
  let section = document.getElementById(`view-${viewName}`);
  if (!section && viewContainer) {
    section = document.createElement('section');
    section.id = `view-${viewName}`;
    section.className = 'view';
    section.setAttribute('data-view', viewName);
    const footer = viewContainer.querySelector('#input-bar');
    if (footer) {
      viewContainer.insertBefore(section, footer);
    } else {
      viewContainer.appendChild(section);
    }
  }
  return section;
}

/**
 * Unload the previous view's lifecycle hook (if any).
 * Called during view transitions to let the outgoing view clean up.
 */
function deactivatePreviousView(viewName) {
  const prev = getState('currentView');
  if (prev && prev !== viewName) {
    const prevView = views.get(prev);
    if (prevView?.unload) {
      try {
        prevView.unload();
      } catch (err) {
        console.error(`[router] unload error for ${prev}:`, err);
      }
    }
  }
}

/**
 * Set the active nav item and aria-current attribute.
 * Clears active state from all other nav items.
 */
function updateNavActiveState(viewName) {
  const navItems = document.querySelectorAll('.nav-items .nav-item');
  navItems.forEach((item) => {
    if (item.getAttribute('data-view') === viewName) {
      item.classList.add('active');
      item.setAttribute('aria-current', 'page');
    } else {
      item.classList.remove('active');
      item.removeAttribute('aria-current');
    }
  });
}

/**
 * Hide all view sections, show the target view, and render it on first activation.
 * Returns the active section element (or null).
 */
function switchViewSections(viewName, view) {
  const allSections = viewContainer ? viewContainer.querySelectorAll('.view') : [];
  allSections.forEach((s) => {
    s.classList.remove('active');
  });

  const section = ensureViewContainer(viewName);

  if (section) {
    section.classList.add('active');

    // Render view HTML on first activation
    if (!rendered.has(viewName) && view.render) {
      try {
        view.render(section);
      } catch (err) {
        console.error(`[router] render error for ${viewName}:`, err);
      }
      rendered.add(viewName);
    }
  }
  return section;
}

/**
 * Activate a view — unload previous, switch DOM, render if needed, load data.
 * Shared by both eager and lazy views once lifecycle hooks are available.
 */
function activateView(viewName, view) {
  deactivatePreviousView(viewName);
  updateNavActiveState(viewName);
  switchViewSections(viewName, view);

  // Show/hide input bar (only visible on chat)
  if (inputBar) {
    inputBar.style.display = viewName === 'chat' ? '' : 'none';
  }

  setState('currentView', viewName);

  // Update hash without triggering hashchange
  if (window.location.hash !== `#${viewName}`) {
    history.replaceState(null, '', `#${viewName}`);
  }

  // Run view-specific load (data refresh)
  if (view.load) {
    try {
      view.load();
    } catch (err) {
      console.error(`[router] load error for ${viewName}:`, err);
    }
  }
}

// ── Keyboard shortcuts ───────────────────────────────────────

function bindKeyboardShortcuts() {
  document.addEventListener('keydown', (e) => {
    // Escape → chat (unless settings overlay is open — settings.js handles that)
    if (e.key === 'Escape') {
      const settingsOverlay = document.getElementById('settings-overlay');
      if (settingsOverlay && settingsOverlay.style.display !== 'none') return;
      e.preventDefault();
      showView('chat');
      return;
    }
    // Ctrl/Cmd + number → view by navOrder
    if (!(e.ctrlKey || e.metaKey)) return;
    const num = parseInt(e.key, 10);
    if (Number.isNaN(num) || num < 1) return;

    const sorted = getVisibleViews();

    if (num <= sorted.length) {
      e.preventDefault();
      showView(sorted[num - 1].id);
    }
  });
}

// ── Hash routing ─────────────────────────────────────────────

function handleHash() {
  const hash = window.location.hash.replace('#', '');
  if (hash && views.has(hash)) {
    showView(hash);
  }
}

// ── Init ─────────────────────────────────────────────────────

/**
 * Initialise the router. Call after all views have been registered.
 * Builds the nav rail, binds keyboard shortcuts, and navigates to
 * the initial view (from URL hash or default).
 *
 * @param {Object} opts
 * @param {string} [opts.defaultView='chat'] - Fallback view if no hash
 */
/**
 * Rebuild the nav rail. Call after role changes or dynamic view registration.
 * Exported so external code (e.g. settings) can trigger a rebuild when the
 * user's role becomes known after login.
 */
export function rebuildNav() {
  if (routerInitialised) buildNav();
}

export function initRouter(opts) {
  const defaultView = opts?.defaultView || 'chat';
  viewContainer = document.getElementById('main-wrapper');
  navItemsContainer = document.querySelector('.nav-items');
  inputBar = document.getElementById('input-bar');

  buildNav();
  bindKeyboardShortcuts();
  routerInitialised = true;

  // Rebuild nav when user role changes (e.g. after /api/auth/me responds)
  subscribe('userRole', () => {
    buildNav();
  });

  // Hash-based deep link
  window.addEventListener('hashchange', handleHash);
  const hash = window.location.hash.replace('#', '');
  if (hash && views.has(hash)) {
    showView(hash);
  } else {
    showView(defaultView);
  }
}
