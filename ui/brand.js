/**
 * Brand manifest — single source of truth for identity.
 *
 * All hardcoded name/colour/tagline references should import from here.
 * White-label readiness: swap this file to rebrand the entire UI.
 *
 * Colour contract: brand.colors defines the canonical palette.
 * styles/tokens.css must be manually synced to match these values.
 * Runtime setProperty() is NOT used because inline custom properties
 * override [data-theme="dark"] rules and break dark mode.
 */

export const brand = {
  name: 'Sentinel',
  tagline: 'Defence-in-depth AI assistant',
  welcomeMessage: 'I plan carefully and check everything before acting. Ask me to do something to get started.',

  // Theme colours — canonical values. Sync tokens.css when changing.
  colors: {
    primary: '#2B8585',
    primaryHover: '#1E6868',
    background: '#F8F6F3',
    surface: '#FFFFFF',
    text: '#302C26',
    textMuted: '#635E56',
    inputBg: '#E4E0DA',
    inputBorder: '#D4CFC7',
    error: '#C05050',
    darkBackground: '#171614',
  },
};

/**
 * Update <meta name="theme-color"> to match current light/dark mode.
 * Called on theme change to keep mobile browser chrome in sync.
 *
 * Reads from CSS custom properties so the meta tag stays in sync with
 * tokens.css / dark.css — no hardcoded colour values to drift.
 */
export function updateThemeColor() {
  const meta = document.querySelector('meta[name="theme-color"]');
  if (!meta) return;

  const isDark =
    document.documentElement.getAttribute('data-theme') === 'dark' ||
    (!document.documentElement.hasAttribute('data-theme') && window.matchMedia('(prefers-color-scheme: dark)').matches);

  const styles = getComputedStyle(document.documentElement);
  const color = isDark
    ? styles.getPropertyValue('--bg-primary').trim() || '#171614'
    : styles.getPropertyValue('--accent').trim() || '#2B8585';
  meta.setAttribute('content', color);
}
