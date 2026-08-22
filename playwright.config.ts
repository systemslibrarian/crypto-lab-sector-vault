import { defineConfig, devices } from '@playwright/test';

/**
 * Everything runs against the PRODUCTION build served by `vite preview`, so
 * what passes here is what ships.
 *
 * Port 4657 is unique to this lab across the fleet. Never the Vite default
 * 4173: with 190 labs side by side, a shared port plus `reuseExistingServer`
 * means a run can silently scan a different lab's preview — that has really
 * happened here, and it happened again while this lab was being built, when a
 * sibling took the port this file first claimed and served ITS bundle to this
 * suite. 4657 sits in the middle of a wide unclaimed gap rather than at the
 * first-free or next-above-the-maximum slot everyone else reaches for.
 */
const PORT = 4657;
const BASE = `http://localhost:${PORT}/crypto-lab-sector-vault/`;

export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  timeout: 180_000, // the a11y drive walks every act before each of its scans
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? 'list' : [['list'], ['html', { open: 'never' }]],
  use: {
    baseURL: BASE,
    colorScheme: 'dark', // dark is the only theme
  },
  projects: [
    { name: 'a11y', testMatch: /a11y\.spec\.ts/, use: { ...devices['Desktop Chrome'], colorScheme: 'dark' } },
    { name: 'claims', testMatch: /claims\.spec\.ts/, use: { ...devices['Desktop Chrome'], colorScheme: 'dark' } },
  ],
  webServer: {
    // Build before serving. `vite preview` only serves whatever is already in
    // dist/, so without the build in front a failing compile leaves the
    // previous good bundle in place and the whole suite passes green against
    // source that no longer compiles — which silently invalidates every
    // mutation check.
    command: `npm run build && npm run preview -- --port ${PORT} --strictPort`,
    url: BASE,
    // Deliberately NOT `!process.env.CI`. Reusing a preview server that is
    // already listening means the `npm run build` in front of it never runs, so
    // the suite tests whatever is already in dist/ — a stale bundle, silently.
    // That is the exact false-green §4.1 of the template warns about, and it
    // invalidates mutation checking, which is the only way a test is proved to
    // have teeth. A stray server now produces a loud "port in use" instead.
    reuseExistingServer: false,
    timeout: 180_000,
  },
});
