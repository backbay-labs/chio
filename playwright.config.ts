/*
 * Repo-root Playwright config.
 *
 * Re-exports the docs-demo Playwright config. Runs the demo's banner-snapshot
 * test from the repo root via:
 *
 *   bunx playwright test docs/demo/tests/banner.spec.ts
 *
 * The demo is the only Playwright suite in the repo today; if other suites
 * land later, switch this to a `projects:` array.
 */

export { default } from './docs/demo/playwright.config.ts';
