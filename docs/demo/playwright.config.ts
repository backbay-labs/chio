import { defineConfig, devices } from '@playwright/test';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DEMO_DIR = __dirname;
const TESTS_DIR = resolve(DEMO_DIR, 'tests');

/**
 * Playwright config for docs/demo.
 *
 * `webServer.command` runs `vite preview --port 4173` against the prebuilt
 * `dist/` artifact. The build step is the gate-check responsibility:
 *
 *   bun run --filter docs-demo build
 *   bunx playwright test docs/demo/tests/banner.spec.ts
 *
 * Tests must pass with the artifact already on disk; we do not rebuild
 * inside Playwright to keep the failure surface tight.
 */
export default defineConfig({
  testDir: TESTS_DIR,
  timeout: 30_000,
  fullyParallel: false,
  reporter: [['list']],
  outputDir: resolve(DEMO_DIR, 'test-results'),
  use: {
    baseURL: 'http://localhost:4173',
    headless: true,
    trace: 'retain-on-failure',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  webServer: {
    // Pin cwd to docs/demo so `vite preview` finds vite.config.ts and
    // serves dist/ regardless of where the playwright runner was invoked
    // (gate-check runs from repo root; local dev runs from docs/demo).
    cwd: DEMO_DIR,
    command: 'bunx vite preview --port 4173 --strictPort --host 127.0.0.1',
    url: 'http://localhost:4173',
    reuseExistingServer: !process.env.CI,
    timeout: 60_000,
    stdout: 'pipe',
    stderr: 'pipe',
  },
});
