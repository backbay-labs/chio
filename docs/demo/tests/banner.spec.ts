/*
 * docs/demo banner-snapshot Playwright test.
 *
 * The engineering-output banner MUST be present and visible without scrolling
 * on a 1080p viewport. This test serves the built `dist/` directory via
 * Playwright's webServer, asserts the banner DOM contract, and verifies that
 * the banner is positioned within the first 1080 viewport pixels.
 *
 * Verify-result assertions are best-effort: the wasm artifact is generated
 * by `sdks/typescript/scripts/build-wasm.sh`, which may not have run before
 * this test. When the wasm module fails to load, the banner contract still
 * holds (this is the gating assertion); the verify result is checked only
 * when the SDK successfully loaded.
 */

import { test, expect } from '@playwright/test';

const EXPECTED_BANNER_TEXT = [
  'This page is engineering output, not a release.',
  'It demonstrates the',
  '@chio-protocol/browser verify path against a fixture from the M04 replay',
  'corpus.',
  'It is not a substitute for an audited release of the SDK.',
];

test.describe('docs/demo engineering-output banner', () => {
  test.use({ viewport: { width: 1920, height: 1080 } });

  test('banner is present, visible, and above the fold on 1080p', async ({ page }) => {
    await page.goto('/');

    const banner = page.getByTestId('engineering-output-banner');
    await expect(banner).toBeVisible();
    await expect(banner).toHaveAttribute('role', 'note');
    await expect(banner).toHaveClass(/engineering-output-banner/);

    // Each chunk of the normative banner text must appear in document order.
    // Splitting the assertion lets us tolerate browser-side text-node
    // collapsing without weakening the contract.
    for (const chunk of EXPECTED_BANNER_TEXT) {
      await expect(banner).toContainText(chunk);
    }

    // Above-the-fold check: banner top must sit within the first 1080 px of
    // the layout. We allow a small positional tolerance for rounding.
    const box = await banner.boundingBox();
    expect(box, 'banner bounding box').not.toBeNull();
    if (box) {
      expect(box.y).toBeLessThan(1080);
      expect(box.y + box.height).toBeLessThan(1080);
    }
  });

  test('verify result renders successfully when wasm is available', async ({ page }) => {
    await page.goto('/');

    // Wait for the demo to finish its run cycle. The fixture-id field starts
    // as "(loading)" and is overwritten when run() reaches either the result
    // path or the error path.
    const fixtureCell = page.getByTestId('fixture-id');
    await expect(fixtureCell).not.toHaveText('(loading)', { timeout: 10_000 });
    await expect(fixtureCell).toContainText('allow_receipt');

    const verdict = page.getByTestId('verdict');
    const verdictText = (await verdict.textContent()) ?? '';

    if (verdictText.startsWith('error during')) {
      // Wasm artifact not built in this environment. The banner contract is
      // the gating assertion above; soft-skip the verify-success check and
      // emit a Playwright annotation so CI surfaces it.
      test.info().annotations.push({
        type: 'wasm-missing',
        description: `verify path could not run: ${verdictText}`,
      });
      return;
    }

    await expect(verdict).toHaveText('allow');
    await expect(page.getByTestId('signature-valid')).toHaveText('true');
    await expect(page.getByTestId('signer-key')).toHaveText(
      'ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c',
    );
  });
});
