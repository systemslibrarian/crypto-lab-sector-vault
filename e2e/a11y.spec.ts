import { expect, test } from '@playwright/test';
import {
  boot,
  driveAllStates,
  expectBaselineNotStale,
  NARROW,
  REFLOW,
  reportCollected,
  watchPageErrors,
} from './gate';

/**
 * WCAG A/AA regression gate.
 *
 * The lab is driven along everything it teaches: the arrival state, exactly as
 * a reader gets it — sector 9 selected, the tweak ladder at j = 0, one disk
 * image held, nothing damaged, all four disclosures shut and act 5's nine
 * experiments already resolved; the shared skip link focused; another sector
 * and another block selected; the tweak ladder stepped through both branches of
 * the GF(2^128) reduction, found rather than assumed; a sector rewritten, which
 * paints the session log's first row; one ciphertext bit flipped, which paints
 * the damaged block cell, the corrupted sector tile and the alarm read-out; an
 * out-of-range byte offset, which paints the `aria-invalid` boundary and the
 * refusal line; a block relocated and a whole sector relocated; a sector rolled
 * back, which is the one read that succeeds cleanly and is still wrong; act 4's
 * 512-cell watermark grid with changed blocks and then with a reverted one, and
 * then discarded again; act 5 with the attacker owning the version store and
 * without; all four disclosures open; four hover states; three focus rings; and
 * the volume reformatted. Every one of those states is scanned, at desktop and
 * phone width.
 *
 * See `gate.ts` for why nothing is injected into the page, why no content is
 * revealed from script, why the lab's defaults are asserted rather than assumed
 * — act 5 paints asynchronously, so a scan that did not wait would measure a
 * placeholder — and why `violations` is not the whole oracle.
 *
 * Dark is the only theme this lab ships. The loop is kept so the shape matches
 * its siblings, and `boot` seeds `localStorage` with `light` on purpose, so the
 * anti-flash script's overwrite is exercised rather than assumed.
 */
for (const theme of ['dark'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(1_800_000);
    const errors = watchPageErrors(page);
    await boot(page, theme);
    await driveAllStates(page, theme);
    expect(errors, errors.join('\n')).toEqual([]);
    expectBaselineNotStale();
    reportCollected();
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(1_800_000);
    const errors = watchPageErrors(page);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
    expect(errors, errors.join('\n')).toEqual([]);
    expectBaselineNotStale();
    reportCollected();
  });

  test(`no WCAG A/AA violations in ${theme} theme at 280px — reflow headroom below the 320px threshold`, async ({ page }) => {
    test.setTimeout(1_800_000);
    const errors = watchPageErrors(page);
    await page.setViewportSize(REFLOW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @280px`);
    expect(errors, errors.join('\n')).toEqual([]);
    expectBaselineNotStale();
    reportCollected();
  });
}
