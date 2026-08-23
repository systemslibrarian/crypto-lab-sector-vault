import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';
import { auditNonText } from './nontext';
import { NONTEXT_BASELINE } from './nontext-baseline';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };
/**
 * A HEADROOM probe, deliberately narrower than the 320 CSS px WCAG 1.4.10 asks
 * for. Scanning AT 320 does not work: a sibling lab in this batch shipped a
 * defect whose min-content floor was 318px, so it fit at 320 and failed at 380
 * only once Linux font metrics in CI inflated it — a single-width check cannot
 * see a floor sitting just under that width. 280 asserts the floor is low
 * enough that no font-metric delta can push it back over 320.
 */
export const REFLOW = { width: 280, height: 800 };

/**
 * Shared machinery for the WCAG gate.
 *
 * Five rules govern everything here, and each one corrects something the
 * retired fleet-wide template gate did:
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN. The old spec pushed
 *     `animation:none!important; transition:none!important` through
 *     `addStyleTag`. That BYPASSES a lab's own
 *     `@media (prefers-reduced-motion: reduce)` block instead of exercising it,
 *     so the rendering a reduced-motion reader actually gets was never the
 *     rendering that got scanned — and where a page parks content at
 *     `opacity: 0` and reveals it through an animation's `forwards` fill, the
 *     injection kills the reveal and the content is scanned invisible. This
 *     gate sets the preference through `emulateMedia`, asserts from inside the
 *     page that it took effect (`test.use({ reducedMotion })` and the
 *     `reducedMotion` config key are both measured no-ops on Playwright
 *     1.61.x), and injects nothing.
 *
 *  2. IT FORCED HIDDEN CONTENT VISIBLE FROM SCRIPT. The old drive stripped
 *     every `[hidden]` attribute and set every `<details>.open` by JS before
 *     its only scan. That scans a state the page never renders, and destroys
 *     the ability to catch the `[hidden]` cascade trap. This lab has no
 *     `[hidden]` content at all — everything is on one page — and its four
 *     disclosures are opened here through their `<summary>`, which is the route
 *     a reader has, with both the shut and the open state scanned.
 *
 *  3. IT DROVE BLIND AND THEN THREW THE STATES AWAY. The old drive clicked
 *     every button whose label matched a regex, swallowed every failure with
 *     `.catch(() => {})`, waited a fixed 400ms, and scanned ONCE at the end —
 *     so a click that silently did nothing looked identical to one that
 *     worked. This drive names every control it touches, asserts a real
 *     completion signal after each, and scans after every step, at 1280 and
 *     380 wide.
 *
 *  4. `violations` IS NOT THE WHOLE ORACLE. See `scan`. Everything axe declines
 *     to judge lands in `incomplete` instead — including the shared top bar's
 *     `color-mix()` ink, and an `aria-label` on a role-less element. This lab
 *     leans on getting the second right: the sector grid, act 4's legend and
 *     every scrolling region carry `aria-label`s that are only exposed because
 *     they sit on an element with a role.
 *
 *  5. IT HAD NO REFLOW, NON-TEXT-CONTRAST OR GENERATED-CONTENT ORACLE. The old
 *     spec hand-rolled one luminance check over two input selectors, reading
 *     the DECLARED `border-top-color` and `background-color` — blind to
 *     composited backdrops, to every button, input, select, sector tile, block
 *     cell and watermark cell on this page, and to all states past first paint.
 *     `nontext.ts` replaces it with a measured oracle over every control at
 *     every driven state, and `expectNoHorizontalOverflow` adds the 1.4.10
 *     check axe has no rule for — which matters here, because this page ships
 *     three tables and two grids wider than a phone.
 */

/**
 * Wait for every running animation and transition to drain.
 *
 * Two rAFs are not enough. A transition sampled mid-flight has a colour that
 * exists in no state of the page, and axe will happily report it: elsewhere in
 * this fleet that produced a phantom 2.00:1 failure on a button whose settled
 * ratio is 9:1. Transitions also drain in waves rather than in one batch, so a
 * poll for "nothing running right now" can exit through a gap between waves —
 * hence six consecutive quiet frames rather than one.
 *
 * Bounded three ways, because a gate that can hang is a gate nobody runs:
 * animations that never finish (`iterations: Infinity`) are excluded from the
 * quiescence test rather than waited on, a wall-clock budget inside the page
 * gives up and proceeds, and Playwright's own timeout is the backstop.
 *
 * This lab declares no `@keyframes` at all — the template bans decorative
 * motion, and the one thing that moves is the tweak ladder, which advances
 * only when a reader presses a button. What remains is transitions: the
 * `#app button` hover repaint and the shared top bar's `.cl-btn`, the latter
 * declared OUTSIDE the lab's `@media (prefers-reduced-motion)` block. Under
 * the reduced motion this gate asserts, the lab's block collapses every
 * transition to 0.001ms, so `getAnimations()` is normally empty and this
 * returns on the sixth frame. It stays because that is a property of the
 * current stylesheet, not of the page.
 */
export async function settle(page: Page, budgetMs = 4000): Promise<void> {
  await page.waitForFunction(
    (budget: number) => {
      const w = window as unknown as { __quietFrames?: number; __settleStart?: number };
      if (w.__settleStart === undefined) w.__settleStart = performance.now();
      const done = (): boolean => {
        w.__quietFrames = 0;
        w.__settleStart = undefined;
        return true;
      };
      const running = document.getAnimations().filter((a) => {
        if (a.playState !== 'running') return false;
        const timing = a.effect?.getComputedTiming?.();
        // An infinite decorative animation never drains; waiting on it hangs.
        return timing?.iterations !== Infinity;
      });
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      if (w.__quietFrames >= 6) return done();
      if (performance.now() - (w.__settleStart ?? 0) > budget) return done();
      return false;
    },
    budgetMs,
    { timeout: 20_000, polling: 'raf' }
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set. This lab
 * cannot currently have that shape, because it declares no `@keyframes` and no
 * `opacity` anywhere. That is precisely why the assertion is worth keeping: it
 * makes "the page is not blank under reduced motion" a measurement rather than
 * a reading of a stylesheet that could acquire a reveal animation tomorrow.
 *
 * `aria-hidden` subtrees are excluded; what this lab hides is the decorative
 * verdict glyphs and legend swatches beside their own words — see
 * `contrast.ts`, which measures them anyway with the exemption lifted.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      if (el.closest('[aria-hidden="true"]')) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([]);
}

/**
 * Uncaught page errors and console errors, collected from the moment the page
 * is created. Every panel here renders synchronously at first activation, so a
 * renderer that throws leaves that tabpanel EMPTY — and an empty region is
 * exactly what a scan reports as perfectly accessible. Attach before `boot`,
 * assert after the drive.
 */
export function watchPageErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(`console.error: ${m.text()}`);
  });
  return errors;
}

/**
 * Exactly one banner landmark.
 *
 * The shared `.cl-topbar` carries an explicit `role="banner"`. This lab's own
 * hero is a `<div class="cl-hero">`, not a `<header>`, so nothing here implies
 * a second banner today — but the template's own hero snippet is a `<header>`,
 * the shared bar's `dedupeBanner()` exists because other labs in this fleet
 * shipped exactly that, and the hero is the part of this page most likely to be
 * re-templated. Asserting the OUTCOME rather than the markup is what catches
 * that edit. The scripture `<footer>` implies `contentinfo`, not `banner`, and
 * is unaffected.
 */
export async function assertSingleBanner(page: Page): Promise<void> {
  const banners = await page.evaluate(() => {
    const scoped = new Set(['MAIN', 'ARTICLE', 'ASIDE', 'NAV', 'SECTION']);
    const isBanner = (el: Element): boolean => {
      if (el.getAttribute('role') === 'banner') return true;
      if (el.tagName !== 'HEADER') return false;
      if (el.getAttribute('role')) return false; // explicit non-banner role wins
      for (let p = el.parentElement; p; p = p.parentElement) if (scoped.has(p.tagName)) return false;
      return true;
    };
    return [...document.querySelectorAll('header,[role="banner"]')].filter(isBanner).length;
  });
  expect(banners, 'exactly one banner landmark').toBe(1);
}

/**
 * List semantics survive their styling.
 *
 * Four lists on this page are styled `list-style: none` — the session log, the
 * act 4 legend, the act 4 reverted-block list and act 5's two honest notes —
 * and that declaration is exactly what makes Safari and VoiceOver DROP a
 * list's implicit role. Each compensates the documented way: an explicit
 * `role="list"` on the `<ul>` and `role="listitem"` on every `<li>`, so here,
 * unlike most of this fleet, an explicit role on a list is the fix rather than
 * the defect. What is asserted is therefore the SHAPE of that fix: any explicit
 * role on a `ul`/`ol` must be `list` (any other value orphans every `<li>`
 * under it), and a `role="list"` must never sit on an empty element, because
 * axe applies `aria-required-children` to the explicit role and fails it the
 * day a list renders with no rows — which the reverted-block list really can
 * do, since it is empty until a rollback has happened. It renders a paragraph
 * instead of an empty list for that reason, and this is what holds that
 * decision in place. Roles are assigned through an element-creation helper, so
 * ask the DOM rather than grepping the source.
 */
export async function assertListSemantics(page: Page): Promise<void> {
  const broken = await page.$$eval('ul[role], ol[role]', (els) =>
    els
      .filter((e) => e.getAttribute('role') !== 'list' || e.children.length === 0)
      .map(
        (e) =>
          `${e.tagName.toLowerCase()}[role=${e.getAttribute('role')}] with ${e.children.length} children`
      )
  );
  expect(
    broken,
    'an explicit non-list role on a list deletes its semantics; an empty role="list" fails aria-required-children'
  ).toEqual([]);
}

/**
 * Load the page with reduced motion actually in effect, and assert the content
 * every scan relies on is really on the page — including the lab's DEFAULTS,
 * which are never assumed.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.x, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page.
 *
 * Dark is the only theme in this fleet. The parameter stays so the shape
 * matches its siblings and so a future light variant cannot be added without
 * touching this function, but the assertion is that `data-theme` is `dark`
 * whatever `localStorage` said beforehand — `index.html`'s anti-flash script
 * WRITES `theme=dark` rather than reading a preference, deliberately, to
 * overwrite any `light` a visitor stored back when the shared bar had a toggle.
 * Seeding the opposite value and still expecting dark is what makes that a
 * measurement.
 *
 * The defaults are asserted at length because act 5 renders ASYNCHRONOUSLY: it
 * runs nine real attack experiments through WebCrypto and only then paints its
 * table. A navigation that resolves proves nothing — axe would happily scan the
 * "Running the nine experiments…" placeholder and report a clean page having
 * checked almost none of it. Waiting on real content is the whole point.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  // A click on a control that never becomes actionable otherwise burns the
  // whole test timeout and reports nothing useful. 20s turns that silent hang
  // into a named failure naming the locator.
  page.setDefaultTimeout(20_000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  // Seeded to the OPPOSITE of what must win, so the anti-flash script's
  // overwrite is exercised rather than merely agreed with.
  await page.addInitScript(() => localStorage.setItem('theme', 'light'));
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  expect(theme, 'dark is the only theme this lab ships').toBe('dark');
  expect(
    await page.evaluate(() => Object.keys(localStorage).sort()),
    'the theme is written under exactly one key'
  ).toEqual(['theme']);
  await assertSingleBanner(page);
  await assertListSemantics(page);

  // ── The page really rendered ────────────────────────────────────────────
  await expect(page.locator('main')).toHaveCount(1);
  await expect(page.locator('h1')).toHaveCount(1);
  await expect(page.locator('.scripture-footer')).toHaveCount(1);

  // The shared skip link points at an id that exists. axe's skip-link rule is
  // best-practice, not WCAG-tagged, so `withTags` never runs it — a skip link
  // aimed at a missing element is exactly the kind of thing a green axe run
  // says nothing about.
  await expect(page.locator('a.cl-skip-link')).toHaveAttribute('href', '#app');
  await expect(page.locator('#app')).toHaveCount(1);

  // Dark is the only theme, so the page must carry no theme control at all —
  // not the shared bar's, which was removed, and not a lab-local one. The
  // shared CSS hides any lab toggle with `display:none !important`, which would
  // leave a dead-but-known element; asserting the count at zero catches the day
  // one is added without going through that list.
  await expect(
    page.locator('#theme-toggle, #themeToggle, .theme-toggle, .theme-toggle-btn, [data-theme-toggle]')
  ).toHaveCount(0);

  // ── Act 1: the volume arrives written, on sector 9, block 0 ────────────
  await expect(page.locator('#act-disk .sector-tile')).toHaveCount(16);
  await expect(page.locator('#act-disk .block-cell')).toHaveCount(32);
  await expect(page.locator('#act-disk .sector-tile[aria-pressed="true"]')).toHaveCount(1);
  await expect(page.locator('#act-disk .sector-tile[aria-pressed="true"] .tile-id')).toHaveText('SECTOR 09');
  await expect(page.locator('#disk-readout')).toContainText('DECRYPTED — AND INTACT');
  await expect(page.locator('#disk-readout')).toContainText('none — there is none to give');
  // The four rows of the check inventory: two the construction really performs
  // and two it does not have, which is the exhibit rather than an omission.
  await expect(page.locator('#disk-readout [data-check]')).toHaveCount(2);
  await expect(page.locator('#disk-readout [data-missing-check]')).toHaveCount(2);
  // The negative claim belongs to the damaged state, not to the arrival state.
  await expect(page.locator('[data-negative-claim]')).toHaveCount(1);
  await expect(page.locator('#scope [data-negative-claim]')).toHaveCount(1);
  await expect(page.locator('#ladder')).toContainText('current  j = 0');
  await expect(page.locator('#ladder-back')).toBeDisabled();
  await expect(page.locator('#write-text')).toHaveValue(/^LEDGER 2026-08-02/);
  // No block is painted damaged on arrival; the alarm fill is a driven state.
  await expect(page.locator('#act-disk .block-cell.fill-alarm')).toHaveCount(0);

  // ── Acts 2 and 3: the shipped form defaults ────────────────────────────
  await expect(page.locator('#flip-sector')).toHaveValue('7');
  await expect(page.locator('#flip-byte')).toHaveValue('20');
  await expect(page.locator('#flip-bit')).toHaveValue('3');
  await expect(page.locator('#flip-error')).toBeEmpty();
  await expect(page.locator('#rollback-version option')).toHaveCount(2);
  await expect(page.locator('#rollback')).toBeEnabled();

  // ── Act 4: one image held, so the grid has nothing to draw yet ─────────
  await expect(page.locator('#wm-summary')).toContainText('1 disk image held');
  await expect(page.locator('.wm-cell')).toHaveCount(0);
  await expect(page.locator('#clear-images')).toBeDisabled();

  // ── Act 5 finished its nine experiments ────────────────────────────────
  // The scan race, closed: this table is painted only after nine real
  // encryptions, tag checks and version comparisons resolve.
  await expect(page.locator('#comparison table.matrix tbody tr')).toHaveCount(3);
  await expect(page.locator('#comparison')).toContainText('STALE_VERSION');
  await expect(page.locator('#comparison .verdict')).toHaveCount(9);
  await expect(page.locator('#attacker-owns-store')).not.toBeChecked();
  await expect(page.locator('#act-compare table.matrix')).toHaveCount(3);

  // ── The session log is empty, and every disclosure ships shut ──────────
  await expect(page.locator('#log-host')).toContainText('Nothing yet');
  await expect(page.locator('details.more')).toHaveCount(4);
  await expect(page.locator('details.more[open]')).toHaveCount(0);

  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all, and this page has
 * more than most labs to get wrong: three `table.matrix` bodies with a 46rem
 * minimum width, a 32-button block strip, and act 4's 512-cell watermark grid,
 * every one of them wider than a 380px viewport. Each sits inside a
 * `.scroller` (`overflow-x: auto`), so it is clipped by its own region and
 * contributes nothing to the document's scroll width. The remaining risk is a
 * long hex run: `.hexline` and `.textline` rely on `overflow-wrap: anywhere`
 * rather than a scroller. If any of those wrappers is ever dropped, or a new
 * unwrapped run appears, the document itself starts scrolling sideways — which
 * at 380px is precisely what this check exists to catch.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    if (doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. A
    // wide box inside an `overflow: auto` wrapper has a huge bounding rect but
    // is clipped by its scroller and contributes nothing to the document's
    // scroll width — naming it sends you off fixing the wrong element.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      while (n && n !== doc) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    const widest = over.filter((x) => !clipped(x.el))[0] ?? over[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${clipped(widest.el) ? '[clipped] ' : ''}${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    };
  });
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull();
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1).
 * If it holds no focusable content it needs `tabindex="0"`, so it becomes a
 * focus target arrow keys can then scroll.
 *
 * This is a live check here rather than a precaution. The page ships five or
 * more real scrollers — the block strip, act 4's watermark grid and act 5's
 * three tables — and every one is created through `scroller()` in `ui/dom.ts`,
 * which attaches `role="region"`, `tabindex="0"` and an `aria-label` together.
 * A scroller born any other way is invisible to axe and unreachable by
 * keyboard, and this is what catches it. Note that the requirement only bites
 * once the content actually overflows, so the watermark grid is only judged
 * after the drive has taken a second disk image.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,summary,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY);
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`
      );
  });
  expect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`
  ).toEqual([]);
}

/**
 * Nothing may be focusable while it paints nothing (WCAG 2.4.3 / 2.4.7).
 *
 * `opacity: 0` with `pointer-events: none` is NOT hiding: the element keeps
 * `tabIndex: 0`, so a keyboard reader tabs to a control that is not on screen
 * and the focus ring lands nowhere. `display: none` and `visibility: hidden`
 * DO remove an element from the tab order, so those are skipped rather than
 * flagged — the failure is specifically the invisible-but-tabbable pair. The
 * `hidden` tabpanels here take the `display: none` route, which is why five
 * panels' worth of buttons are legitimately absent from the tab order.
 *
 * Off-screen-but-focusable is the WCAG-sanctioned skip-link idiom and is
 * deliberately not flagged: the shared skip link parks at `top:-3rem` with
 * full opacity and slides in on focus. The drive scans it focused.
 *
 * This lab renders everything on one page, so it has no hidden panel full of
 * legitimately unreachable controls. Every button, input and select on the
 * page is in the tab order at every state, which is the simplest thing for
 * this oracle to judge and the reason nothing here is exempted.
 */
export async function expectNoInvisibleFocusTargets(page: Page, label: string): Promise<void> {
  const bad = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,summary,[tabindex]:not([tabindex="-1"])';
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll<HTMLElement>(FOCUSABLE))) {
      if (el.tabIndex < 0) continue;
      // display:none / visibility:hidden already remove it from the tab order.
      if (!el.checkVisibility?.({ checkVisibilityCSS: true })) continue;
      let effective = 1;
      for (let n: Element | null = el; n; n = n.parentElement) {
        effective *= parseFloat(getComputedStyle(n).opacity);
      }
      const r = el.getBoundingClientRect();
      if (effective !== 0 && r.width > 0 && r.height > 0) continue;
      // Confirm it really is reachable rather than inferring it.
      const before = document.activeElement;
      el.focus();
      const took = document.activeElement === el;
      (before as HTMLElement | null)?.focus?.();
      if (took) {
        out.push(
          `${el.tagName.toLowerCase()}${el.id ? '#' + el.id : ''}.${(el.getAttribute('class') ?? '').trim()}` +
            ` (opacity ${effective}, ${Math.round(r.width)}x${Math.round(r.height)})`
        );
      }
    }
    return Array.from(new Set(out));
  });
  expect(bad, `focusable elements that paint nothing in state: ${label}`).toEqual([]);
}

/**
 * When `A11Y_COLLECT` is set, `scan` records failures instead of throwing.
 *
 * A strict gate reports the first failing assertion in the first failing state
 * and stops, so a page with defects in several states needs one full run per
 * defect to enumerate them. The collection pass turns that into a single run.
 * It is a debugging aid only: `A11Y_COLLECT` is never set in CI, and a run
 * with it set prints every finding as it happens and then fails at the end, so
 * a green collection run cannot be mistaken for a green gate.
 */
const COLLECTING = !!process.env.A11Y_COLLECT;
const collected: string[] = [];

function record(entry: string): void {
  collected.push(entry);
  // Printed as it happens, not only at the end: a hard assertion later in the
  // drive would otherwise abort the test before anything collected so far was
  // ever shown.
  console.log(`\n[A11Y_COLLECT #${collected.length}] ${entry}`);
}

export function softExpect(actual: unknown, message: string, expected: unknown): void {
  if (!COLLECTING) {
    expect(actual, message).toEqual(expected);
    return;
  }
  try {
    expect(actual, message).toEqual(expected);
  } catch {
    record(`${message}\n  ${JSON.stringify(actual, null, 2)}`);
  }
}

/**
 * Fail the test if the collection pass recorded anything. Without this a
 * collection run would end green, and a green collection run is
 * indistinguishable from a green gate — which is the exact confusion the whole
 * exercise exists to remove.
 */
export function reportCollected(): void {
  if (!COLLECTING) return;
  expect(collected, `A11Y_COLLECT recorded ${collected.length} failure(s)`).toEqual([]);
}

async function soft(fn: () => Promise<void>): Promise<void> {
  if (!COLLECTING) return fn();
  try {
    await fn();
  } catch (e) {
    // Generous, not 900: a truncated oracle dump is how a second and third
    // finding in the same state get missed on a collection pass.
    record(String(e).slice(0, 6000));
  }
}

/**
 * WCAG 1.4.11 and generated content, ratcheted against a per-repo baseline.
 *
 * Neither class has ANY other oracle: axe has no rule for non-text contrast,
 * and the arithmetic text walk cannot reach a control's boundary or a
 * `::before` glyph, because a pseudo-element is not an element and owns no
 * text node.
 *
 * IT IS CALLED FROM `scan()`, deliberately and not by accident. Fleet-wide
 * this oracle had been called from inside a soft wrapper AFTER its
 * `if (!COLLECTING) return` guard — so in a strict run, which is every run in
 * CI and every run anyone reads as a pass, the guard returned first and
 * `nontext.ts` never executed at all. Thirteen repos certified themselves
 * clean on an oracle that had never looked. Calling it here means it runs at
 * every driven state, including `:hover`, and this repo's baseline was
 * captured by that live path.
 *
 * A check that merely logs is not a gate, so it ratchets: anything NOT in the
 * baseline fails, anything in the baseline that got WORSE fails, and anything
 * in the baseline that has been FIXED fails until its entry is deleted. That
 * last rule is what stops the allowlist becoming a permanent exemption.
 */
const nonTextSeen = new Set<string>();

export async function expectNoNewNonTextFailures(page: Page, label: string): Promise<void> {
  const found = await auditNonText(page);
  // Capture mode: emit every finding and assert nothing, so a baseline can be
  // generated by the SAME path that checks it.
  if (process.env.NT_BASELINE_CAPTURE) {
    for (const f of found) {
      console.log(`NTCAP|${f.kind}|${f.selector}|${f.ratio}|${f.required}|${/POSITIONED/.test(f.detail)}`);
    }
    return;
  }
  const problems: string[] = [];
  for (const f of found) {
    const key = `${f.kind}|${f.selector}`;
    nonTextSeen.add(key);
    const base = NONTEXT_BASELINE[key];
    if (!base) {
      problems.push(`NEW ${f.ratio}:1 (needs ${f.required}:1) [${f.kind}] ${f.selector} — ${f.detail}`);
    } else if (f.ratio < base.ratio - 0.01) {
      problems.push(`WORSE ${f.selector}: ${f.ratio}:1, baseline recorded ${base.ratio}:1`);
    }
  }
  expect(problems, `new or worsened non-text contrast in state: ${label}`).toEqual([]);
}

/**
 * Fail if a baselined finding never appeared during the whole drive.
 *
 * It has either been fixed — in which case delete the entry, which is the
 * point — or the drive stopped reaching the state that shows it, which is a
 * coverage regression worth knowing about. Call once, after `driveAllStates`.
 */
export function expectBaselineNotStale(): void {
  const unseen = Object.keys(NONTEXT_BASELINE).filter((k) => !nonTextSeen.has(k));
  expect(
    unseen,
    'baselined non-text findings that no longer appear — delete them from nontext-baseline.ts (or restore the drive state that showed them)'
  ).toEqual([]);
}

/**
 * Scan the page as it currently stands.
 *
 * Nine assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - reduced-motion end state — see `expectNotBlank`.
 *  - `violations` — the usual WCAG A/AA rule failures, plus four landmark
 *    best-practice rules `withTags` does not run on its own.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those
 *    ratios arithmetically — which matters here for the shared top bar, whose
 *    ink, border and hover fill are all `color-mix()` axe declines to resolve.
 *    Everything else in that bucket is a real result axe simply could not
 *    finish — including `aria-prohibited-attr`, which is where an `aria-label`
 *    on a role-less element hides. This page leans on getting that right: the
 *    sector grid pairs its label with `role="group"`, every `.scroller` pairs
 *    its label with `role="region"`, and each watermark cell pairs its label
 *    with `role="img"`. Drop any of those roles and the label is silently
 *    discarded — the grid becomes 512 unlabelled glyphs, and act 4 stops
 *    existing for a screen reader.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node.
 *  - the same walk over `aria-hidden` content with the exemption lifted —
 *    SC 1.4.3 is about what a reader SEES, and what this lab hides is the
 *    verdict glyphs and legend swatches beside their own words; see
 *    `contrast.ts` for the inventory and why it is measured anyway.
 *  - non-text contrast and generated content — SC 1.4.11, ratcheted; see
 *    `expectNoNewNonTextFailures`. This is the only oracle that judges a
 *    control's boundary against the surface OUTSIDE it.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - no focusable element that paints nothing — WCAG 2.4.3/2.4.7.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 */
export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await expectNotBlank(page, label);
  // TWO axe runs, deliberately, and this is not a style choice.
  //
  // `AxeBuilder.withTags()` and `AxeBuilder.withRules()` both write the same
  // `options.runOnly` field, so the second call SILENTLY REPLACES the first —
  // the axe-core/playwright source says so in as many words on `withRules`
  // ("Cannot be used with AxeBuilder#withTags"). Chained as
  // `.withTags(TAGS).withRules([...4 landmark rules])`, axe runs those FOUR
  // best-practice rules and NOT ONE WCAG RULE, while a green result reads
  // exactly like a full A/AA pass. For scale, `withTags(TAGS)` selects 69 of
  // axe-core 4.12's 105 rule definitions; the chained form executes 4.
  //
  // The landmark four are still wanted because they are best-practice rather
  // than WCAG-tagged, so `withTags` alone does not reach them — and this page
  // has the shape they catch: a sticky `<header role="banner">` above a
  // `<div id="app">` holding an `<aside class="cl-hero-why">`, the shared
  // bar's `<nav>`, one `<main>` and the scripture `<footer>`. The aside is the
  // live one — it sits inside `#app` but OUTSIDE `<main>` on purpose, because a
  // complementary landmark nested inside another landmark fails
  // `landmark-complementary-is-top-level`, and moving the hero into `<main>` is
  // the single most likely edit anyone would make to this page.
  const wcag = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const landmarks = await new AxeBuilder({ page })
    .withRules([
      'landmark-no-duplicate-banner',
      'landmark-unique',
      'landmark-one-main',
      'landmark-complementary-is-top-level',
    ])
    .analyze();
  const results = {
    violations: [...wcag.violations, ...landmarks.violations],
    incomplete: [...wcag.incomplete, ...landmarks.incomplete],
  };

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  softExpect(violations, `axe violations in state: ${label}`, []);

  // The `incomplete` bucket is asserted, not skimmed. `aria-prohibited-attr`
  // and `aria-required-children` appear ONLY here — never in `violations` — so
  // a gate that ignores this bucket cannot see either. Only `color-contrast`
  // is allowed to remain, and only because the arithmetic walk below judges
  // those ratios for real; no other rule is filtered out.
  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  softExpect(unexplainedIncomplete, `axe incomplete results in state: ${label}`, []);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  softExpect(contrast, `measured contrast failures in state: ${label}`, []);

  // The aria-hidden walk, exemption lifted — axe skips this text entirely and
  // the default walk honours the same boundary, so this second call is the
  // ONLY thing that ever measures it. See `contrast.ts` for the inventory.
  const hiddenContrast = Array.from(
    new Set(
      formatContrastFailures(
        await auditContrast(page, '[aria-hidden="true"], [aria-hidden="true"] *', true)
      )
    )
  );
  softExpect(hiddenContrast, `measured aria-hidden contrast failures in state: ${label}`, []);

  await soft(() => expectNoNewNonTextFailures(page, label));
  await soft(() => expectScrollersReachable(page, label));
  await soft(() => expectNoInvisibleFocusTargets(page, label));
  await soft(() => expectNoHorizontalOverflow(page, label));
}

// ── The drive ───────────────────────────────────────────────────────────────

/**
 * Drive the lab through the states that render content, scanning each.
 *
 * Four things shape this drive:
 *
 *  - THE ARRIVAL STATE IS SCANNED FIRST, exactly as a reader gets it: sector 9
 *    selected, block 0 open, the ladder at j = 0, one disk image held, no
 *    damage anywhere, every disclosure shut, and act 5's table already
 *    resolved.
 *
 *  - EVERY DAMAGED AND REFUSED STATE. The alarm fills — a corrupted sector
 *    tile, a damaged block cell, a stale read-out, an `aria-invalid` number
 *    box, the red cells in act 5 — are the surfaces that carry this lab's
 *    meaning, and none of them exists until somebody breaks something. A gate
 *    that only scans the arrival state has measured the colour of nothing that
 *    matters.
 *
 *  - HOVER IS A STATE, AND IT PERSISTS AFTER A CLICK. `:hover` stays on the
 *    element under the pointer after `page.click()` resolves, so it is the
 *    state a reader occupies the instant after pressing a button — and
 *    `#app button:hover` repaints both fill and border, while `.cl-btn:hover`
 *    in the shared bar repaints a `color-mix()`. Both are scanned explicitly.
 *
 *  - NO FIXED TIMEOUTS. Every wait is on a real DOM completion signal: a
 *    verdict's wording, a counter, `aria-pressed`, `aria-invalid`, an option
 *    count, a painted cell count.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  const scanAt = (s: string): Promise<void> => scan(page, `${theme} / ${s}`);

  await scanAt('arrival: sector 9 selected, ladder at j = 0, nothing damaged, disclosures shut');

  // ── The shared skip link, focused ───────────────────────────────────────
  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur?.());
  await page.keyboard.press('Tab');
  await expect(page.locator('a.cl-skip-link')).toBeFocused();
  await scanAt('the shared skip link focused, slid in from top:-3rem');

  // ── Act 1: another sector, another block ────────────────────────────────
  await page.locator('#act-disk .sector-tile').nth(0).click();
  await expect(page.locator('#act-disk .sector-tile').nth(0)).toHaveAttribute('aria-pressed', 'true');
  await expect(page.locator('#write-text')).toHaveValue(/^VOLUME LABEL/);
  await scanAt('Disk: sector 0 selected, its tile pressed and the write box refilled');

  await page.locator('#act-disk .block-cell').nth(5).click();
  await expect(page.locator('#act-disk .block-cell').nth(5)).toHaveAttribute('aria-pressed', 'true');
  await expect(page.locator('#ladder')).toContainText('current  j = 5');
  await scanAt('Disk: block 5 selected — the ladder jumps to its tweak and the sandwich follows');

  // ── The ladder, both branches of the reduction ──────────────────────────
  // Which j reduces depends on the session keys, so the branch is FOUND rather
  // than assumed: over 31 steps the probability of never seeing a carry, or
  // never seeing its absence, is about 2^-31 each. Both renderings get scanned.
  await page.locator('#ladder-reset').click();
  await expect(page.locator('#ladder-back')).toBeDisabled();
  let sawReduction = false;
  let sawNoReduction = false;
  for (let step = 0; step < 31 && !(sawReduction && sawNoReduction); step++) {
    const carried = (await page.locator('#ladder').innerText()).includes('XOR 0x87');
    if (carried && !sawReduction) {
      sawReduction = true;
      await scanAt(`ladder at j = ${step}: the shift overflowed x^127 and the reduction fired`);
    } else if (!carried && !sawNoReduction) {
      sawNoReduction = true;
      await scanAt(`ladder at j = ${step}: no overflow, so no reduction`);
    }
    await page.locator('#ladder-step').click();
    await expect(page.locator('#ladder')).toContainText(`current  j = ${step + 1}`);
  }
  expect(sawReduction, 'the ladder must reach a step where the reduction fires').toBe(true);
  expect(sawNoReduction, 'the ladder must reach a step where it does not').toBe(true);

  await page.locator('#ladder-reset').click();
  await expect(page.locator('#ladder')).toContainText('current  j = 0');
  await expect(page.locator('#ladder-back')).toBeDisabled();

  // ── A write, which also puts the first row in the session log ───────────
  await page.fill('#write-text', 'VOLUME LABEL: RELABELLED BY THE READER');
  await page.locator('#write-sector').click();
  await expect(page.locator('#disk-readout')).toContainText('INTACT');
  await expect(page.locator('#log-host li')).toHaveCount(1);
  await scanAt('Disk: a sector rewritten — the session log paints its first row');

  // ── Act 2: the damage states ────────────────────────────────────────────
  await page.locator('#flip-bit-button').click();
  await expect(page.locator('#flip-readout')).toContainText('DECRYPTED — AND MODIFIED');
  await expect(page.locator('#flip-readout')).toContainText('CORRUPTED (UNDETECTED)');
  await expect(page.locator('#act-disk .block-cell.fill-alarm')).toHaveCount(1);
  await expect(page.locator('.sector-tile .tile-state.s-alarm')).toHaveCount(1);
  // The negative-claim fixture: every performed check green, the claim printed
  // inside the state that demonstrates it.
  await expect(page.locator('#flip-readout [data-check="pass"]')).toHaveCount(2);
  await expect(page.locator('[data-check="fail"]')).toHaveCount(0);
  await expect(page.locator('#flip-readout [data-negative-claim="NEG-1"]')).toBeVisible();
  await scanAt('Flip: the NEG-1 fixture — every check green, the claim printed, the data wrong');

  await page.fill('#flip-byte', '9999');
  await page.locator('#flip-bit-button').click();
  await expect(page.locator('#flip-byte')).toHaveAttribute('aria-invalid', 'true');
  await expect(page.locator('#flip-error')).toContainText('inside its stated range');
  await scanAt('Flip: an out-of-range byte — the aria-invalid boundary and the refusal line');

  await page.fill('#flip-byte', '20');
  await expect(page.locator('#flip-byte')).toHaveValue('20');

  // ── Act 3: relocation, then rollback ────────────────────────────────────
  await page.locator('#relocate-block').click();
  await expect(page.locator('#relocate-readout')).toContainText('CORRUPTED (UNDETECTED)');
  await scanAt('Relocate: a block copied elsewhere — the two tweaks printed side by side');

  await page.locator('#relocate-sector').click();
  await expect(page.locator('#relocate-readout')).toContainText('CORRUPTED (UNDETECTED)');
  await expect(page.locator('#relocate-readout')).toContainText('32 of 32');
  await scanAt('Relocate: a whole sector moved — every block in it differs');

  await page.fill('#rollback-sector', '9');
  await page.locator('#rollback-sector').dispatchEvent('change');
  await expect(page.locator('#rollback-version option')).toHaveCount(2);
  await page.selectOption('#rollback-version', '1');
  await page.locator('#rollback').click();
  await expect(page.locator('#relocate-readout')).toContainText('SUCCEEDS CLEANLY (STALE)');
  await expect(page.locator('#relocate-readout')).toContainText('DECRYPTED — AND ROLLED BACK');
  await expect(page.locator('#relocate-readout [data-negative-claim="NEG-1"]')).toBeVisible();
  await scanAt('Rollback: an earlier image restored — a clean read of stale data, and still no code');

  // ── Act 4: the watermark grid ───────────────────────────────────────────
  await page.locator('#take-image').click();
  await expect(page.locator('.wm-cell')).toHaveCount(512);
  await expect(page.locator('.wm-cell.wm-changed')).not.toHaveCount(0);
  await expect(page.locator('#clear-images')).toBeEnabled();
  await scanAt('Watermark: two images compared — 512 cells, a legend and the changed blocks named');

  // A block only reads as REVERTED when its ciphertext goes A, B, A across the
  // images. The rollback above already put version 1 on the platter, so the
  // sector has to be written again before restoring version 1 a second time.
  await page.fill('#write-text', 'LEDGER 2026-08-05  TRANSFER OUT            250000.00 EUR');
  await page.locator('#write-sector').click();
  await page.locator('#take-image').click();
  await page.selectOption('#rollback-version', '1');
  await page.locator('#rollback').click();
  await page.locator('#take-image').click();
  await expect(page.locator('.wm-cell.wm-reverted')).not.toHaveCount(0);
  await scanAt('Watermark: a reverted block, read off the ciphertext with no key');

  await page.locator('#clear-images').click();
  await expect(page.locator('.wm-cell')).toHaveCount(0);
  await expect(page.locator('#wm-summary')).toContainText('1 disk image held');
  await scanAt('Watermark: images discarded — back to the single-image prompt');

  // ── Act 5: the version store toggle ─────────────────────────────────────
  await page.locator('#attacker-owns-store').check();
  await expect(page.locator('#comparison table.matrix tbody tr').nth(2)).toContainText('still authenticates');
  await scanAt('Compare: the attacker owns the version store — stage three falls back to stage two');

  await page.locator('#attacker-owns-store').uncheck();
  await expect(page.locator('#comparison table.matrix tbody tr').nth(2)).toContainText('STALE_VERSION');

  // ── Every disclosure, opened the way a reader opens it ──────────────────
  const disclosures = page.locator('details.more');
  for (let i = 0; i < 4; i++) {
    await disclosures.nth(i).locator('summary').click();
    await expect(disclosures.nth(i)).toHaveAttribute('open', '');
  }
  await expect(page.locator('details.more[open]')).toHaveCount(4);
  await scanAt('every disclosure open — the depth panels a reader has to ask for');

  // ── Hover, which persists after a click ─────────────────────────────────
  await page.locator('#write-sector').hover();
  await scanAt('a primary button hovered — its accent fill inverted');

  await page.locator('#flip-bit-button').hover();
  await scanAt('a danger button hovered');

  await page.locator('#act-disk .sector-tile').nth(3).hover();
  await scanAt('an unselected sector tile hovered');

  await page.locator('.cl-topbar .cl-btn').first().hover();
  await scanAt('a shared top bar control hovered — its color-mix fill repainted');

  // ── Focus rings on the controls that take them ──────────────────────────
  await page.locator('#write-text').focus();
  await expect(page.locator('#write-text')).toBeFocused();
  await scanAt('a text input focused, showing its focus-visible outline');

  await page.locator('#rollback-version').focus();
  await expect(page.locator('#rollback-version')).toBeFocused();
  await scanAt('the styled select focused — appearance:none plus a drawn chevron');

  await page.locator('#attacker-owns-store').focus();
  await expect(page.locator('#attacker-owns-store')).toBeFocused();
  await scanAt('the version-store checkbox focused');

  // ── Reformat, which returns the page to a clean volume with a log ───────
  await page.locator('#reset-volume').click();
  await expect(page.locator('#log-host li')).toHaveCount(1);
  await expect(page.locator('#disk-readout')).toContainText('INTACT');
  await expect(page.locator('.sector-tile .tile-state.s-alarm')).toHaveCount(0);
  await scanAt('the volume reformatted with fresh keys — every sector intact again');
}
