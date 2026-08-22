import { expect, test, type Page } from '@playwright/test';

/**
 * The claims suite: does the page tell the truth?
 *
 * The rule that makes these worth anything is that they compare two values the
 * PAGE printed, or re-derive a claim from the page's own raw inputs by a
 * different route than `src/` takes. A test that recomputes the same
 * expression the source uses will agree with a bug quite happily.
 *
 * So the tweak ladder is checked by multiplying by alpha with BigInt shifts
 * here in the test — nothing like the byte-at-a-time carry chain in
 * `gf128.ts`; the "blocks differing" counter is checked against an independent
 * count of the block cells the page painted; the overhead percentages are
 * recomputed from the byte counts printed beside them; and the failure-code
 * inventory is checked against the read-out that names the same codes in
 * completely different markup.
 */

const HEX = /[0-9a-f]{2}(?: [0-9a-f]{2})+/;

function parseHex(text: string): Uint8Array {
  const match = text.match(HEX);
  if (!match) throw new Error(`no hex run found in: ${text.slice(0, 120)}`);
  return Uint8Array.from(match[0].split(' ').map((b) => parseInt(b, 16)));
}

/** Multiply by alpha in GF(2^128), IEEE 1619 byte order — via one BigInt. */
function alphaTimes(bytes: Uint8Array): Uint8Array {
  let value = 0n;
  for (let i = 15; i >= 0; i--) value = (value << 8n) | BigInt(bytes[i]);
  let shifted = value << 1n;
  if (shifted >> 128n) shifted = (shifted & ((1n << 128n) - 1n)) ^ 0x87n;
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[i] = Number((shifted >> BigInt(8 * i)) & 0xffn);
  return out;
}

const hex = (b: Uint8Array): string => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');

async function ladderRow(page: Page, label: string): Promise<string> {
  const row = page.locator('#ladder .ladder-row', { has: page.locator('.ladder-label', { hasText: label }) });
  return (await row.first().innerText()).replace(/\s+/g, ' ');
}

async function boot(page: Page): Promise<string[]> {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(`console.error: ${m.text()}`);
  });
  await page.goto('.');
  await expect(page.locator('#comparison table.matrix')).toBeVisible();
  return errors;
}

test.describe('the page and the head agree with the fleet standard', () => {
  test('title, single meta description, language, pinned theme, inline favicon', async ({ page }) => {
    await boot(page);
    await expect(page).toHaveTitle('Sector Vault — crypto-lab');
    await expect(page.locator('html')).toHaveAttribute('lang', 'en');
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
    await expect(page.locator('meta[name="description"]')).toHaveCount(1);
    const favicon = await page.locator('link[rel="icon"]').getAttribute('href');
    expect(favicon, 'the favicon must be an inline data URI, immune to the subpath 404').toMatch(/^data:image\/svg\+xml,/);
    await expect(page.locator('link[href^="/favicon"]')).toHaveCount(0);
    // The theme is written under exactly one key.
    expect(await page.evaluate(() => Object.keys(localStorage).sort())).toEqual(['theme']);
    expect(await page.evaluate(() => localStorage.getItem('theme'))).toBe('dark');
  });

  test('exactly one h1, one main, one banner, and the scripture footer verbatim', async ({ page }) => {
    await boot(page);
    await expect(page.locator('h1')).toHaveCount(1);
    await expect(page.locator('main')).toHaveCount(1);
    const footers = page.locator('.scripture-footer');
    await expect(footers).toHaveCount(1);
    await expect(footers).toHaveText(
      'So whether you eat or drink or whatever you do, do it all for the glory of God. — 1 Corinthians 10:31',
    );
    // Last visible element on the page.
    const lastText = await page.evaluate(() => {
      const all = [...document.querySelectorAll('body *')].filter(
        (el) => (el as HTMLElement).checkVisibility?.() && (el.textContent ?? '').trim(),
      );
      return all[all.length - 1]?.textContent?.trim() ?? '';
    });
    expect(lastText).toContain('1 Corinthians 10:31');
  });

  test('nothing carrying the hidden attribute is actually rendered', async ({ page }) => {
    await boot(page);
    // The [hidden] cascade trap: a class rule setting `display` outranks the UA
    // `[hidden]` rule, so an element can paint while the code believes it is
    // hidden. Assert the outcome rather than the attribute.
    const painted = await page.evaluate(() =>
      [...document.querySelectorAll('[hidden]')]
        .filter((el) => (el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true }))
        .map((el) => el.tagName.toLowerCase() + '.' + el.className),
    );
    expect(painted, 'elements with [hidden] that still paint').toEqual([]);
  });
});

test.describe('the tweak ladder shows the operation the cipher performs', () => {
  test('T(j+1) really is T(j) multiplied by alpha, re-derived with BigInt shifts', async ({ page }) => {
    const errors = await boot(page);
    for (let step = 0; step < 6; step++) {
      const current = parseHex(await ladderRow(page, 'current'));
      const shifted = parseHex(await ladderRow(page, 'shift'));
      const result = parseHex(await ladderRow(page, 'result'));
      const carryText = await ladderRow(page, 'carry out');

      // Independent re-derivation, by a completely different route.
      expect(hex(result), `alpha times T${step}`).toBe(hex(alphaTimes(current)));

      // Parts sum to whole: the printed shift is the printed input shifted,
      // and the printed result is the shift with the reduction applied exactly
      // when the page says the carry fired.
      const carry = current[15] >>> 7;
      expect(carryText).toContain(`is ${carry}`);
      const expectedShift = new Uint8Array(16);
      let borrow = 0;
      for (let i = 0; i < 16; i++) {
        const next = current[i] >>> 7;
        expectedShift[i] = ((current[i] << 1) | borrow) & 0xff;
        borrow = next;
      }
      expect(hex(shifted)).toBe(hex(expectedShift));
      const reduced = Uint8Array.from(expectedShift);
      if (carry) reduced[0] ^= 0x87;
      expect(hex(result)).toBe(hex(reduced));
      expect(carryText).toContain(carry ? 'XOR 0x87' : 'no reduction');

      // Stepping must land on the value the page just predicted.
      await page.locator('#ladder-step').click();
      await expect(page.locator('#ladder')).toContainText(`current  j = ${step + 1}`);
      expect(hex(parseHex(await ladderRow(page, 'current')))).toBe(hex(result));
    }
    expect(errors, errors.join('\n')).toEqual([]);
  });

  test('the XEX sandwich the page prints is internally consistent and matches the platter', async ({ page }) => {
    await boot(page);
    // Block 7, not the default block 0. At j = 0 the tweak is T_0 itself and
    // alpha never runs, so a broken ladder is invisible here — which a mutation
    // of `tweakForBlock` demonstrated by leaving this test green.
    await page.locator('#act-disk .block-cell').nth(7).click();
    await expect(page.locator('#ladder')).toContainText('current  j = 7');
    const rows = await page.locator('#act-disk .ladder').last().locator('.ladder-row').allInnerTexts();
    const find = (label: string): Uint8Array => {
      const row = rows.find((r) => r.replace(/\s+/g, ' ').toLowerCase().includes(label.toLowerCase()));
      if (!row) throw new Error(`no sandwich row for ${label}: ${rows.join(' | ')}`);
      return parseHex(row.replace(/\s+/g, ' '));
    };
    const p = find('P (as written)');
    const t = find('T7');
    const masked = find('P ⊕ T');
    const aes = find('AES-K1');
    const c = find('⊕ T again');
    const platter = find('on the platter');

    for (let i = 0; i < 16; i++) {
      expect(masked[i], `byte ${i} of P xor T`).toBe(p[i] ^ t[i]);
      expect(c[i], `byte ${i} of AES output xor T`).toBe(aes[i] ^ t[i]);
    }
    expect(hex(c), 'the sandwich must reproduce the ciphertext really on the platter').toBe(hex(platter));
    await expect(page.locator('#act-disk .ladder').last()).toContainText('BYTE-FOR-BYTE EQUAL');
  });
});

test.describe('NEG-1: XTS reports nothing about an edited ciphertext', () => {
  test('a flipped bit damages one block, and the counter agrees with the painted cells', async ({ page }) => {
    await boot(page);
    await page.fill('#flip-sector', '7');
    await page.fill('#flip-byte', '20');
    await page.fill('#flip-bit', '3');
    await page.getByRole('button', { name: 'Flip this bit' }).click();

    const readout = page.locator('#flip-readout');
    await expect(readout).toContainText('CORRUPTED (UNDETECTED)');
    await expect(readout).toContainText('none — there is none to give');
    await expect(readout).toContainText('errors raised');

    // The counter, parsed from the page...
    const counterText = await readout.locator('.readout-line', { hasText: 'blocks differing' }).innerText();
    const printed = Number(counterText.replace(/\s+/g, ' ').match(/(\d+) of 32/)?.[1]);
    expect(printed).toBe(1);

    // ...against an independent count of what the disk panel actually painted.
    const painted = await page.locator('#act-disk .block-cell.fill-alarm').count();
    expect(painted, 'the disk panel must paint exactly as many damaged blocks as the read-out counts').toBe(printed);

    // And the block it names is the block the byte offset falls in.
    await expect(readout).toContainText('block 1 (bytes 16–31)');
    expect(Math.floor(20 / 16)).toBe(1);

    // Every other sector is untouched: the damage cannot spread.
    const alarmTiles = await page.locator('.sector-tile .tile-state.s-alarm').count();
    expect(alarmTiles).toBe(1);
  });

  test('the read-out and the failure-code table name the same two XTS codes', async ({ page }) => {
    await boot(page);
    const fromReadout = (await page.locator('#disk-readout').innerText())
      .replace(/\s+/g, ' ')
      .match(/codes this mode has ([A-Z_ ·]+?) Both/)?.[1]
      .trim()
      .split(' · ');
    expect(fromReadout).toBeTruthy();

    const rows = await page.locator('#act-compare table.matrix').nth(1).locator('tbody tr').all();
    const availableForXts: string[] = [];
    for (const row of rows) {
      const code = (await row.locator('th').innerText()).trim();
      const cell = (await row.locator('td').first().innerText()).replace(/\s+/g, ' ');
      if (cell.includes('available')) availableForXts.push(code);
    }
    expect(availableForXts, 'two surfaces, printed by different code, must name the same codes').toEqual(fromReadout);
    expect(availableForXts).toEqual(['MALFORMED_SECTOR', 'KEY_LENGTH_INVALID']);
  });
});

test.describe('relocation and rollback are different things, and the page says so', () => {
  test('a relocated sector is CORRUPTED (UNDETECTED); a rolled-back one succeeds cleanly', async ({ page }) => {
    await boot(page);
    await page.fill('#rs-from', '4');
    await page.fill('#rs-to', '5');
    await page.getByRole('button', { name: 'Copy the sector' }).click();
    const readout = page.locator('#relocate-readout');
    await expect(readout).toContainText('CORRUPTED (UNDETECTED)');
    await expect(readout).not.toContainText('SUCCEEDS CLEANLY');

    // Sector 9 arrives with two versions, so a rollback is available at once.
    await page.fill('#rollback-sector', '9');
    await page.locator('#rollback-sector').dispatchEvent('change');
    await page.selectOption('#rollback-version', '1');
    await page.getByRole('button', { name: 'Restore that image' }).click();
    await expect(readout).toContainText('SUCCEEDS CLEANLY (STALE)');
    await expect(readout).not.toContainText('CORRUPTED (UNDETECTED)');
    await expect(readout).toContainText('version 1, which is not the current one');
    await expect(readout).toContainText('Not corruption');
    // Still no failure code, in either case.
    await expect(readout).toContainText('none — there is none to give');
  });

  test('a stale verdict is retired when the sector is written again', async ({ page }) => {
    await boot(page);
    await page.fill('#flip-sector', '3');
    await page.fill('#flip-byte', '0');
    await page.getByRole('button', { name: 'Flip this bit' }).click();
    await expect(page.locator('#flip-readout')).toContainText('CORRUPTED (UNDETECTED)');

    // Selecting the same sector again must NOT change the verdict — the no-op
    // guard, so a re-render cannot be mistaken for a fresh result.
    const before = await page.locator('#flip-readout').innerText();
    await page.getByRole('button', { name: /^Sector 3/ }).click();
    expect(await page.locator('#flip-readout').innerText(), 're-selecting the same sector must not produce a fresh verdict').toBe(before);

    // Rewriting the sector retires the verdict entirely.
    await page.getByRole('button', { name: /^Sector 3/ }).click();
    await page.fill('#write-text', 'REWRITTEN AFTER THE DAMAGE');
    await page.getByRole('button', { name: 'Write sector' }).click();
    await expect(page.locator('#disk-readout')).toContainText('INTACT');
    await expect(page.locator('#disk-readout')).not.toContainText('CORRUPTED (UNDETECTED)');
    await expect(page.locator('#flip-readout')).not.toContainText('CORRUPTED (UNDETECTED)');
  });

  test('an out-of-range address is refused, names the cause, and changes nothing', async ({ page }) => {
    await boot(page);
    const before = await page.locator('#flip-readout').innerText();
    await page.fill('#flip-byte', '9999');
    await page.getByRole('button', { name: 'Flip this bit' }).click();
    await expect(page.locator('#flip-error')).toContainText('inside its stated range');
    await expect(page.locator('#flip-byte')).toHaveAttribute('aria-invalid', 'true');
    expect(await page.locator('#flip-readout').innerText(), 'a refused edit must not alter the volume').toBe(before);
  });
});

test.describe('watermarking uses no key', () => {
  test('the reverted-block count matches the cells the page painted', async ({ page }) => {
    await boot(page);
    // Image 1 is the volume as found. Write sector 9 again, image it, then put
    // the previous version back and image it once more: the ciphertext of that
    // sector's first block goes A, B, A — which is a rollback, read straight
    // off three disk images with no key involved.
    await page.getByRole('button', { name: /^Sector 9/ }).click();
    await page.fill('#write-text', 'LEDGER 2026-08-04  TRANSFER OUT            250000.00 EUR');
    await page.getByRole('button', { name: 'Write sector' }).click();
    await page.getByRole('button', { name: 'Take a disk image' }).click();

    await page.fill('#rollback-sector', '9');
    await page.locator('#rollback-sector').dispatchEvent('change');
    await page.selectOption('#rollback-version', '2');
    await page.getByRole('button', { name: 'Restore that image' }).click();
    await page.getByRole('button', { name: 'Take a disk image' }).click();

    const summary = (await page.locator('#wm-summary').innerText()).replace(/\s+/g, ' ');
    const changed = Number(summary.match(/(\d+) of \d+ blocks changed/)?.[1]);
    const reverted = Number(summary.match(/(\d+) returned to a value/)?.[1]);
    expect(Number.isInteger(changed) && changed > 0).toBe(true);
    expect(reverted).toBeGreaterThan(0);

    // Independent counts from the painted grid.
    expect(await page.locator('.wm-cell.wm-reverted').count()).toBe(reverted);
    expect(await page.locator('.wm-cell.wm-changed').count() + reverted).toBe(changed);
    await expect(page.locator('#wm-summary')).toContainText('no key was used');
  });
});

test.describe('the three-stage comparison', () => {
  test('the matrix reads exactly as the thesis states, and every cell was computed', async ({ page }) => {
    await boot(page);
    const table = page.locator('#comparison table.matrix');
    const cellText = async (row: number, col: number): Promise<string> =>
      (await table.locator('tbody tr').nth(row).locator('td').nth(col).innerText()).replace(/\s+/g, ' ');

    expect(await cellText(0, 0)).toContain('CORRUPTED (UNDETECTED)');
    expect(await cellText(0, 1)).toContain('CORRUPTED (UNDETECTED)');
    expect(await cellText(0, 1)).toContain('tweak is position-bound');
    expect(await cellText(0, 2)).toContain('succeeds cleanly');
    expect(await cellText(1, 0)).toContain('BAD_TAG');
    expect(await cellText(1, 1)).toContain('BAD_TAG');
    expect(await cellText(1, 2)).toContain('still authenticates');
    expect(await cellText(1, 2)).toContain('RFC 5116');
    expect(await cellText(2, 0)).toContain('BAD_TAG');
    expect(await cellText(2, 1)).toContain('BAD_TAG');
    expect(await cellText(2, 2)).toContain('STALE_VERSION');
    // The XTS row never claims a detection: nothing in it is green.
    expect(await table.locator('tbody tr').nth(0).locator('.fill-ok').count()).toBe(0);
  });

  test('the version store toggle moves exactly one cell', async ({ page }) => {
    await boot(page);
    const labels = async (): Promise<string[]> =>
      (await page.locator('#comparison table.matrix tbody .verdict').allInnerTexts()).map((t) =>
        t.replace(/\s+/g, ' ').trim(),
      );
    const before = await labels();
    await page.locator('#attacker-owns-store').check();
    await expect(page.locator('#comparison')).toContainText('still authenticates');
    const after = await labels();
    expect(before.length).toBe(9);
    const moved = before.map((v, i) => (v === after[i] ? null : i)).filter((i) => i !== null);
    expect(moved.length, 'only the stage-three rollback cell may move').toBe(1);
    expect(moved[0]).toBe(8);
    expect(after[8]).toContain('still authenticates');
  });

  test('the storage overhead is arithmetic, and the parts add up to the whole', async ({ page }) => {
    await boot(page);
    const table = page.locator('#act-compare table.matrix').last();
    for (const row of await table.locator('tbody tr').all()) {
      const cells = await row.locator('td').allInnerTexts();
      const bytes = Number(cells[0].trim());
      const expansion = Number(cells[1].replace('%', ''));
      // The percentage is re-derived from the byte count printed beside it.
      expect(expansion).toBeCloseTo((bytes / 512) * 100, 2);
      // The itemised parts must sum to the total.
      const parts = [...cells[2].matchAll(/(\d+)-byte/g)].map((m) => Number(m[1]));
      expect(parts.reduce((a, b) => a + b, 0)).toBe(bytes);
    }
  });

  test('the page names the honest caveats rather than ending on a clean win', async ({ page }) => {
    await boot(page);
    const notes = (await page.locator('#act-compare .notes').innerText()).replace(/\s+/g, ' ');
    expect(notes).toContain('sector number as the GCM nonce');
    expect(notes).toContain('96 fresh random bits');
    expect(notes).toContain('moved the rollback target');
    const scope = (await page.locator('#act-compare').innerText()).replace(/\s+/g, ' ');
    expect(scope).toContain('SP 800-38E');
    expect(scope).toContain('dm-integrity');
    expect(scope).toContain('T10 Protection Information');
    // The cross-link to the sibling lab lives behind a disclosure, so open it
    // the way a reader would rather than reading through the closed element.
    await page.locator('#act-compare details.more > summary').click();
    await expect(page.locator('#act-compare details.more[open]')).toHaveCount(1);
    await expect(page.locator('#act-compare details.more')).toContainText('Stream Ward');
    await expect(
      page.locator('#act-compare a[href="https://systemslibrarian.github.io/crypto-lab-stream-ward/"]'),
    ).toHaveCount(1);
  });

  test('the negative claim is pinned to XTS, not to full-disk encryption at large', async ({ page }) => {
    await boot(page);
    const scope = (await page.locator('#scope').innerText()).replace(/\s+/g, ' ');
    expect(scope).toContain('XTS-based, confidentiality-only full-disk encryption does not detect adversarial modification or rollback');
    expect(scope).toContain('pinned to XTS, not to full-disk encryption in general');
    expect(scope).toContain('Not production cryptography');
    expect(scope).toContain('This is a teaching demo');
    expect(scope).toContain('does not show a weakness in AES');
  });
});

test.describe('the document itself is well formed', () => {
  test('no id appears twice, and every control has an accessible name', async ({ page }) => {
    await boot(page);
    // A duplicated id silently breaks every `for=`/`aria-labelledby` pointing
    // at the second one, and axe only catches some of the shapes it produces.
    const duplicates = await page.evaluate(() => {
      const counts = new Map<string, number>();
      for (const el of document.querySelectorAll('[id]')) {
        counts.set(el.id, (counts.get(el.id) ?? 0) + 1);
      }
      return [...counts].filter(([, n]) => n > 1).map(([id, n]) => `${id} x${n}`);
    });
    expect(duplicates).toEqual([]);

    const unnamed = await page.evaluate(() =>
      [...document.querySelectorAll<HTMLElement>('#app button, #app input, #app select, #app textarea')]
        .filter((el) => {
          if (el.getAttribute('aria-label')) return false;
          if (el.id && document.querySelector(`label[for="${CSS.escape(el.id)}"]`)) return false;
          return !(el.textContent ?? '').trim();
        })
        .map((el) => `${el.tagName.toLowerCase()}#${el.id || '(no id)'}`),
    );
    expect(unnamed).toEqual([]);
  });
});
