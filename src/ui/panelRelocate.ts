import { relocateBlock, relocateSector, rollbackSector } from '../volume/attacks.js';
import { BLOCK_BYTES, BLOCKS_PER_SECTOR, SECTOR_COUNT } from '../volume/types.js';
import { sectorToDisplay } from '../volume/text.js';
import { actCard, h, replace } from './dom.js';
import { groupedHex } from './format.js';
import { readout } from './readout.js';
import { numberField } from './fields.js';
import type { LabContext } from './state.js';

/**
 * Act 3 — moving bytes that are already encrypted, and putting old bytes back.
 *
 * Two different things happen here and the lab is careful not to conflate them.
 * A relocated block decrypts under the tweak of WHERE IT NOW SITS, so it yields
 * different, wrong plaintext: CORRUPTED (UNDETECTED). A rolled-back sector
 * decrypts perfectly, because those bytes really were written there under that
 * tweak: it succeeds cleanly and returns old data. Calling either one a
 * "failure" would smuggle in a detection event that does not exist.
 */
export function mountRelocatePanel(ctx: LabContext): { root: HTMLElement; refresh: () => void } {
  const root = actCard('act-relocate', 'ACT 3', 'Move it, or put it back');

  root.append(
    h('p', { class: 'lede' }, [
      'The tweak binds a block to its position — so moving encrypted bytes somewhere else does not hand the attacker a chosen plaintext, it hands the reader different wrong bytes with no warning. ',
      'Rolling a sector back to an earlier image is different again: nothing in XTS binds a version, so the old bytes decrypt perfectly and the read is clean, correct and wrong.',
    ]),
  );

  const targetHost = h('p', { class: 'readout-note', role: 'status', 'aria-live': 'polite', id: 'relocate-error' });

  // ── Move a block ───────────────────────────────────────────────────────
  root.append(h('h3', { text: 'Copy one ciphertext block somewhere else' }));
  const fromSector = numberField('rb-from-sector', 'From sector', 0, SECTOR_COUNT - 1, 1);
  const fromBlock = numberField('rb-from-block', 'From block', 0, BLOCKS_PER_SECTOR - 1, 0);
  const toSector = numberField('rb-to-sector', 'To sector', 0, SECTOR_COUNT - 1, 9);
  const toBlock = numberField('rb-to-block', 'To block', 0, BLOCKS_PER_SECTOR - 1, 0);
  const blockButton = h('button', { type: 'button', class: 'danger', id: 'relocate-block' }, [
    'Copy the block',
  ]) as HTMLButtonElement;
  blockButton.addEventListener('click', () => {
    const a = fromSector.value();
    const b = fromBlock.value();
    const c = toSector.value();
    const d = toBlock.value();
    if (a === null || b === null || c === null || d === null) {
      targetHost.textContent = 'Every address needs a whole number inside its stated range.';
      return;
    }
    targetHost.textContent = '';
    const result = relocateBlock(ctx.state.volume, { sector: a, block: b }, { sector: c, block: d });
    ctx.state.selectedSector = c;
    ctx.state.selectedBlock = d;
    ctx.state.ladderStep = d;
    ctx.record(result.description);
  });
  root.append(
    h('div', { class: 'controls' }, [
      fromSector.root,
      fromBlock.root,
      toSector.root,
      toBlock.root,
      blockButton,
    ]),
  );

  const tweakHost = h('div', {});
  root.append(tweakHost);

  // ── Move a whole sector ────────────────────────────────────────────────
  root.append(h('h3', { text: 'Copy a whole sector to a different sector number' }));
  const sectorFrom = numberField('rs-from', 'From sector', 0, SECTOR_COUNT - 1, 4);
  const sectorTo = numberField('rs-to', 'To sector', 0, SECTOR_COUNT - 1, 5);
  const sectorButton = h('button', { type: 'button', class: 'danger', id: 'relocate-sector' }, [
    'Copy the sector',
  ]) as HTMLButtonElement;
  sectorButton.addEventListener('click', () => {
    const a = sectorFrom.value();
    const b = sectorTo.value();
    if (a === null || b === null) {
      targetHost.textContent = 'Both sector numbers need a whole number inside the stated range.';
      return;
    }
    targetHost.textContent = '';
    const result = relocateSector(ctx.state.volume, a, b);
    ctx.state.selectedSector = b;
    ctx.state.selectedBlock = 0;
    ctx.state.ladderStep = 0;
    ctx.record(result.description);
  });
  root.append(h('div', { class: 'controls' }, [sectorFrom.root, sectorTo.root, sectorButton]));

  // ── Roll a sector back ─────────────────────────────────────────────────
  root.append(h('h3', { text: 'Put an earlier image of a sector back over itself' }));
  root.append(
    h('p', { class: 'lede', text: 'Write a sector twice first, then restore version 1. Nothing is corrupted; the read is clean and the data is old.' }),
  );
  const rollbackSectorField = numberField('rollback-sector', 'Sector', 0, SECTOR_COUNT - 1, 9);
  const versionSelect = h('select', { id: 'rollback-version' }) as HTMLSelectElement;
  const versionField = h('div', { class: 'field' }, [
    h('label', { for: 'rollback-version', text: 'Restore version' }),
    versionSelect,
  ]);
  const rollbackButton = h('button', { type: 'button', class: 'danger', id: 'rollback' }, [
    'Restore that image',
  ]) as HTMLButtonElement;
  rollbackButton.addEventListener('click', () => {
    const sector = rollbackSectorField.value();
    const version = Number(versionSelect.value);
    if (sector === null || !Number.isInteger(version) || version < 1) {
      targetHost.textContent = 'Pick a sector and one of the versions it actually has.';
      return;
    }
    targetHost.textContent = '';
    const result = rollbackSector(ctx.state.volume, sector, version);
    ctx.state.selectedSector = sector;
    ctx.record(result.description);
  });
  rollbackSectorField.input.addEventListener('change', () => ctx.refresh());
  root.append(
    h('div', { class: 'controls' }, [rollbackSectorField.root, versionField, rollbackButton]),
    targetHost,
  );

  const readoutHost = h('div', { role: 'status', 'aria-live': 'polite', id: 'relocate-readout' });
  root.append(readoutHost);

  function refresh(): void {
    const { volume } = ctx.state;

    // Version options track the sector actually named in the rollback field.
    const rollbackTarget = rollbackSectorField.value() ?? ctx.state.selectedSector;
    const history = volume.history(rollbackTarget);
    const previous = versionSelect.value;
    replace(
      versionSelect,
      history.map((entry) =>
        h('option', { value: String(entry.version) }, [`version ${entry.version} — "${entry.label.slice(0, 34)}"`]),
      ),
    );
    if (history.some((entry) => String(entry.version) === previous)) versionSelect.value = previous;
    rollbackButton.disabled = history.length < 2;

    replace(readoutHost, [readout(volume.read(ctx.state.selectedSector))]);

    // The tweak mismatch, printed rather than described: the tweak that made
    // those bytes, beside the tweak they are now being read under.
    const a = fromSector.value();
    const b = fromBlock.value();
    const c = toSector.value();
    const d = toBlock.value();
    if (a === null || b === null || c === null || d === null) {
      replace(tweakHost, []);
    } else {
      const sourceTweak = volume.tweakFor(a, b);
      const destTweak = volume.tweakFor(c, d);
      const destRead = volume.read(c);
      const off = d * BLOCK_BYTES;
      replace(tweakHost, [
        h('h4', { text: 'The tweak that made those bytes, and the tweak they would be read under' }),
        h('div', { class: 'ladder' }, [
          row(`T for sector ${a}, block ${b}`, groupedHex(sourceTweak)),
          row(`T for sector ${c}, block ${d}`, groupedHex(destTweak)),
          row(
            'plaintext there now',
            sectorToDisplay(destRead.plaintext.subarray(off, off + BLOCK_BYTES)),
          ),
        ]),
        h('p', {
          class: 'readout-note',
          text: 'Two different field elements, so AES-K1 is handed two different inputs and returns two unrelated results. The mode has no way to notice that the block came from somewhere else — it simply decrypts what it finds, under the tweak of where it found it.',
        }),
      ]);
    }
  }

  return { root, refresh };
}

function row(label: string, value: string): HTMLElement {
  return h('div', { class: 'ladder-row' }, [
    h('span', { class: 'ladder-label', text: label }),
    h('span', { class: 'hexline', text: value }),
  ]);
}
