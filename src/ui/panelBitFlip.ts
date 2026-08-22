import { flipCiphertextBit } from '../volume/attacks.js';
import { BLOCK_BYTES, BLOCKS_PER_SECTOR, SECTOR_BYTES, SECTOR_COUNT } from '../volume/types.js';
import { printableFraction, sectorToDisplay } from '../volume/text.js';
import { actCard, h, replace } from './dom.js';
import { groupedHex, TONE_ALARM, TONE_OK, verdictPill } from './format.js';
import { readout } from './readout.js';
import { numberField } from './fields.js';
import type { LabContext } from './state.js';

/**
 * Act 2 — one bit.
 *
 * The learner picks the bit, presses the button, and the real cipher decides
 * what comes back. Nothing here is staged: the flip lands on the stored
 * ciphertext and the plaintext shown afterwards is `decryptSector` output.
 */
export function mountBitFlipPanel(ctx: LabContext): { root: HTMLElement; refresh: () => void } {
  const root = actCard('act-flip', 'ACT 2', 'Flip one bit');

  root.append(
    h('p', { class: 'lede' }, [
      'Change a single bit of stored ciphertext — the kind of edit a malicious storage backend, a stolen laptop or a bad cable can make. ',
      'Its own 16-byte block turns to noise. The other thirty-one are perfect. Nothing is raised, because there is nothing to raise it with.',
    ]),
  );

  const sectorInput = numberField('flip-sector', 'Sector', 0, SECTOR_COUNT - 1, 7);
  const byteInput = numberField('flip-byte', 'Ciphertext byte', 0, SECTOR_BYTES - 1, 20);
  const bitInput = numberField('flip-bit', 'Bit in that byte', 0, 7, 3);
  const flipButton = h('button', { type: 'button', class: 'danger', id: 'flip-bit-button' }, [
    'Flip this bit',
  ]) as HTMLButtonElement;

  const errorHost = h('p', { class: 'readout-note', role: 'status', 'aria-live': 'polite', id: 'flip-error' });

  flipButton.addEventListener('click', () => {
    const sector = sectorInput.value();
    const byte = byteInput.value();
    const bit = bitInput.value();
    if (sector === null || byte === null || bit === null) {
      errorHost.textContent = 'Every field needs a whole number inside its stated range before a bit can be flipped.';
      return;
    }
    errorHost.textContent = '';
    const result = flipCiphertextBit(ctx.state.volume, sector, byte, bit);
    ctx.state.selectedSector = sector;
    ctx.state.selectedBlock = Math.floor(byte / BLOCK_BYTES);
    ctx.state.ladderStep = ctx.state.selectedBlock;
    ctx.record(result.description);
  });

  root.append(
    h('div', { class: 'controls' }, [sectorInput.root, byteInput.root, bitInput.root, flipButton]),
    errorHost,
  );

  const readoutHost = h('div', { role: 'status', 'aria-live': 'polite', id: 'flip-readout' });
  const detailHost = h('div', {});
  root.append(readoutHost, detailHost);

  function refresh(): void {
    const sector = sectorInput.value() ?? ctx.state.selectedSector;
    const read = ctx.state.volume.read(sector);
    replace(readoutHost, [readout(ctx.state.volume, read)]);

    const damaged = read.changedBlocks;
    const focus = damaged.length ? damaged[0] : ctx.state.selectedBlock;
    const off = focus * BLOCK_BYTES;
    const wasText = sectorToDisplay(read.expected.subarray(off, off + BLOCK_BYTES));
    const nowText = sectorToDisplay(read.plaintext.subarray(off, off + BLOCK_BYTES));
    const nowPrintable = printableFraction(read.plaintext.subarray(off, off + BLOCK_BYTES));

    replace(detailHost, [
      h('h4', { text: `Block ${focus} of sector ${sector}, before and after` }),
      h('div', { class: 'ladder' }, [
        line('written', wasText),
        line('read back', nowText),
        line('written, hex', groupedHex(read.expected.subarray(off, off + BLOCK_BYTES))),
        line('read back, hex', groupedHex(read.plaintext.subarray(off, off + BLOCK_BYTES))),
        h('div', { class: 'ladder-row' }, [
          h('span', { class: 'ladder-label', text: 'reads as text' }),
          verdictPill(
            nowPrintable === 1 ? TONE_OK : TONE_ALARM,
            `${Math.round(nowPrintable * 100)}% of these 16 bytes are printable`,
          ),
        ]),
      ]),
      h('p', {
        class: 'readout-note',
        text: `${damaged.length} of ${BLOCKS_PER_SECTOR} blocks in this sector differ from what was written. XTS decrypts each block independently under its own tweak, so damage cannot spread past the block it lands in — and cannot be noticed outside it either.`,
      }),
      h('details', { class: 'more' }, [
        h('summary', { text: 'Why exactly one block, and not the rest of the sector' }),
        h('p', {
          text: 'A CBC-style chained mode would carry the damage forward into every following block. XTS chains nothing: block j is AES-K1(P ⊕ T_j) ⊕ T_j, and T_j depends only on the sector number and j. That independence is what makes a disk usable — you can read block 900 without decrypting the 899 before it — and it is also why a one-bit edit is a one-block edit, indistinguishable from data that was simply always that way.',
        }),
      ]),
    ]);
  }

  return { root, refresh };
}

function line(label: string, value: string): HTMLElement {
  return h('div', { class: 'ladder-row' }, [
    h('span', { class: 'ladder-label', text: label }),
    h('span', { class: 'textline', text: value }),
  ]);
}
