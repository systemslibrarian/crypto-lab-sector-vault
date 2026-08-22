import { BLOCK_BYTES, BLOCKS_PER_SECTOR, SECTOR_BYTES, SECTOR_COUNT } from '../volume/types.js';
import { sectorToDisplay } from '../volume/text.js';
import { toHex, sequenceNumberToBlock, equalBytes } from '../crypto/bytes.js';
import { mulAlphaTraced, REDUCTION_BYTE } from '../crypto/gf128.js';
import { actCard, h, replace, scroller } from './dom.js';
import { groupedHex, statusLabel, toneForStatus, verdictPill } from './format.js';
import { readout } from './readout.js';
import type { LabContext } from './state.js';

/**
 * Act 1 — the disk, and the tweak that binds every block to where it sits.
 *
 * The tweak ladder is the one mechanism this lab exists to show. It is stepped
 * by the reader rather than animated at them, it prints the real 16 bytes the
 * cipher will use, and every intermediate comes from `mulAlphaTraced`, the same
 * function `mulAlpha` is tested against — so the drawn shift-and-reduce cannot
 * describe an operation the cipher does not perform.
 */
export function mountDiskPanel(ctx: LabContext): { root: HTMLElement; refresh: () => void } {
  const root = actCard('act-disk', 'ACT 1', 'The disk');

  root.append(
    h('p', { class: 'lede' }, [
      'Sixteen sectors of 512 bytes, each encrypted with XTS-AES-128 under two session keys held only in memory. ',
      'The sector number is the data unit sequence number, so every sector gets its own tweak — and every 16-byte block inside it gets that tweak multiplied by a further power of α. ',
      'Pick a sector, write to it, then open a block and step the tweak.',
    ]),
  );

  // ── Sector grid ────────────────────────────────────────────────────────
  const grid = h('div', { class: 'sector-grid', role: 'group', 'aria-label': 'Volume map: 16 sectors' });
  const tiles: HTMLButtonElement[] = [];
  for (let sector = 0; sector < SECTOR_COUNT; sector++) {
    const tile = h('button', { type: 'button', class: 'sector-tile', 'aria-pressed': 'false' }, [
      h('span', { class: 'tile-id' }),
      h('span', { class: 'tile-state' }),
      h('span', { class: 'tile-text' }),
    ]) as HTMLButtonElement;
    tile.addEventListener('click', () => {
      ctx.state.selectedSector = sector;
      ctx.state.selectedBlock = 0;
      ctx.state.ladderStep = 0;
      ctx.refresh();
    });
    tiles.push(tile);
    grid.append(tile);
  }
  root.append(grid);

  // ── Write form ─────────────────────────────────────────────────────────
  const writeInput = h('input', {
    type: 'text',
    id: 'write-text',
    maxlength: String(SECTOR_BYTES),
    autocomplete: 'off',
    spellcheck: 'false',
  }) as HTMLInputElement;
  const writeLabel = h('label', { for: 'write-text', id: 'write-label' });
  const writeButton = h('button', { type: 'button', class: 'primary', id: 'write-sector' }, [
    'Write sector',
  ]) as HTMLButtonElement;
  writeButton.addEventListener('click', () => {
    const text = writeInput.value;
    ctx.state.volume.writeText(ctx.state.selectedSector, text);
    ctx.record(`Wrote sector ${ctx.state.selectedSector}: "${text.slice(0, 48)}"`);
  });
  root.append(
    h('div', { class: 'controls' }, [
      h('div', { class: 'field' }, [writeLabel, writeInput]),
      writeButton,
    ]),
  );

  // ── Read-out ───────────────────────────────────────────────────────────
  const readoutHost = h('div', { role: 'status', 'aria-live': 'polite', id: 'disk-readout' });
  root.append(readoutHost);

  // ── Decrypted text ─────────────────────────────────────────────────────
  const textHost = h('div', {});
  root.append(textHost);

  // ── Block strip ────────────────────────────────────────────────────────
  root.append(h('h3', { text: 'Blocks in this sector' }));
  root.append(
    h('p', { class: 'lede', text: `Each cell is one 16-byte AES block and the first two bytes of its ciphertext. Select one to see the tweak that produced it.` }),
  );
  const strip = h('div', { class: 'block-strip' });
  const blockCells: HTMLButtonElement[] = [];
  for (let block = 0; block < BLOCKS_PER_SECTOR; block++) {
    const cell = h('button', { type: 'button', class: 'block-cell', 'aria-pressed': 'false' }, [
      h('span', { class: 'cell-j' }),
      h('span', { class: 'cell-hex' }),
    ]) as HTMLButtonElement;
    cell.addEventListener('click', () => {
      ctx.state.selectedBlock = block;
      ctx.state.ladderStep = block;
      ctx.refresh();
    });
    blockCells.push(cell);
    strip.append(cell);
  }
  root.append(scroller('Blocks in the selected sector', strip));

  // ── The tweak ladder ───────────────────────────────────────────────────
  root.append(h('h3', { text: 'The tweak, one multiplication at a time' }));
  root.append(
    h('p', { class: 'lede' }, [
      'T₀ is AES under the tweak key K2 of the sector number. Every following block multiplies that by α — the primitive element x of GF(2¹²⁸) — which in the byte order the standard fixes is one left shift of all 128 bits plus a single conditional XOR of 0x87. ',
      'Step it and watch the carry decide.',
    ]),
  );

  const ladderHost = h('div', { class: 'ladder', role: 'status', 'aria-live': 'polite', id: 'ladder' });
  const backButton = h('button', { type: 'button', id: 'ladder-back' }, ['‹ Back']) as HTMLButtonElement;
  const stepButton = h('button', { type: 'button', class: 'primary', id: 'ladder-step' }, [
    'Multiply by α ›',
  ]) as HTMLButtonElement;
  const resetButton = h('button', { type: 'button', id: 'ladder-reset' }, ['Reset to j = 0']) as HTMLButtonElement;
  backButton.addEventListener('click', () => {
    ctx.state.ladderStep = Math.max(0, ctx.state.ladderStep - 1);
    ctx.refresh();
  });
  stepButton.addEventListener('click', () => {
    ctx.state.ladderStep = Math.min(BLOCKS_PER_SECTOR - 1, ctx.state.ladderStep + 1);
    ctx.refresh();
  });
  resetButton.addEventListener('click', () => {
    ctx.state.ladderStep = 0;
    ctx.refresh();
  });
  root.append(ladderHost, h('div', { class: 'controls' }, [backButton, stepButton, resetButton]));

  // ── The XEX sandwich for the selected block ────────────────────────────
  const sandwichHost = h('div', {});
  root.append(sandwichHost);

  function refresh(): void {
    const { volume, selectedSector, selectedBlock, ladderStep } = ctx.state;
    const reads = volume.readAll();

    for (let sector = 0; sector < SECTOR_COUNT; sector++) {
      const tile = tiles[sector];
      const read = reads[sector];
      const tone = toneForStatus(read.status);
      tile.setAttribute('aria-pressed', String(sector === selectedSector));
      const [id, state, text] = Array.from(tile.children) as HTMLElement[];
      id.textContent = `SECTOR ${String(sector).padStart(2, '0')}`;
      state.textContent = `${tone.glyph} ${statusLabel(read.status)}`;
      state.className = `tile-state ${read.status === 'INTACT' ? 's-ok' : 's-alarm'}`;
      text.textContent = sectorToDisplay(read.plaintext, 24);
      tile.setAttribute(
        'aria-label',
        `Sector ${sector}: ${statusLabel(read.status)}. Reads as "${sectorToDisplay(read.plaintext, 24).trim()}"`,
      );
    }

    const read = reads[selectedSector];
    const history = volume.history(selectedSector);
    writeLabel.textContent = `Text to write into sector ${selectedSector} (padded to ${SECTOR_BYTES} bytes)`;
    if (document.activeElement !== writeInput) {
      writeInput.value = history.length ? history[history.length - 1].label : '';
    }

    replace(readoutHost, [readout(read)]);

    replace(textHost, [
      h('h4', { text: `Sector ${selectedSector}, decrypted — first 128 bytes` }),
      h('p', { class: 'textline', text: sectorToDisplay(read.plaintext, 128) }),
      h('p', {
        class: 'hexline',
        text: `ciphertext on the platter: ${groupedHex(volume.ciphertextOf(selectedSector), 16)}`,
      }),
    ]);

    const ciphertext = volume.ciphertextOf(selectedSector);
    for (let block = 0; block < BLOCKS_PER_SECTOR; block++) {
      const cell = blockCells[block];
      const off = block * BLOCK_BYTES;
      const [j, hex] = Array.from(cell.children) as HTMLElement[];
      j.textContent = `j=${block}`;
      hex.textContent = toHex(ciphertext.subarray(off, off + 2));
      const damaged = read.changedBlocks.includes(block);
      cell.setAttribute('aria-pressed', String(block === selectedBlock));
      cell.className = `block-cell${damaged ? ' fill-alarm' : ''}`;
      cell.setAttribute(
        'aria-label',
        `Block ${block} of sector ${selectedSector}${damaged ? ', differs from what was written' : ''}. Ciphertext starts ${toHex(ciphertext.subarray(off, off + 2))}`,
      );
    }

    // ── Ladder ───────────────────────────────────────────────────────────
    const seed = volume.tweakFor(selectedSector, 0);
    const current = volume.tweakFor(selectedSector, ladderStep);
    const trace = mulAlphaTraced(current);
    const topByte = current[15];
    replace(ladderHost, [
      h('div', { class: 'ladder-row' }, [
        h('span', { class: 'ladder-label', text: 'sector no.' }),
        h('span', { class: 'hexline', text: `${selectedSector} as a 128-bit little-endian block = ${groupedHex(sequenceNumberToBlock(BigInt(selectedSector)))}` }),
      ]),
      h('div', { class: 'ladder-row' }, [
        h('span', { class: 'ladder-label', text: 'T₀ = AES-K2' }),
        h('span', { class: 'hexline', text: groupedHex(seed) }),
      ]),
      h('div', { class: 'ladder-row' }, [
        h('span', { class: 'ladder-label', text: `current  j = ${ladderStep}` }),
        h('span', { class: 'hexline' }, [h('span', { class: 'hl', text: `T${ladderStep} = ${groupedHex(current)}` })]),
      ]),
      h('div', { class: 'ladder-row' }, [
        h('span', { class: 'ladder-label', text: 'shift ≪ 1' }),
        h('span', { class: 'hexline', text: groupedHex(trace.shifted) }),
      ]),
      h('div', { class: 'ladder-row' }, [
        h('span', { class: 'ladder-label', text: 'carry out' }),
        h('span', { class: 'hexline' }, [
          `top bit of byte 15 (0x${topByte.toString(16).padStart(2, '0')}) is ${trace.carryOut} — `,
          trace.reduced
            ? h('span', { class: 'hl', text: `overflowed x¹²⁷, so XOR 0x${REDUCTION_BYTE.toString(16)} into byte 0` })
            : h('span', { text: 'no overflow, so no reduction' }),
        ]),
      ]),
      h('div', { class: 'ladder-row' }, [
        h('span', { class: 'ladder-label', text: `result  T${ladderStep + 1}` }),
        h('span', { class: 'hexline', text: groupedHex(trace.output) }),
      ]),
      h('p', {
        class: 'readout-note',
        text:
          ladderStep === selectedBlock
            ? `This is the tweak for the block you have selected (block ${selectedBlock}).`
            : `Block ${selectedBlock} is selected; the ladder is sitting on j = ${ladderStep}.`,
      }),
    ]);
    backButton.disabled = ladderStep === 0;
    stepButton.disabled = ladderStep >= BLOCKS_PER_SECTOR - 1;
    stepButton.textContent = `Multiply by α → j = ${Math.min(ladderStep + 1, BLOCKS_PER_SECTOR - 1)} ›`;

    // ── XEX sandwich ─────────────────────────────────────────────────────
    const off = selectedBlock * BLOCK_BYTES;
    const plainBlock = read.expected.subarray(off, off + BLOCK_BYTES);
    const sandwich = volume.cipher.traceBlockEncrypt(
      volume.sequenceNumber(selectedSector),
      selectedBlock,
      plainBlock,
    );
    const onPlatter = ciphertext.subarray(off, off + BLOCK_BYTES);
    const matches = equalBytes(sandwich.ciphertext, onPlatter);
    replace(sandwichHost, [
      h('h4', { text: `Block ${selectedBlock} encrypted, with the tweak on both sides` }),
      h('div', { class: 'ladder' }, [
        row('P (as written)', groupedHex(plainBlock)),
        row(`T${selectedBlock}`, groupedHex(sandwich.tweak)),
        row('P ⊕ T', groupedHex(sandwich.masked)),
        row('AES-K1(P ⊕ T)', groupedHex(sandwich.aesOutput)),
        row('⊕ T again = C', groupedHex(sandwich.ciphertext)),
        row('on the platter', groupedHex(onPlatter)),
        h('div', { class: 'ladder-row' }, [
          h('span', { class: 'ladder-label', text: 'compared' }),
          verdictPill(
            matches ? toneForStatus('INTACT') : toneForStatus('CORRUPTED_UNDETECTED'),
            matches ? 'BYTE-FOR-BYTE EQUAL' : 'DIFFERS — THIS BLOCK WAS EDITED ON THE PLATTER',
          ),
        ]),
      ]),
    ]);
  }

  return { root, refresh };
}

function row(label: string, value: string): HTMLElement {
  return h('div', { class: 'ladder-row' }, [
    h('span', { class: 'ladder-label', text: label }),
    h('span', { class: 'hexline', text: value }),
  ]);
}
