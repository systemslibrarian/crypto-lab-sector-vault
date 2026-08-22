import { analyseSnapshots } from '../volume/watermark.js';
import { BLOCKS_PER_SECTOR, SECTOR_COUNT } from '../volume/types.js';
import { actCard, h, replace, scroller } from './dom.js';
import type { LabContext } from './state.js';

/**
 * Act 4 — what a snapshotting adversary reads off the ciphertext alone.
 *
 * `analyseSnapshots` takes `Snapshot[]`, and a snapshot carries ciphertext and
 * a label. No key can reach it. Everything this panel prints was derived from
 * disk images somebody could have taken from a backup server.
 */
export function mountWatermarkPanel(ctx: LabContext): { root: HTMLElement; refresh: () => void } {
  const root = actCard('act-watermark', 'ACT 4', 'Watermarking: reading the disk with no key at all');

  root.append(
    h('p', { class: 'lede' }, [
      'XTS is deterministic per (sector, block index): the same plaintext block, written to the same place under the same key, always produces the same ciphertext. ',
      'So two disk images can be diffed directly. Take an image, change something, take another — then read off exactly which 16-byte blocks moved, and which came back to a value they held before.',
    ]),
  );

  const captureButton = h('button', { type: 'button', class: 'primary', id: 'take-image' }, [
    'Take a disk image',
  ]) as HTMLButtonElement;
  const clearButton = h('button', { type: 'button', id: 'clear-images' }, ['Keep only the first']) as HTMLButtonElement;
  captureButton.addEventListener('click', () => {
    const n = ctx.state.snapshots.length + 1;
    ctx.state.snapshots.push(ctx.state.volume.snapshot(`image ${n}`));
    ctx.record(`Took disk image ${n} — ciphertext only, no key involved.`);
  });
  clearButton.addEventListener('click', () => {
    ctx.state.snapshots = ctx.state.snapshots.slice(0, 1);
    ctx.record('Discarded every disk image except the first.');
  });
  root.append(h('div', { class: 'controls' }, [captureButton, clearButton]));

  const summaryHost = h('div', { role: 'status', 'aria-live': 'polite', id: 'wm-summary' });
  const gridHost = h('div', {});
  root.append(summaryHost, gridHost);

  root.append(
    h('details', { class: 'more' }, [
      h('summary', { text: 'Why this leak is a design consequence, not a bug' }),
      h('p', {
        text: 'A sector on a disk has to be readable and rewritable in place, with no room for a per-write nonce. That forces the encryption of a given sector to be a fixed function of its contents and its address, and a fixed function is exactly what makes two images comparable. The leak is not an oversight in XTS; it is the price of a mode that expands data by zero bytes.',
      }),
      h('p', {
        text: 'What it costs in practice depends on what the plaintext is. A block of a database index changing on a known schedule tells an observer a great deal; a block of a compressed archive tells them almost nothing. The point of this act is that the observer gets to make that judgement without a key.',
      }),
    ]),
  );

  function refresh(): void {
    const snapshots = ctx.state.snapshots;
    clearButton.disabled = snapshots.length < 2;

    if (snapshots.length < 2) {
      replace(summaryHost, [
        h('p', {
          class: 'readout-note',
          text: `${snapshots.length} disk image held. Take a second one — after writing, flipping or rolling something back — and the diff appears here.`,
        }),
      ]);
      replace(gridHost, []);
      return;
    }

    const report = analyseSnapshots(snapshots);
    replace(summaryHost, [
      h('p', {
        class: 'readout-note',
        text: `${report.snapshotLabels.length} images compared. ${report.changedBlocks} of ${report.totalBlocks} blocks changed at some point; ${report.revertedBlocks} returned to a value they had held before. Derived from ciphertext alone — no key was used, and the analysis function cannot reach one.`,
      }),
    ]);

    const grid = h('div', { class: 'wm-grid' });
    for (let sector = 0; sector < SECTOR_COUNT; sector++) {
      grid.append(h('span', { class: 'wm-rowlabel', text: `S${String(sector).padStart(2, '0')}` }));
      for (let block = 0; block < BLOCKS_PER_SECTOR; block++) {
        const timeline = report.timelines[sector * BLOCKS_PER_SECTOR + block];
        const kind = timeline.reverted ? 'reverted' : timeline.changed ? 'changed' : 'same';
        const glyph = timeline.reverted ? '↺' : timeline.changed ? '▲' : '·';
        grid.append(
          h('span', {
            class: `wm-cell wm-${kind}`,
            role: 'img',
            'aria-label': `Sector ${sector} block ${block}: ${describe(kind)} (${timeline.symbols.join('→')})`,
            text: glyph,
          }),
        );
      }
    }

    replace(gridHost, [
      scroller('Ciphertext diff across the disk images, by sector and block', grid),
      h('ul', { class: 'legend', role: 'list' }, [
        legend('·', 'wm-same', 'unchanged in every image'),
        legend('▲', 'wm-changed', 'changed at least once'),
        legend('↺', 'wm-reverted', 'returned to an earlier value — a rollback, visible without decrypting'),
      ]),
      revertedList(report.timelines.filter((t) => t.reverted)),
    ]);
  }

  return { root, refresh };
}

function describe(kind: string): string {
  if (kind === 'reverted') return 'returned to an earlier ciphertext value';
  if (kind === 'changed') return 'ciphertext changed';
  return 'ciphertext unchanged';
}

function legend(glyph: string, cls: string, label: string): HTMLElement {
  return h('li', { role: 'listitem' }, [
    h('span', { class: `legend-swatch ${cls}`, 'aria-hidden': 'true', text: glyph }),
    h('span', { text: label }),
  ]);
}

function revertedList(reverted: { sector: number; block: number; symbols: number[] }[]): HTMLElement {
  if (reverted.length === 0) {
    return h('p', {
      class: 'readout-note',
      text: 'No block has returned to an earlier value yet. Roll a sector back in act 3, take another image, and it will appear here.',
    });
  }
  return h('div', {}, [
    h('h4', { text: 'Blocks that went back to an earlier value' }),
    h(
      'ul',
      { class: 'log', role: 'list' },
      reverted
        .slice(0, 24)
        .map((t) =>
          h('li', {
            role: 'listitem',
            text: `sector ${t.sector}, block ${t.block} — ciphertext sequence ${t.symbols.join(' → ')}`,
          }),
        ),
    ),
  ]);
}
