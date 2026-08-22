/**
 * Ciphertext-only analysis: what a snapshotting adversary learns with no key.
 *
 * XTS is deterministic per (sector, block index) — the same plaintext block
 * written to the same place under the same key always produces the same
 * ciphertext. So two disk images taken at different times can be diffed
 * directly, and the diff reports which 16-byte blocks changed. Do it three
 * times and reverted blocks fall out too: a block whose ciphertext returns to a
 * value it held before has had its plaintext returned to what it was before.
 *
 * The signature of this module is the argument: it takes `Snapshot[]`, which
 * carries ciphertext and nothing else. No key can reach this code.
 */
import type { Snapshot } from './volume.js';
import { toHex } from '../crypto/bytes.js';
import { BLOCK_BYTES, BLOCKS_PER_SECTOR, SECTOR_COUNT } from './types.js';

export interface BlockTimeline {
  sector: number;
  block: number;
  /**
   * One symbol per snapshot. Equal symbols mean byte-identical ciphertext.
   * `[0,0,0]` never changed; `[0,1,2]` changed twice; `[0,1,0]` changed and
   * then went back — a rollback, visible without decrypting anything.
   */
  symbols: number[];
  changed: boolean;
  reverted: boolean;
}

export interface WatermarkReport {
  snapshotLabels: string[];
  timelines: BlockTimeline[];
  changedBlocks: number;
  revertedBlocks: number;
  totalBlocks: number;
}

export function analyseSnapshots(snapshots: Snapshot[]): WatermarkReport {
  if (snapshots.length < 2) {
    throw new Error('watermark analysis needs at least two disk images to compare');
  }
  const timelines: BlockTimeline[] = [];
  let changedBlocks = 0;
  let revertedBlocks = 0;

  for (let sector = 0; sector < SECTOR_COUNT; sector++) {
    for (let block = 0; block < BLOCKS_PER_SECTOR; block++) {
      const off = block * BLOCK_BYTES;
      const seen: string[] = [];
      const symbols = snapshots.map((snap) => {
        const value = toHex(snap.ciphertext[sector].subarray(off, off + BLOCK_BYTES));
        let symbol = seen.indexOf(value);
        if (symbol === -1) {
          symbol = seen.length;
          seen.push(value);
        }
        return symbol;
      });
      const changed = seen.length > 1;
      // Reverted: a symbol reappears after a different symbol intervened.
      let reverted = false;
      for (let i = 2; i < symbols.length && !reverted; i++) {
        for (let j = 0; j < i - 1; j++) {
          if (symbols[i] === symbols[j] && symbols[i] !== symbols[i - 1]) {
            reverted = true;
            break;
          }
        }
      }
      if (changed) changedBlocks++;
      if (reverted) revertedBlocks++;
      timelines.push({ sector, block, symbols, changed, reverted });
    }
  }

  return {
    snapshotLabels: snapshots.map((s) => s.label),
    timelines,
    changedBlocks,
    revertedBlocks,
    totalBlocks: SECTOR_COUNT * BLOCKS_PER_SECTOR,
  };
}
