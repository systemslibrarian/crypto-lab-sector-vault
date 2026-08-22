import { describe, expect, it } from 'vitest';
import { SectorVolume } from './volume.js';
import { analyseSnapshots } from './watermark.js';
import { rollbackSector } from './attacks.js';
import { BLOCKS_PER_SECTOR, SECTOR_COUNT } from './types.js';

function loadedVolume(): SectorVolume {
  const volume = new SectorVolume({
    k1: crypto.getRandomValues(new Uint8Array(16)),
    k2: crypto.getRandomValues(new Uint8Array(16)),
  });
  for (let s = 0; s < SECTOR_COUNT; s++) volume.writeText(s, `SECTOR ${s} ORIGINAL CONTENT`);
  return volume;
}

describe('ciphertext-only watermarking', () => {
  it('names the blocks that changed between two images, without a key', () => {
    const volume = loadedVolume();
    const before = volume.snapshot('image 1');
    // Rewrite sector 4 with a line that differs only in its first 16 bytes.
    volume.writeText(4, 'SECTOR X ORIGINAL CONTENT');
    const after = volume.snapshot('image 2');

    const report = analyseSnapshots([before, after]);
    const changed = report.timelines.filter((t) => t.changed);
    expect(changed.every((t) => t.sector === 4)).toBe(true);
    expect(changed.map((t) => t.block)).toEqual([0]);
    expect(report.changedBlocks).toBe(1);
    expect(report.revertedBlocks).toBe(0);
    expect(report.totalBlocks).toBe(SECTOR_COUNT * BLOCKS_PER_SECTOR);
  });

  it('reads a rollback straight off three images as a reverted block', () => {
    const volume = loadedVolume();
    const one = volume.snapshot('image 1');
    volume.writeText(4, 'SECTOR X ORIGINAL CONTENT');
    const two = volume.snapshot('image 2');
    rollbackSector(volume, 4, 1);
    const three = volume.snapshot('image 3');

    const report = analyseSnapshots([one, two, three]);
    const reverted = report.timelines.filter((t) => t.reverted);
    expect(reverted.length).toBe(1);
    expect(reverted[0]).toMatchObject({ sector: 4, block: 0, symbols: [0, 1, 0] });
    expect(report.revertedBlocks).toBe(1);
    expect(report.snapshotLabels).toEqual(['image 1', 'image 2', 'image 3']);
  });

  it('does not call a block reverted when it simply keeps changing', () => {
    const volume = loadedVolume();
    const one = volume.snapshot('image 1');
    volume.writeText(4, 'SECTOR A ORIGINAL CONTENT');
    const two = volume.snapshot('image 2');
    volume.writeText(4, 'SECTOR B ORIGINAL CONTENT');
    const three = volume.snapshot('image 3');

    const report = analyseSnapshots([one, two, three]);
    expect(report.revertedBlocks).toBe(0);
    expect(report.timelines.find((t) => t.sector === 4 && t.block === 0)?.symbols).toEqual([0, 1, 2]);
  });

  it('sees nothing when nothing was written', () => {
    const volume = loadedVolume();
    const report = analyseSnapshots([volume.snapshot('a'), volume.snapshot('b')]);
    expect(report.changedBlocks).toBe(0);
    expect(report.timelines.every((t) => t.symbols.every((s) => s === 0))).toBe(true);
  });

  it('needs at least two images', () => {
    const volume = loadedVolume();
    expect(() => analyseSnapshots([volume.snapshot('only one')])).toThrow(/at least two/);
  });

  it('is determinism made visible: rewriting identical content produces no diff at all', () => {
    // If XTS were randomised per write, this diff would light up every block
    // and the whole act would be impossible. It is not; that is the leak.
    const volume = loadedVolume();
    const before = volume.snapshot('image 1');
    for (let s = 0; s < SECTOR_COUNT; s++) volume.writeText(s, `SECTOR ${s} ORIGINAL CONTENT`);
    const after = volume.snapshot('image 2');
    expect(analyseSnapshots([before, after]).changedBlocks).toBe(0);
  });
});
