import { describe, expect, it } from 'vitest';
import { ATTACKS, CONSTRUCTIONS, findCell, runComparison } from './comparison.js';
import { SECTOR_BYTES } from './types.js';

describe('the three-stage comparison', () => {
  it('fills all nine cells', async () => {
    const report = await runComparison({ attackerControlsVersionStore: false });
    expect(report.cells.length).toBe(CONSTRUCTIONS.length * ATTACKS.length);
    for (const construction of CONSTRUCTIONS) {
      for (const attack of ATTACKS) expect(findCell(report, construction, attack)).toBeTruthy();
    }
  });

  it('XTS detects nothing, in any column', async () => {
    const report = await runComparison({ attackerControlsVersionStore: false });
    for (const attack of ATTACKS) {
      expect(findCell(report, 'xts', attack).raisedByConstruction).toBe(false);
    }
  });

  it('XTS: modification and relocation are CORRUPTED (UNDETECTED); rollback succeeds cleanly', async () => {
    const report = await runComparison({ attackerControlsVersionStore: false });
    expect(findCell(report, 'xts', 'bit-modification').outcome).toBe('CORRUPTED_UNDETECTED');
    expect(findCell(report, 'xts', 'relocation').outcome).toBe('CORRUPTED_UNDETECTED');
    expect(findCell(report, 'xts', 'relocation').detail).toMatch(/position-bound/);
    expect(findCell(report, 'xts', 'rollback').outcome).toBe('SUCCEEDS_CLEANLY');
    expect(findCell(report, 'xts', 'rollback').label).toBe('succeeds cleanly');
  });

  it('stage two: modification and relocation die on the tag, rollback still authenticates', async () => {
    const report = await runComparison({ attackerControlsVersionStore: false });
    expect(findCell(report, 'gcm-sector-aad', 'bit-modification').outcome).toBe('BAD_TAG');
    expect(findCell(report, 'gcm-sector-aad', 'relocation').outcome).toBe('BAD_TAG');
    const rollback = findCell(report, 'gcm-sector-aad', 'rollback');
    expect(rollback.outcome).toBe('SUCCEEDS_CLEANLY');
    expect(rollback.label).toBe('still authenticates');
    expect(rollback.raisedByConstruction).toBe(false);
    expect(rollback.detail).toMatch(/RFC 5116/);
  });

  it('stage three: rollback becomes STALE_VERSION, and only stage three has that code', async () => {
    const report = await runComparison({ attackerControlsVersionStore: false });
    expect(findCell(report, 'gcm-sector-version-aad', 'bit-modification').outcome).toBe('BAD_TAG');
    expect(findCell(report, 'gcm-sector-version-aad', 'relocation').outcome).toBe('BAD_TAG');
    expect(findCell(report, 'gcm-sector-version-aad', 'rollback').outcome).toBe('STALE_VERSION');
    const stale = report.cells.filter((c) => c.outcome === 'STALE_VERSION');
    expect(stale.map((c) => c.construction)).toEqual(['gcm-sector-version-aad']);
  });

  it('"protected" is load-bearing: an attacker who also owns the version store gets away with it', async () => {
    const report = await runComparison({ attackerControlsVersionStore: true });
    const rollback = findCell(report, 'gcm-sector-version-aad', 'rollback');
    expect(rollback.outcome).toBe('SUCCEEDS_CLEANLY');
    expect(rollback.raisedByConstruction).toBe(false);
    // Modification and relocation still die on the tag: the version store has
    // nothing to do with those, so the cell that changes is exactly one.
    expect(findCell(report, 'gcm-sector-version-aad', 'bit-modification').outcome).toBe('BAD_TAG');
    expect(findCell(report, 'gcm-sector-version-aad', 'relocation').outcome).toBe('BAD_TAG');
  });

  it('exactly one cell differs between the two version-store models', async () => {
    const protectedRun = await runComparison({ attackerControlsVersionStore: false });
    const ownedRun = await runComparison({ attackerControlsVersionStore: true });
    const differing = protectedRun.cells.filter((cell, i) => cell.outcome !== ownedRun.cells[i].outcome);
    expect(differing.length).toBe(1);
    expect(differing[0]).toMatchObject({ construction: 'gcm-sector-version-aad', attack: 'rollback' });
  });

  it('measures the data expansion each construction costs a 512-byte sector', async () => {
    const report = await runComparison({ attackerControlsVersionStore: false });
    expect(report.overheadBytes.xts).toBe(0);
    expect(report.overheadBytes['gcm-sector-aad']).toBe(28);
    expect(report.overheadBytes['gcm-sector-version-aad']).toBe(36);
    // Independently re-derived from the byte counts rather than copied.
    expect(report.overheadPercent['gcm-sector-aad']).toBeCloseTo((28 / SECTOR_BYTES) * 100, 10);
    expect(report.overheadPercent['gcm-sector-version-aad']).toBeCloseTo((36 / SECTOR_BYTES) * 100, 10);
  });

  it('no cell is ever "no effect" — every attack in the table really lands', async () => {
    const report = await runComparison({ attackerControlsVersionStore: false });
    expect(report.cells.filter((c) => c.outcome === 'NO_EFFECT')).toEqual([]);
  });

  it('is stable across runs despite fresh random keys and nonces', async () => {
    const first = await runComparison({ attackerControlsVersionStore: false });
    for (let i = 0; i < 5; i++) {
      const again = await runComparison({ attackerControlsVersionStore: false });
      expect(again.cells.map((c) => c.outcome)).toEqual(first.cells.map((c) => c.outcome));
    }
  });
});
