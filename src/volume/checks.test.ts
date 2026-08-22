import { describe, expect, it } from 'vitest';
import { runXtsChecks } from './checks.js';
import { XTS_FAILURE_CODES } from '../crypto/xts.js';
import { SECTOR_BYTES } from './types.js';

const goodKey = { k1: new Uint8Array(16).fill(1), k2: new Uint8Array(16).fill(2) };
const sector = new Uint8Array(SECTOR_BYTES).fill(0x41);

describe('the checks XTS actually performs', () => {
  it('reports two real checks and two that do not exist', () => {
    const checks = runXtsChecks(goodKey, 3n, sector);
    expect(checks.map((c) => c.name)).toEqual([
      'Key length',
      'Data unit length',
      'Data authenticity',
      'Freshness',
    ]);
    // Sorted on both sides: the ORDER the panel runs its checks in is a
    // presentation decision, but the set of codes it can report is the claim.
    expect(checks.filter((c) => c.outcome === 'pass').map((c) => c.code).sort()).toEqual(
      [...XTS_FAILURE_CODES].sort(),
    );
    expect(checks.filter((c) => c.outcome === 'no-such-check').map((c) => c.code)).toEqual([null, null]);
  });

  it('every check with a code has one XTS really has, and the codeless ones really have none', () => {
    // The inventory is the exhibit: nothing here may invent a code the mode
    // does not carry, and nothing that lacks one may pretend otherwise.
    for (const check of runXtsChecks(goodKey, 0n, sector)) {
      if (check.code === null) expect(check.outcome).toBe('no-such-check');
      else expect(XTS_FAILURE_CODES).toContain(check.code);
    }
  });

  it('fails the key-length check on a mismatched key pair, naming the code', () => {
    const checks = runXtsChecks({ k1: new Uint8Array(16), k2: new Uint8Array(32) }, 0n, sector);
    const keyCheck = checks.find((c) => c.code === 'KEY_LENGTH_INVALID');
    expect(keyCheck?.outcome).toBe('fail');
    expect(keyCheck?.detail).toContain('KEY_LENGTH_INVALID');
    // With no cipher there is nothing to run the data unit through, and the
    // page must not report that as a pass.
    expect(checks.find((c) => c.code === 'MALFORMED_SECTOR')?.outcome).toBe('fail');
  });

  it('fails the data-unit check on a short sector, naming the code', () => {
    const checks = runXtsChecks(goodKey, 0n, new Uint8Array(8));
    const lengthCheck = checks.find((c) => c.code === 'MALFORMED_SECTOR');
    expect(lengthCheck?.outcome).toBe('fail');
    expect(lengthCheck?.detail).toContain('MALFORMED_SECTOR');
    expect(checks.find((c) => c.code === 'KEY_LENGTH_INVALID')?.outcome).toBe('pass');
  });

  it('never reports a pass for authenticity or freshness, whatever the input', () => {
    // The negative claim, at the level of the check inventory: there is no
    // input for which this construction can report either property verified.
    for (const key of [goodKey, { k1: new Uint8Array(32), k2: new Uint8Array(32).fill(9) }]) {
      for (const data of [sector, new Uint8Array(16), new Uint8Array(4096)]) {
        const checks = runXtsChecks(key, 7n, data);
        for (const name of ['Data authenticity', 'Freshness']) {
          const check = checks.find((c) => c.name === name);
          expect(check?.outcome).toBe('no-such-check');
          expect(check?.code).toBeNull();
        }
      }
    }
  });
});
