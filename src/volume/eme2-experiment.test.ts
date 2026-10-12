import { expect, it } from 'vitest';
import { runEme2Experiment } from './eme2-experiment.js';

const keys = { aes: new Uint8Array(16).fill(1), ecbMask: new Uint8Array(16).fill(2), adMask: new Uint8Array(16).fill(3) };
for (const length of [512, 513, 2064]) {
  it(`measures actual XTS and EME2 outputs, including ${length}-byte boundaries`, () => {
    const clean = runEme2Experiment(keys, length, 'clean');
    expect(clean.xts.changedBits).toBe(0); expect(clean.eme2.changedBits).toBe(0);
    for (const action of ['ciphertext-bit', 'splice', 'plaintext-bit'] as const) {
      const r = runEme2Experiment(keys, length, action);
      expect(r.xts.changedBlocks).toBe(1);
      expect(r.eme2.changedBlocks).toBe(Math.ceil(length / 16));
      expect(r.xts.bytes.length).toBe(length); expect(r.eme2.bytes.length).toBe(length);
    }
    const address = runEme2Experiment(keys, length, 'wrong-ad');
    expect(address.eme2.changedBlocks).toBe(Math.ceil(length / 16));
    expect(address.result).toContain('no authentication error');
    const replay = runEme2Experiment(keys, length, 'replay');
    expect(replay.eme2.bytes).toEqual(clean.eme2.bytes);
    expect(replay.xts.bytes).toEqual(clean.xts.bytes);
    expect(replay.xts.changedBits).toBe(1); expect(replay.eme2.changedBits).toBe(1);
    expect(replay.result).toContain('rollback accepted');
  });
}
