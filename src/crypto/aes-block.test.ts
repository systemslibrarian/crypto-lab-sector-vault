import { describe, expect, it } from 'vitest';
import { unsafe } from '@noble/ciphers/aes.js';
import { fromHex, toHex } from './bytes.js';

/**
 * FIPS-197 Appendix C known-answer tests for the single-block primitive this
 * lab builds XTS on top of. The mode is hand-rolled here; the block cipher is
 * not, so this is the check that the borrowed piece is the real AES before any
 * XTS vector is trusted.
 */
const FIPS_197 = [
  { name: 'AES-128', key: '000102030405060708090a0b0c0d0e0f', ct: '69c4e0d86a7b0430d8cdb78070b4c55a' },
  { name: 'AES-192', key: '000102030405060708090a0b0c0d0e0f1011121314151617', ct: 'dda97ca4864cdfe06eaf70a0ec0d7191' },
  {
    name: 'AES-256',
    key: '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
    ct: '8ea2b7ca516745bfeafc49904b496089',
  },
];
const FIPS_197_PLAINTEXT = '00112233445566778899aabbccddeeff';

describe('AES block primitive (FIPS-197 Appendix C)', () => {
  for (const vector of FIPS_197) {
    it(`${vector.name} encrypts the appendix C block`, () => {
      const schedule = unsafe.expandKeyLE(fromHex(vector.key));
      expect(toHex(unsafe.encryptBlock(schedule, fromHex(FIPS_197_PLAINTEXT)))).toBe(vector.ct);
    });

    it(`${vector.name} decrypts it back`, () => {
      const schedule = unsafe.expandKeyDecLE(fromHex(vector.key));
      expect(toHex(unsafe.decryptBlock(schedule, fromHex(vector.ct)))).toBe(FIPS_197_PLAINTEXT);
    });
  }

  it('reuses one expanded key across many blocks', () => {
    // XTS calls the primitive once per 16 bytes; a schedule that could only be
    // used once would make the volume unusable, so this is load-bearing.
    const schedule = unsafe.expandKeyLE(fromHex(FIPS_197[0].key));
    for (let i = 0; i < 64; i++) {
      expect(toHex(unsafe.encryptBlock(schedule, fromHex(FIPS_197_PLAINTEXT)))).toBe(FIPS_197[0].ct);
    }
  });
});
