import { createCipheriv, createDecipheriv, getCiphers, randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { createXtsCipher } from './xts.js';
import { fromHex, sequenceNumberToBlock, toHex } from './bytes.js';

/**
 * Cross-implementation check against OpenSSL's XTS through node:crypto.
 *
 * This is the independent oracle. The KATs in `xts.test.ts` pin a handful of
 * published data units; this pins the whole surface — both key sizes, every
 * data-unit length including the ciphertext-stealing ones, random keys, random
 * sequence numbers — against an implementation written by other people from the
 * same standard. A test that only re-derives what the source does agrees
 * happily with a bug; this one cannot.
 *
 * It also covers the 480 bytes of IEEE vectors 4 and 10 that `xts.test.ts`
 * asserts only a 32-byte prefix of.
 */
const HAVE_OPENSSL_XTS = getCiphers().includes('aes-128-xts') && getCiphers().includes('aes-256-xts');

function opensslXts(
  direction: 'encrypt' | 'decrypt',
  k1: Uint8Array,
  k2: Uint8Array,
  sequenceNumber: bigint,
  data: Uint8Array,
): Uint8Array {
  const algorithm = k1.length === 16 ? 'aes-128-xts' : 'aes-256-xts';
  const key = Buffer.concat([Buffer.from(k1), Buffer.from(k2)]);
  const iv = Buffer.from(sequenceNumberToBlock(sequenceNumber));
  const cipher = direction === 'encrypt' ? createCipheriv(algorithm, key, iv) : createDecipheriv(algorithm, key, iv);
  cipher.setAutoPadding(false);
  return new Uint8Array(Buffer.concat([cipher.update(Buffer.from(data)), cipher.final()]));
}

// Skipping silently would turn the strongest check in the suite into a no-op,
// so the absence is asserted rather than ignored: if this ever fails, the
// oracle is gone and somebody has to notice.
describe('OpenSSL is available as an independent XTS oracle', () => {
  it('exposes aes-128-xts and aes-256-xts', () => {
    expect(HAVE_OPENSSL_XTS).toBe(true);
  });
});

describe('XTS agrees with OpenSSL', () => {
  const LENGTHS = [16, 17, 18, 19, 31, 32, 33, 63, 100, 511, 512, 513, 4096];

  for (const bits of [128, 256] as const) {
    it(`XTS-AES-${bits}: encrypt and decrypt match OpenSSL across ${LENGTHS.length} data-unit lengths`, () => {
      const keyBytes = bits / 8;
      for (const length of LENGTHS) {
        for (let trial = 0; trial < 8; trial++) {
          const k1 = new Uint8Array(randomBytes(keyBytes));
          const k2 = new Uint8Array(randomBytes(keyBytes));
          const sequenceNumber = BigInt('0x' + randomBytes(6).toString('hex'));
          const plaintext = new Uint8Array(randomBytes(length));
          const mine = createXtsCipher({ k1, k2 });

          const ours = mine.encryptSector(sequenceNumber, plaintext);
          const theirs = opensslXts('encrypt', k1, k2, sequenceNumber, plaintext);
          expect(toHex(ours)).toBe(toHex(theirs));

          expect(toHex(mine.decryptSector(sequenceNumber, theirs))).toBe(toHex(plaintext));
          expect(toHex(opensslXts('decrypt', k1, k2, sequenceNumber, ours))).toBe(toHex(plaintext));
        }
      }
    });
  }

  it('covers IEEE vector 4 in full, not just the 32 bytes xts.test.ts transcribes', () => {
    const k1 = fromHex('27182818284590452353602874713526');
    const k2 = fromHex('31415926535897932384626433832795');
    const plaintext = new Uint8Array(512);
    for (let i = 0; i < 512; i++) plaintext[i] = i & 0xff;
    const ours = createXtsCipher({ k1, k2 }).encryptSector(0n, plaintext);
    expect(toHex(ours)).toBe(toHex(opensslXts('encrypt', k1, k2, 0n, plaintext)));
    expect(toHex(ours.subarray(0, 32))).toBe('27a7479befa1d476489f308cd4cfa6e2a96e4bbe3208ff25287dd3819616e89c');
  });

  it('covers IEEE vector 10 in full', () => {
    const k1 = fromHex('2718281828459045235360287471352662497757247093699959574966967627');
    const k2 = fromHex('3141592653589793238462643383279502884197169399375105820974944592');
    const plaintext = new Uint8Array(512);
    for (let i = 0; i < 512; i++) plaintext[i] = i & 0xff;
    const ours = createXtsCipher({ k1, k2 }).encryptSector(0xffn, plaintext);
    expect(toHex(ours)).toBe(toHex(opensslXts('encrypt', k1, k2, 0xffn, plaintext)));
    expect(toHex(ours.subarray(0, 32))).toBe('1c3b3a102f770386e4836c99e370cf9bea00803f5e482357a4ae12d414a3e63b');
  });

  it('agrees on the sequence-number encoding, byte for byte', () => {
    // OpenSSL takes the tweak input block directly as its IV. If this lab's
    // little-endian encoding were wrong, every ciphertext above would still
    // agree with OpenSSL's for the SAME wrong block, so pin the block itself
    // against the byte string IEEE 1619 prints for vector 15.
    expect(toHex(sequenceNumberToBlock(0x123456789an))).toBe('9a78563412' + '00'.repeat(11));
  });
});
