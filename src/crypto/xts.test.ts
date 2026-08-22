import { describe, expect, it } from 'vitest';
import { createXtsCipher, XtsError, XTS_BLOCK_BYTES, XTS_FAILURE_CODES } from './xts.js';
import { fromHex, toHex } from './bytes.js';
import { mulAlphaPow } from './gf128.js';

/**
 * IEEE Std 1619-2007 Annex B / NIST SP 800-38E known-answer vectors.
 *
 * Sequence numbers are given as the integer, and `sequenceNumberToBlock`
 * encodes them little-endian — so vector 15's number 0x123456789a becomes the
 * byte string 9a 78 56 34 12 the spec prints. The palindromic 0x3333333333 in
 * vectors 2 and 3 cannot catch that mistake, which is why vector 15 is here.
 */
const IEEE_1619_FULL = [
  {
    id: 1,
    note: 'zero keys, zero data unit, 32 bytes',
    k1: '00000000000000000000000000000000',
    k2: '00000000000000000000000000000000',
    seq: 0n,
    pt: '00'.repeat(32),
    ct: '917cf69ebd68b2ec9b9fe9a3eadda692cd43d2f59598ed858c02c2652fbf922e',
  },
  {
    id: 2,
    note: 'repeating keys, 32 bytes',
    k1: '11111111111111111111111111111111',
    k2: '22222222222222222222222222222222',
    seq: 0x3333333333n,
    pt: '44'.repeat(32),
    ct: 'c454185e6a16936e39334038acef838bfb186fff7480adc4289382ecd6d394f0',
  },
  {
    id: 3,
    note: 'K1 and K2 unrelated, 32 bytes',
    k1: 'fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0',
    k2: '22222222222222222222222222222222',
    seq: 0x3333333333n,
    pt: '44'.repeat(32),
    ct: 'af85336b597afc1a900b2eb21ec949d292df4c047e0b21532186a5971a227a89',
  },
  {
    id: 15,
    note: 'ciphertext stealing, 17 bytes',
    k1: 'fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0',
    k2: 'bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0',
    seq: 0x123456789an,
    pt: '000102030405060708090a0b0c0d0e0f10',
    ct: '6c1625db4671522d3d7599601de7ca09ed',
  },
  {
    id: 16,
    note: 'ciphertext stealing, 18 bytes',
    k1: 'fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0',
    k2: 'bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0',
    seq: 0x123456789an,
    pt: '000102030405060708090a0b0c0d0e0f1011',
    ct: 'd069444b7a7e0cab09e24447d24deb1fedbf',
  },
  {
    id: 17,
    note: 'ciphertext stealing, 19 bytes',
    k1: 'fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0',
    k2: 'bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0',
    seq: 0x123456789an,
    pt: '000102030405060708090a0b0c0d0e0f101112',
    ct: 'e5df1351c0544ba1350b3363cd8ef4beedbf9d',
  },
  {
    id: 18,
    note: 'ciphertext stealing, 20 bytes',
    k1: 'fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0',
    k2: 'bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0',
    seq: 0x123456789an,
    pt: '000102030405060708090a0b0c0d0e0f10111213',
    ct: '9d84c813f719aa2c7be3f66171c7c5c2edbf9dac',
  },
];

/**
 * The 512-byte vectors. Only the leading 32 ciphertext bytes are transcribed
 * here — the full data unit is 1024 hex characters — so these assert a PREFIX
 * and say so. The remaining 480 bytes are covered by `xts.cross.test.ts`,
 * which checks the identical inputs against OpenSSL's independent XTS.
 */
const IEEE_1619_PREFIX = [
  {
    id: 4,
    note: 'XTS-AES-128, 512-byte data unit, sequence number 0',
    k1: '27182818284590452353602874713526',
    k2: '31415926535897932384626433832795',
    seq: 0n,
    ctPrefix: '27a7479befa1d476489f308cd4cfa6e2a96e4bbe3208ff25287dd3819616e89c',
  },
  {
    id: 10,
    note: 'XTS-AES-256, 512-byte data unit, sequence number 0xff',
    k1: '2718281828459045235360287471352662497757247093699959574966967627',
    k2: '3141592653589793238462643383279502884197169399375105820974944592',
    seq: 0xffn,
    ctPrefix: '1c3b3a102f770386e4836c99e370cf9bea00803f5e482357a4ae12d414a3e63b',
  },
];

/** The 512-byte plaintext those vectors use: 0x00..0xff, twice. */
function counterPlaintext(length: number): Uint8Array {
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i++) out[i] = i & 0xff;
  return out;
}

describe('XTS-AES known-answer tests (IEEE 1619-2007 / NIST SP 800-38E)', () => {
  for (const v of IEEE_1619_FULL) {
    it(`vector ${v.id} — ${v.note} — encrypts to the published ciphertext`, () => {
      const cipher = createXtsCipher({ k1: fromHex(v.k1), k2: fromHex(v.k2) });
      expect(toHex(cipher.encryptSector(v.seq, fromHex(v.pt)))).toBe(v.ct);
    });

    it(`vector ${v.id} — decrypts the published ciphertext back to the plaintext`, () => {
      const cipher = createXtsCipher({ k1: fromHex(v.k1), k2: fromHex(v.k2) });
      expect(toHex(cipher.decryptSector(v.seq, fromHex(v.ct)))).toBe(v.pt);
    });
  }

  for (const v of IEEE_1619_PREFIX) {
    it(`vector ${v.id} — ${v.note} — matches the published first 32 ciphertext bytes`, () => {
      const cipher = createXtsCipher({ k1: fromHex(v.k1), k2: fromHex(v.k2) });
      const ct = cipher.encryptSector(v.seq, counterPlaintext(512));
      expect(ct.length).toBe(512);
      expect(toHex(ct.subarray(0, 32))).toBe(v.ctPrefix);
      expect(toHex(cipher.decryptSector(v.seq, ct))).toBe(toHex(counterPlaintext(512)));
    });
  }
});

describe('XTS structure', () => {
  const key = { k1: fromHex('fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0'), k2: fromHex('bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0') };
  const cipher = createXtsCipher(key);

  it('round-trips every length from one block to a 4096-byte data unit', () => {
    const lengths = [16, 17, 23, 31, 32, 33, 47, 48, 64, 100, 511, 512, 513, 4096];
    for (const length of lengths) {
      const pt = crypto.getRandomValues(new Uint8Array(length));
      const ct = cipher.encryptSector(7n, pt);
      expect(ct.length).toBe(length);
      expect(toHex(cipher.decryptSector(7n, ct))).toBe(toHex(pt));
    }
  });

  it('reports the AES size behind the mode', () => {
    expect(cipher.aesBits).toBe(128);
    expect(createXtsCipher({ k1: new Uint8Array(32), k2: new Uint8Array(32).fill(1) }).aesBits).toBe(256);
  });

  it('derives T_j as T_0 times alpha^j', () => {
    const seed = cipher.tweakSeed(11n);
    for (let j = 0; j < 40; j++) {
      expect(toHex(cipher.tweakForBlock(11n, j))).toBe(toHex(mulAlphaPow(seed, j)));
    }
  });

  it('gives every sector a different tweak seed', () => {
    const seeds = new Set<string>();
    for (let s = 0; s < 64; s++) seeds.add(toHex(cipher.tweakSeed(BigInt(s))));
    expect(seeds.size).toBe(64);
  });

  it('is deterministic per (key, sector, plaintext) — the premise of the watermarking act', () => {
    const pt = crypto.getRandomValues(new Uint8Array(512));
    expect(toHex(cipher.encryptSector(2n, pt))).toBe(toHex(cipher.encryptSector(2n, pt)));
  });

  it('binds ciphertext to position: the same plaintext at another sector encrypts differently', () => {
    const pt = crypto.getRandomValues(new Uint8Array(512));
    expect(toHex(cipher.encryptSector(2n, pt))).not.toBe(toHex(cipher.encryptSector(3n, pt)));
  });

  it('confines one flipped ciphertext bit to exactly its own 16-byte block', () => {
    const pt = new Uint8Array(512).fill(0x41);
    const ct = cipher.encryptSector(5n, pt);
    for (const byteOffset of [0, 19, 255, 511]) {
      const tampered = Uint8Array.from(ct);
      tampered[byteOffset] ^= 0x08;
      const out = cipher.decryptSector(5n, tampered);
      const hitBlock = Math.floor(byteOffset / XTS_BLOCK_BYTES);
      for (let block = 0; block < 32; block++) {
        const slice = toHex(out.subarray(block * XTS_BLOCK_BYTES, block * XTS_BLOCK_BYTES + XTS_BLOCK_BYTES));
        const original = toHex(pt.subarray(block * XTS_BLOCK_BYTES, block * XTS_BLOCK_BYTES + XTS_BLOCK_BYTES));
        if (block === hitBlock) expect(slice).not.toBe(original);
        else expect(slice).toBe(original);
      }
    }
  });
});

describe('what XTS can and cannot refuse', () => {
  const key = { k1: fromHex('fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0'), k2: fromHex('bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0') };

  it('has exactly two failure codes', () => {
    expect([...XTS_FAILURE_CODES]).toEqual(['MALFORMED_SECTOR', 'KEY_LENGTH_INVALID']);
  });

  it('raises MALFORMED_SECTOR below one block, in both directions', () => {
    const cipher = createXtsCipher(key);
    for (const length of [0, 1, 15]) {
      expect(() => cipher.encryptSector(0n, new Uint8Array(length))).toThrow(XtsError);
      try {
        cipher.decryptSector(0n, new Uint8Array(length));
        expect.unreachable('a short data unit must be refused');
      } catch (error) {
        expect((error as XtsError).code).toBe('MALFORMED_SECTOR');
      }
    }
  });

  it('raises KEY_LENGTH_INVALID for wrong or mismatched key sizes', () => {
    const cases: [number, number][] = [
      [16, 32],
      [32, 16],
      [24, 24],
      [8, 8],
      [0, 0],
    ];
    for (const [a, b] of cases) {
      try {
        createXtsCipher({ k1: new Uint8Array(a), k2: new Uint8Array(b) });
        expect.unreachable(`K1=${a} K2=${b} must be refused`);
      } catch (error) {
        expect((error as XtsError).code).toBe('KEY_LENGTH_INVALID');
      }
    }
  });

  it('NEG-1: never refuses a tampered ciphertext of valid length — there is nothing to refuse with', () => {
    // This is the negative claim as an executable check. Every one of these
    // reads returns bytes; not one of them raises anything, because the mode
    // carries no tag, no checksum and no redundancy to test.
    const cipher = createXtsCipher(key);
    const ct = cipher.encryptSector(1n, new Uint8Array(512).fill(0x41));
    for (let trial = 0; trial < 200; trial++) {
      const tampered = Uint8Array.from(ct);
      const offset = Math.floor(Math.random() * 512);
      tampered[offset] ^= 1 << Math.floor(Math.random() * 8);
      const out = cipher.decryptSector(1n, tampered);
      expect(out.length).toBe(512);
    }
  });
});
