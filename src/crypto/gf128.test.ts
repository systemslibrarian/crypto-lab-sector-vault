import { describe, expect, it } from 'vitest';
import { fromHex, toHex } from './bytes.js';
import { mulAlpha, mulAlphaPow, mulAlphaTraced, REDUCTION_BYTE } from './gf128.js';

/**
 * An INDEPENDENT re-derivation of multiply-by-alpha, written a different way
 * from the shipped one: the 16 little-endian bytes are assembled into a single
 * BigInt, shifted once as one number, and reduced by the polynomial's low word.
 * If the byte-at-a-time carry chain in gf128.ts is wrong in any position, these
 * two disagree.
 */
function mulAlphaViaBigInt(element: Uint8Array): Uint8Array {
  let value = 0n;
  for (let i = 15; i >= 0; i--) value = (value << 8n) | BigInt(element[i]);
  let shifted = value << 1n;
  if (shifted >> 128n) shifted = (shifted & ((1n << 128n) - 1n)) ^ BigInt(REDUCTION_BYTE);
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[i] = Number((shifted >> BigInt(8 * i)) & 0xffn);
  return out;
}

describe('multiply by alpha in GF(2^128)', () => {
  it('doubles a small element with no reduction', () => {
    expect(toHex(mulAlpha(fromHex('01' + '00'.repeat(15))))).toBe('02' + '00'.repeat(15));
  });

  it('carries across a byte boundary', () => {
    // 0x80 in byte 0 is x^7; doubling gives x^8, which is bit 0 of byte 1.
    expect(toHex(mulAlpha(fromHex('80' + '00'.repeat(15))))).toBe('00' + '01' + '00'.repeat(14));
  });

  it('reduces by x^7 + x^2 + x + 1 exactly when the shift overflows x^127', () => {
    // Top bit of byte 15 is x^127. Doubling it overflows and must fold in 0x87.
    const top = fromHex('00'.repeat(15) + '80');
    const traced = mulAlphaTraced(top);
    expect(traced.carryOut).toBe(1);
    expect(traced.reduced).toBe(true);
    expect(toHex(traced.shifted)).toBe('00'.repeat(16));
    expect(toHex(traced.output)).toBe('87' + '00'.repeat(15));

    const noOverflow = mulAlphaTraced(fromHex('01' + '00'.repeat(15)));
    expect(noOverflow.carryOut).toBe(0);
    expect(noOverflow.reduced).toBe(false);
  });

  it('agrees with an independent BigInt re-derivation over random elements', () => {
    for (let trial = 0; trial < 500; trial++) {
      const element = crypto.getRandomValues(new Uint8Array(16));
      expect(toHex(mulAlpha(element))).toBe(toHex(mulAlphaViaBigInt(element)));
    }
  });

  it('traces the same result it computes, so the drawn steps cannot drift', () => {
    for (let trial = 0; trial < 200; trial++) {
      const element = crypto.getRandomValues(new Uint8Array(16));
      expect(toHex(mulAlphaTraced(element).output)).toBe(toHex(mulAlpha(element)));
    }
  });

  it('is injective, so no two block indices in a sector share a tweak', () => {
    // 32 blocks per 512-byte sector: alpha^0 .. alpha^31 must all be distinct,
    // which is what makes each block position its own tweak.
    // Iterated rather than `mulAlphaPow(seed, j)` per j: that form is O(n^2)
    // and took 6.4s under load here, which is over Vitest's default 5s timeout
    // — a test that fails on a busy machine is not a gate. `mulAlphaPow` has
    // its own test below.
    const seed = crypto.getRandomValues(new Uint8Array(16));
    const seen = new Set<string>();
    let acc: Uint8Array = seed;
    for (let j = 0; j < 4096; j++) {
      seen.add(toHex(acc));
      acc = mulAlpha(acc);
    }
    expect(seen.size).toBe(4096);
  });

  it('mulAlphaPow(e, n) equals n applications of mulAlpha', () => {
    const seed = fromHex('0f1e2d3c4b5a69788796a5b4c3d2e1f0');
    let acc: Uint8Array = Uint8Array.from(seed);
    for (let n = 0; n < 40; n++) {
      expect(toHex(mulAlphaPow(seed, n))).toBe(toHex(acc));
      acc = mulAlpha(acc);
    }
  });

  it('rejects elements that are not 16 bytes', () => {
    expect(() => mulAlpha(fromHex('00'))).toThrow(/16 bytes/);
    expect(() => mulAlphaTraced(fromHex('00'))).toThrow(/16 bytes/);
    expect(() => mulAlphaPow(fromHex('00'.repeat(16)), -1)).toThrow(/non-negative/);
  });
});
