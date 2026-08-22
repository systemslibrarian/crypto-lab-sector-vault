/**
 * The XTS tweak algebra, hand-rolled because it is the thing this lab teaches.
 *
 * XTS derives one tweak per 16-byte block: T_j = AES-K2(sequence number) then
 * multiplied j times by the primitive element alpha = x of GF(2^128), the field
 * taken modulo the IEEE 1619 / SP 800-38E polynomial
 *
 *     x^128 + x^7 + x^2 + x + 1
 *
 * In the byte-little-endian, bit-little-endian representation the standard
 * fixes, multiplying by x is a one-bit left shift of the whole 128-bit value,
 * and the reduction is a single XOR of 0x87 into byte 0 whenever that shift
 * carried a 1 out of the top. That is the entire operation — 16 bytes of shift
 * and one conditional XOR — and it is why a block's position, and nothing else
 * about it, is bound into its ciphertext.
 *
 * Nothing here is a model of the multiplication. It IS the multiplication, and
 * `mulAlphaTraced` returns the same result as `mulAlpha` alongside the
 * intermediates, so the panel that draws it cannot drift from what the cipher
 * runs.
 */

/** The low byte of the reduction polynomial, x^7 + x^2 + x + 1 = 0x87. */
export const REDUCTION_BYTE = 0x87;

export const GF_BLOCK_BYTES = 16;

/** Multiply a 128-bit field element by alpha (= x). */
export function mulAlpha(element: Uint8Array): Uint8Array {
  if (element.length !== GF_BLOCK_BYTES) {
    throw new Error(`field element must be ${GF_BLOCK_BYTES} bytes, got ${element.length}`);
  }
  const out = new Uint8Array(GF_BLOCK_BYTES);
  let carry = 0;
  for (let i = 0; i < GF_BLOCK_BYTES; i++) {
    const carryOut = element[i] >>> 7;
    out[i] = ((element[i] << 1) | carry) & 0xff;
    carry = carryOut;
  }
  if (carry) out[0] ^= REDUCTION_BYTE;
  return out;
}

export interface AlphaStep {
  /** The element that went in. */
  input: Uint8Array;
  /** After the 128-bit left shift, before any reduction. */
  shifted: Uint8Array;
  /** The bit that fell off the top of byte 15 — 1 means the shift overflowed x^127. */
  carryOut: 0 | 1;
  /** True when the reduction XOR was applied (identical to carryOut === 1). */
  reduced: boolean;
  /** The finished product, byte-identical to `mulAlpha(input)`. */
  output: Uint8Array;
}

/**
 * `mulAlpha` with its intermediates exposed, for the stepper panel. The output
 * is asserted equal to `mulAlpha`'s in `gf128.test.ts`, so the drawn steps
 * cannot describe an operation the cipher does not perform.
 */
export function mulAlphaTraced(element: Uint8Array): AlphaStep {
  if (element.length !== GF_BLOCK_BYTES) {
    throw new Error(`field element must be ${GF_BLOCK_BYTES} bytes, got ${element.length}`);
  }
  const input = Uint8Array.from(element);
  const shifted = new Uint8Array(GF_BLOCK_BYTES);
  let carry = 0;
  for (let i = 0; i < GF_BLOCK_BYTES; i++) {
    const carryOut = element[i] >>> 7;
    shifted[i] = ((element[i] << 1) | carry) & 0xff;
    carry = carryOut;
  }
  const carryOut = carry as 0 | 1;
  const output = Uint8Array.from(shifted);
  if (carryOut) output[0] ^= REDUCTION_BYTE;
  return { input, shifted, carryOut, reduced: carryOut === 1, output };
}

/** alpha^power times `element`, by repeated multiplication. */
export function mulAlphaPow(element: Uint8Array, power: number): Uint8Array {
  if (!Number.isInteger(power) || power < 0) throw new Error('power must be a non-negative integer');
  let acc: Uint8Array = Uint8Array.from(element);
  for (let i = 0; i < power; i++) acc = mulAlpha(acc);
  return acc;
}
