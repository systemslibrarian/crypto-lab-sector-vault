/**
 * EME2 / EME* research implementation, not IEEE 1619.2-2025 conformance.
 * Halevi, ePrint 2004/125, §3 Figure 1 (27 May 2004), instantiated with AES.
 * Byte encoding: archived IEEE P1619.2/D9 §5.2 (December 2008).
 * Keys are explicit: KAES is an AES key; KECB=L and KAD=R are independent
 * 128-bit masks, not AES key schedules. No derivation from a single AES key.
 * The draft serializes KAD | KECB | KAES; the cross-check Rust crate instead
 * serializes KAES | KECB | KAD. See docs/eme2-validation.md.
 *
 * Noble supplies AES. This module supplies both ECB passes, AD hashing,
 * partial-block handling and mask renewal every 128 blocks. Bounds below are
 * this teaching implementation's resource limits, not the standard's limits.
 * No tag, authentication error or replay check exists in this construction.
 */
import { unsafe } from '@noble/ciphers/aes.js';
import { mulAlpha } from './gf128.js';
import { xorBytes } from './bytes.js';

export const EME2_MAX_BYTES = 8192;
export const EME2_MAX_AD_BYTES = 4096;

export interface Eme2Keys {
  aes: Uint8Array;
  ecbMask: Uint8Array;
  adMask: Uint8Array;
}

export interface Eme2Cipher {
  hashAssociatedData(ad: Uint8Array): Uint8Array;
  encrypt(ad: Uint8Array, plaintext: Uint8Array): Uint8Array;
  decrypt(ad: Uint8Array, ciphertext: Uint8Array): Uint8Array;
}

function padded(block: Uint8Array): Uint8Array {
  const out = new Uint8Array(16);
  out.set(block);
  out[block.length] = 0x80;
  return out;
}

export function createEme2Cipher(keys: Eme2Keys): Eme2Cipher {
  if (![16, 32].includes(keys.aes.length) || keys.ecbMask.length !== 16 || keys.adMask.length !== 16) {
    throw new Error('EME2 needs a 16- or 32-byte AES key and two independent 16-byte masks');
  }
  const encKey = unsafe.expandKeyLE(keys.aes);
  const decKey = unsafe.expandKeyDecLE(keys.aes);
  const l = Uint8Array.from(keys.ecbMask);
  const r = Uint8Array.from(keys.adMask);
  // Noble's raw block API mutates its argument. Never expose that mutation to
  // callers, saved intermediates, key masks or the AD hash accumulator.
  const enc = (b: Uint8Array): Uint8Array => unsafe.encryptBlock(encKey, Uint8Array.from(b));
  const dec = (b: Uint8Array): Uint8Array => unsafe.decryptBlock(decKey, Uint8Array.from(b));

  function hashAssociatedData(ad: Uint8Array): Uint8Array {
    if (ad.length > EME2_MAX_AD_BYTES) throw new Error('EME2 exhibit AD limit is 4096 bytes');
    if (ad.length === 0) return enc(r);
    let mask = mulAlpha(r);
    let sum: Uint8Array = new Uint8Array(16);
    for (let offset = 0; offset < ad.length; offset += 16) {
      let block: Uint8Array = ad.subarray(offset, offset + 16);
      if (block.length < 16) {
        block = padded(block);
        mask = mulAlpha(mask); // partial AD uses one extra alpha factor
      }
      sum = xorBytes(sum, xorBytes(enc(xorBytes(mask, block)), mask));
      mask = mulAlpha(mask);
    }
    return sum;
  }

  function transform(ad: Uint8Array, input: Uint8Array, decrypt: boolean): Uint8Array {
    if (input.length < 16 || input.length > EME2_MAX_BYTES) {
      throw new Error('EME2 exhibit data unit must contain 16–8192 bytes');
    }
    const aes = decrypt ? dec : enc;
    const t = hashAssociatedData(ad); // always AES encryption, even on decrypt
    const m = Math.ceil(input.length / 16);
    const partial = input.length % 16;
    const full = Math.floor(input.length / 16);
    const first: Uint8Array[] = [];
    let mask: Uint8Array = l;
    let sum = t;
    for (let i = 0; i < m; i++) {
      const block = input.subarray(i * 16, (i + 1) * 16);
      first[i] = block.length === 16 ? aes(xorBytes(block, mask)) : padded(block);
      sum = xorBytes(sum, first[i]);
      mask = mulAlpha(mask);
    }
    const mm = aes(sum);
    const mixedSum = partial ? aes(mm) : mm;
    const initialMix = xorBytes(sum, mixedSum);
    let runningMix = initialMix;
    const mixed: Uint8Array[] = [];
    for (let i = 1; i < full; i++) {
      if (i % 128 === 0) {
        const before = xorBytes(first[i], initialMix);
        const after = aes(before);
        runningMix = xorBytes(before, after);
        mixed[i] = xorBytes(after, initialMix);
      } else {
        runningMix = mulAlpha(runningMix);
        mixed[i] = xorBytes(first[i], runningMix);
      }
    }
    const out = new Uint8Array(input.length);
    if (partial) {
      const tail = xorBytes(input.subarray(full * 16), mm.subarray(0, partial));
      out.set(tail, full * 16);
      mixed[full] = padded(tail);
    }
    // Recover the first mixed block from the total, AD and all other blocks.
    mixed[0] = xorBytes(mixedSum, t);
    for (let i = 1; i < m; i++) mixed[0] = xorBytes(mixed[0], mixed[i]);
    mask = l;
    for (let i = 0; i < full; i++) {
      out.set(xorBytes(aes(mixed[i]), mask), i * 16);
      mask = mulAlpha(mask);
    }
    return out;
  }

  return {
    hashAssociatedData,
    encrypt: (ad, plaintext) => transform(ad, plaintext, false),
    decrypt: (ad, ciphertext) => transform(ad, ciphertext, true),
  };
}
