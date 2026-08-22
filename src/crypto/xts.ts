/**
 * XTS-AES — NIST SP 800-38E / IEEE Std 1619-2007.
 *
 * The single-block AES call comes from @noble/ciphers' audited `unsafe`
 * block API (`expandKeyLE` + `encryptBlock`/`decryptBlock`). That is the
 * deliberate split: the block cipher is a vetted primitive nobody should
 * re-implement for a teaching demo, while the XEX tweaking, the alpha ladder
 * and the ciphertext stealing — the parts this lab exists to expose — are
 * written out here where they can be read and stepped.
 *
 * WebCrypto is not usable for the primitive: it exposes no raw single-block
 * AES, and the usual workaround (AES-CBC with a zero IV over one block, then
 * discarding the padding block) is a coercion that hides the very operation
 * being taught.
 *
 * Failure codes are deliberately almost empty. XTS has exactly two things it
 * can refuse — a data unit too short to encrypt, and a key of the wrong length
 * — and NOTHING it can say about a ciphertext an adversary has edited. There is
 * no MAC, no tag, no redundancy: SP 800-38E section 4 states the mode provides
 * confidentiality only and "does not provide authentication of the data or its
 * source". The absence in this enum is the exhibit.
 */
import { unsafe } from '@noble/ciphers/aes.js';
import { mulAlpha } from './gf128.js';
import { sequenceNumberToBlock, xorBytes } from './bytes.js';

export const XTS_BLOCK_BYTES = 16;

/** Every failure XTS itself is capable of reporting. There are two. */
export const XTS_FAILURE_CODES = ['MALFORMED_SECTOR', 'KEY_LENGTH_INVALID'] as const;
export type XtsFailureCode = (typeof XTS_FAILURE_CODES)[number];

export class XtsError extends Error {
  readonly code: XtsFailureCode;
  constructor(code: XtsFailureCode, message: string) {
    super(message);
    this.name = 'XtsError';
    this.code = code;
  }
}

export interface XtsKeyPair {
  /** The data key. Never used to derive a tweak. */
  k1: Uint8Array;
  /** The tweak key. Never used to encrypt data. */
  k2: Uint8Array;
}

export interface XexTrace {
  /** T_j, the tweak for this block. */
  tweak: Uint8Array;
  /** P XOR T — what actually enters AES. */
  masked: Uint8Array;
  /** AES-K1 of that. */
  aesOutput: Uint8Array;
  /** The finished ciphertext block: AES output XOR T again. */
  ciphertext: Uint8Array;
}

export interface XtsCipher {
  /** 128 for XTS-AES-128 (a 256-bit XTS key), 256 for XTS-AES-256. */
  readonly aesBits: 128 | 256;
  /**
   * One block's encryption with its intermediates exposed, so the page can
   * print the XEX sandwich with real values instead of describing it. The
   * ciphertext it returns is asserted equal to the corresponding slice of
   * `encryptSector` in `xts.test.ts`.
   */
  traceBlockEncrypt(sequenceNumber: bigint, blockIndex: number, plaintextBlock: Uint8Array): XexTrace;
  /** T_0 for a data unit: AES-K2(sequence number as a 128-bit little-endian block). */
  tweakSeed(sequenceNumber: bigint): Uint8Array;
  /** T_j = T_0 * alpha^j, the tweak actually XORed around block j. */
  tweakForBlock(sequenceNumber: bigint, blockIndex: number): Uint8Array;
  encryptSector(sequenceNumber: bigint, plaintext: Uint8Array): Uint8Array;
  decryptSector(sequenceNumber: bigint, ciphertext: Uint8Array): Uint8Array;
}

function assertKeyPair(key: XtsKeyPair): 128 | 256 {
  const { k1, k2 } = key;
  if (k1.length !== k2.length) {
    throw new XtsError(
      'KEY_LENGTH_INVALID',
      `K1 is ${k1.length} bytes and K2 is ${k2.length}; XTS requires two keys of the same length`,
    );
  }
  if (k1.length !== 16 && k1.length !== 32) {
    throw new XtsError(
      'KEY_LENGTH_INVALID',
      `XTS-AES takes two 16-byte keys (XTS-AES-128) or two 32-byte keys (XTS-AES-256); got ${k1.length}`,
    );
  }
  return k1.length === 16 ? 128 : 256;
}

/** C = AES-Enc(K1, P XOR T) XOR T — the XEX construction, one block. */
function blockEncrypt(encKey: Uint32Array, block: Uint8Array, tweak: Uint8Array): Uint8Array {
  return xorBytes(unsafe.encryptBlock(encKey, xorBytes(block, tweak)), tweak);
}

/** P = AES-Dec(K1, C XOR T) XOR T. */
function blockDecrypt(decKey: Uint32Array, block: Uint8Array, tweak: Uint8Array): Uint8Array {
  return xorBytes(unsafe.decryptBlock(decKey, xorBytes(block, tweak)), tweak);
}

export function createXtsCipher(key: XtsKeyPair): XtsCipher {
  const aesBits = assertKeyPair(key);
  // Key schedules are expanded once. Each is derived from exactly one of the
  // two keys, which is the separation XTS depends on: K2 never touches data,
  // K1 never touches a tweak.
  const dataEnc = unsafe.expandKeyLE(key.k1);
  const dataDec = unsafe.expandKeyDecLE(key.k1);
  const tweakEnc = unsafe.expandKeyLE(key.k2);

  const tweakSeed = (sequenceNumber: bigint): Uint8Array =>
    unsafe.encryptBlock(tweakEnc, sequenceNumberToBlock(sequenceNumber));

  const tweakForBlock = (sequenceNumber: bigint, blockIndex: number): Uint8Array => {
    if (!Number.isInteger(blockIndex) || blockIndex < 0) {
      throw new Error('blockIndex must be a non-negative integer');
    }
    let tweak = tweakSeed(sequenceNumber);
    for (let j = 0; j < blockIndex; j++) tweak = mulAlpha(tweak);
    return tweak;
  };

  function assertDataUnit(data: Uint8Array): void {
    if (data.length < XTS_BLOCK_BYTES) {
      throw new XtsError(
        'MALFORMED_SECTOR',
        `a data unit must be at least ${XTS_BLOCK_BYTES} bytes; got ${data.length}`,
      );
    }
  }

  return {
    aesBits,
    tweakSeed,
    tweakForBlock,

    traceBlockEncrypt(sequenceNumber, blockIndex, plaintextBlock) {
      if (plaintextBlock.length !== XTS_BLOCK_BYTES) {
        throw new XtsError('MALFORMED_SECTOR', `a trace needs exactly one ${XTS_BLOCK_BYTES}-byte block`);
      }
      const tweak = tweakForBlock(sequenceNumber, blockIndex);
      const masked = xorBytes(plaintextBlock, tweak);
      // noble's block primitive encrypts IN PLACE and returns the same buffer,
      // so the trace hands it a copy; otherwise `masked` would be overwritten
      // with the AES output and the panel would print the same 16 bytes twice.
      const aesOutput = unsafe.encryptBlock(dataEnc, Uint8Array.from(masked));
      return { tweak, masked, aesOutput, ciphertext: xorBytes(aesOutput, tweak) };
    },

    encryptSector(sequenceNumber, plaintext) {
      assertDataUnit(plaintext);
      const whole = Math.floor(plaintext.length / XTS_BLOCK_BYTES);
      const tail = plaintext.length % XTS_BLOCK_BYTES;
      const out = new Uint8Array(plaintext.length);
      let tweak = tweakSeed(sequenceNumber);

      // Every full block except the last one when stealing is required.
      const plainBlocks = tail === 0 ? whole : whole - 1;
      for (let j = 0; j < plainBlocks; j++) {
        const off = j * XTS_BLOCK_BYTES;
        out.set(blockEncrypt(dataEnc, plaintext.subarray(off, off + XTS_BLOCK_BYTES), tweak), off);
        tweak = mulAlpha(tweak);
      }

      if (tail !== 0) {
        // Ciphertext stealing (SP 800-38E section 5.3.2 / IEEE 1619 5.3):
        // the second-to-last plaintext block is encrypted under tweak m-1, its
        // first `tail` bytes become the FINAL short ciphertext block, and its
        // remaining bytes are stolen back to pad the short plaintext block,
        // which is then encrypted under tweak m into the second-to-last slot.
        const off = plainBlocks * XTS_BLOCK_BYTES;
        const cc = blockEncrypt(dataEnc, plaintext.subarray(off, off + XTS_BLOCK_BYTES), tweak);
        const nextTweak = mulAlpha(tweak);
        const padded = new Uint8Array(XTS_BLOCK_BYTES);
        padded.set(plaintext.subarray(off + XTS_BLOCK_BYTES), 0);
        padded.set(cc.subarray(tail), tail);
        out.set(blockEncrypt(dataEnc, padded, nextTweak), off);
        out.set(cc.subarray(0, tail), off + XTS_BLOCK_BYTES);
      }
      return out;
    },

    decryptSector(sequenceNumber, ciphertext) {
      assertDataUnit(ciphertext);
      const whole = Math.floor(ciphertext.length / XTS_BLOCK_BYTES);
      const tail = ciphertext.length % XTS_BLOCK_BYTES;
      const out = new Uint8Array(ciphertext.length);
      let tweak = tweakSeed(sequenceNumber);

      const plainBlocks = tail === 0 ? whole : whole - 1;
      for (let j = 0; j < plainBlocks; j++) {
        const off = j * XTS_BLOCK_BYTES;
        out.set(blockDecrypt(dataDec, ciphertext.subarray(off, off + XTS_BLOCK_BYTES), tweak), off);
        tweak = mulAlpha(tweak);
      }

      if (tail !== 0) {
        const off = plainBlocks * XTS_BLOCK_BYTES;
        const nextTweak = mulAlpha(tweak);
        const pp = blockDecrypt(dataDec, ciphertext.subarray(off, off + XTS_BLOCK_BYTES), nextTweak);
        const cc = new Uint8Array(XTS_BLOCK_BYTES);
        cc.set(ciphertext.subarray(off + XTS_BLOCK_BYTES), 0);
        cc.set(pp.subarray(tail), tail);
        out.set(blockDecrypt(dataDec, cc, tweak), off);
        out.set(pp.subarray(0, tail), off + XTS_BLOCK_BYTES);
      }
      return out;
    },
  };
}
