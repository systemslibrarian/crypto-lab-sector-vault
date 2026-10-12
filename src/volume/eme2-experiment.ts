import { createEme2Cipher, type Eme2Keys } from '../crypto/eme2.js';
import { createXtsCipher } from '../crypto/xts.js';
import { equalBytes, hammingDistance, sequenceNumberToBlock } from '../crypto/bytes.js';

export type Eme2Experiment = 'clean' | 'plaintext-bit' | 'ciphertext-bit' | 'splice' | 'wrong-ad' | 'replay';
export interface DiffusionResult {
  bytes: Uint8Array;
  changed: boolean[];
  changedBlocks: number;
  changedBits: number;
}
export interface Eme2Comparison {
  xts: DiffusionResult;
  eme2: DiffusionResult;
  length: number;
  outputLabel: string;
  result: string;
  detail: string;
}

function measure(expected: Uint8Array, bytes: Uint8Array): DiffusionResult {
  const changed: boolean[] = [];
  for (let offset = 0; offset < bytes.length; offset += 16) {
    changed.push(!equalBytes(expected.subarray(offset, offset + 16), bytes.subarray(offset, offset + 16)));
  }
  return { bytes, changed, changedBlocks: changed.filter(Boolean).length, changedBits: hammingDistance(expected, bytes) };
}

/** A separate synthetic data unit; it never reads or writes the main volume. */
export function runEme2Experiment(keys: Eme2Keys, length: number, experiment: Eme2Experiment): Eme2Comparison {
  if (keys.aes.length !== 16) throw new Error('the comparison uses AES-128 in both modes');
  if (![512, 513, 2064].includes(length)) throw new Error('unsupported comparison length');
  const eme2 = createEme2Cipher(keys);
  const xts = createXtsCipher({ k1: keys.aes, k2: keys.ecbMask });
  const sector = 9n;
  const ad = sequenceNumberToBlock(sector);
  const line = new TextEncoder().encode('Sector 9: library record version 1. ');
  const original = Uint8Array.from({ length }, (_, i) => line[i % line.length]);
  const latest = Uint8Array.from(original);
  latest[0] ^= 1;
  let expected = original;
  let x = xts.encryptSector(sector, original);
  let e = eme2.encrypt(ad, original);
  const outputLabel = 'Decrypted plaintext';
  let result = 'Original bytes returned; neither mode checked authenticity.';
  let detail = 'The maps compare decrypted bytes with the original plaintext.';
  let decryptSector = sector;
  let decryptAd = ad;

  if (experiment === 'plaintext-bit') {
    return {
      xts: measure(x, xts.encryptSector(sector, latest)),
      eme2: measure(e, eme2.encrypt(ad, latest)), length,
      outputLabel: 'Ciphertext output',
      result: 'One plaintext bit changed before encryption.',
      detail: 'Same keys, length and address/AD. The maps measure ciphertext diffusion, not tamper detection.',
    };
  }
  if (experiment === 'ciphertext-bit') {
    x[20] ^= 1; e[20] ^= 1;
    result = 'Modified bytes returned — no authentication error.';
    detail = 'A storage attacker flipped the same ciphertext bit in each mode. Wider corruption is not a rejection.';
  } else if (experiment === 'splice') {
    const other = Uint8Array.from(original, b => b ^ 0x55);
    x.set(xts.encryptSector(sector, other).subarray(16, 32), 16);
    e.set(eme2.encrypt(ad, other).subarray(16, 32), 16);
    result = 'Spliced bytes returned — no authentication error.';
    detail = 'One 16-byte ciphertext block came from another write at the same address. XTS accepts the donor block locally; EME2 mixes its effect across the data unit.';
  } else if (experiment === 'wrong-ad') {
    decryptSector = sector + 1n;
    decryptAd = sequenceNumberToBlock(decryptSector);
    result = 'Wrong-address bytes returned — no authentication error.';
    detail = 'XTS reads under a different sector tweak; EME2 reads under different associated data. Binding changes the plaintext, without authenticating it.';
  } else if (experiment === 'replay') {
    const savedX = x.slice(), savedE = e.slice();
    x = xts.encryptSector(sector, latest);
    e = eme2.encrypt(ad, latest);
    if (!equalBytes(xts.decryptSector(sector, x), latest) || !equalBytes(eme2.decrypt(ad, e), latest)) {
      throw new Error('the later write did not round-trip');
    }
    // Replace the newly written ciphertext with the saved image, as an
    // attacker with access to stored bytes can. No freshness gate is invoked.
    x.set(savedX); e.set(savedE);
    expected = latest;
    result = 'Old version returned intact — rollback accepted.';
    detail = 'A later write changed one plaintext bit. Restoring the original ciphertext under the same address/AD returns the original bytes exactly. The map compares them with the latest version; it is not corruption. No trusted version state exists here.';
  }
  x = xts.decryptSector(decryptSector, x);
  e = eme2.decrypt(decryptAd, e);
  return { xts: measure(expected, x), eme2: measure(expected, e), length, outputLabel, result, detail };
}
