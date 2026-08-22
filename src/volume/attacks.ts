/**
 * The four edits an adversary with the disk — and no key — can make.
 *
 * Every one of them operates on ciphertext bytes only. None of them needs, or
 * is given, K1 or K2: the functions here receive a `SectorVolume` but touch it
 * exclusively through `ciphertextOf` / `setCiphertext`, which is the same
 * access a stolen laptop, a snapshotted VM image or a malicious storage backend
 * has.
 */
import { SectorVolume } from './volume.js';
import { assertBlockIndex, assertSectorIndex, BLOCK_BYTES, SECTOR_BYTES } from './types.js';

export interface AttackResult {
  /** One line naming exactly what changed on the platter. */
  description: string;
  /** Sectors whose ciphertext this edit touched. */
  touchedSectors: number[];
  /** Ciphertext bytes changed. Zero means the edit was a no-op. */
  bytesChanged: number;
}

function countDifferences(a: Uint8Array, b: Uint8Array): number {
  let n = 0;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) n++;
  return n;
}

/** Flip a single bit of ciphertext. The most surgical edit there is. */
export function flipCiphertextBit(
  volume: SectorVolume,
  sector: number,
  byteOffset: number,
  bitIndex: number,
): AttackResult {
  assertSectorIndex(sector);
  if (!Number.isInteger(byteOffset) || byteOffset < 0 || byteOffset >= SECTOR_BYTES) {
    throw new RangeError(`byte offset must be in 0..${SECTOR_BYTES - 1}, got ${byteOffset}`);
  }
  if (!Number.isInteger(bitIndex) || bitIndex < 0 || bitIndex > 7) {
    throw new RangeError(`bit index must be in 0..7, got ${bitIndex}`);
  }
  const before = volume.ciphertextOf(sector);
  const after = Uint8Array.from(before);
  after[byteOffset] ^= 1 << bitIndex;
  volume.setCiphertext(sector, after);
  return {
    description: `Flipped bit ${bitIndex} of ciphertext byte ${byteOffset} in sector ${sector} (block ${Math.floor(byteOffset / BLOCK_BYTES)}).`,
    touchedSectors: [sector],
    bytesChanged: 1,
  };
}

/** Copy one 16-byte ciphertext block over another, anywhere on the volume. */
export function relocateBlock(
  volume: SectorVolume,
  from: { sector: number; block: number },
  to: { sector: number; block: number },
): AttackResult {
  assertSectorIndex(from.sector);
  assertSectorIndex(to.sector);
  assertBlockIndex(from.block);
  assertBlockIndex(to.block);
  const source = volume.ciphertextOf(from.sector).subarray(from.block * BLOCK_BYTES, from.block * BLOCK_BYTES + BLOCK_BYTES);
  const before = volume.ciphertextOf(to.sector);
  const after = Uint8Array.from(before);
  after.set(source, to.block * BLOCK_BYTES);
  volume.setCiphertext(to.sector, after);
  return {
    description: `Copied ciphertext block ${from.block} of sector ${from.sector} over block ${to.block} of sector ${to.sector}.`,
    touchedSectors: [to.sector],
    bytesChanged: countDifferences(before, after),
  };
}

/** Copy a whole sector's ciphertext to a different sector number. */
export function relocateSector(volume: SectorVolume, from: number, to: number): AttackResult {
  assertSectorIndex(from);
  assertSectorIndex(to);
  const before = volume.ciphertextOf(to);
  const source = Uint8Array.from(volume.ciphertextOf(from));
  volume.setCiphertext(to, source);
  return {
    description: `Copied the whole ciphertext of sector ${from} into sector ${to}.`,
    touchedSectors: [to],
    bytesChanged: countDifferences(before, source),
  };
}

/**
 * Put an earlier ciphertext for a sector back over itself.
 *
 * Nothing is corrupted by this. Those exact bytes were written to that exact
 * sector by the key holder, so they decrypt perfectly under the same tweak. The
 * only thing wrong with the result is that it is old, and XTS has no notion of
 * old.
 */
export function rollbackSector(volume: SectorVolume, sector: number, toVersion: number): AttackResult {
  assertSectorIndex(sector);
  const record = volume.history(sector).find((entry) => entry.version === toVersion);
  if (!record) {
    throw new RangeError(`sector ${sector} has no version ${toVersion} in its write history`);
  }
  const before = volume.ciphertextOf(sector);
  volume.setCiphertext(sector, record.ciphertext);
  return {
    description: `Restored sector ${sector} from a disk image taken at version ${toVersion} ("${record.label}").`,
    touchedSectors: [sector],
    bytesChanged: countDifferences(before, record.ciphertext),
  };
}
