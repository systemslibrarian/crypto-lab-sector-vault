/**
 * A 16-sector XTS volume, plus the write log a real disk does NOT keep.
 *
 * The log is the whole trick of this lab. XTS gives a driver bytes and nothing
 * else — no tag, no version, no error. To show what that costs, this model
 * remembers every plaintext ever written so the page can print, side by side,
 * "what XTS reported" (always: nothing) and "what actually happened". A
 * shipping full-disk-encryption stack has only the first column.
 */
import { createXtsCipher, type XtsCipher, type XtsKeyPair } from '../crypto/xts.js';
import { equalBytes } from '../crypto/bytes.js';
import {
  assertSectorIndex,
  BLOCK_BYTES,
  BLOCKS_PER_SECTOR,
  SECTOR_BYTES,
  SECTOR_COUNT,
  type ReadStatus,
} from './types.js';
import { textToSector } from './text.js';

export interface WriteRecord {
  /** 1-based write counter for this sector. */
  version: number;
  plaintext: Uint8Array;
  ciphertext: Uint8Array;
  label: string;
}

export interface SectorRead {
  sector: number;
  /** What XTS produced from whatever is on the platter right now. */
  plaintext: Uint8Array;
  /** What was last written here, per the lab's log. XTS has no access to this. */
  expected: Uint8Array;
  status: ReadStatus;
  /** Set when the bytes read are a genuine earlier version of this sector. */
  staleVersion: number | null;
  /** Indices of the 16-byte blocks whose plaintext differs from the last write. */
  changedBlocks: number[];
  /**
   * Always null. XTS has no failure to report about a read: there is no tag to
   * check and no redundancy to notice. The field exists so the panel renders
   * the absence rather than describing it.
   */
  failureCode: null;
}

export interface Snapshot {
  label: string;
  /** Ciphertext only. An attacker taking disk images has exactly this and no key. */
  ciphertext: Uint8Array[];
}

export class SectorVolume {
  readonly cipher: XtsCipher;
  private readonly platter: Uint8Array[] = [];
  private readonly log: WriteRecord[][] = [];

  constructor(readonly key: XtsKeyPair) {
    this.cipher = createXtsCipher(key);
    for (let i = 0; i < SECTOR_COUNT; i++) {
      this.platter.push(new Uint8Array(SECTOR_BYTES));
      this.log.push([]);
    }
  }

  /** Sector numbers are the XTS data unit sequence numbers, one-for-one. */
  sequenceNumber(sector: number): bigint {
    assertSectorIndex(sector);
    return BigInt(sector);
  }

  writeText(sector: number, text: string): WriteRecord {
    return this.write(sector, textToSector(text), text);
  }

  write(sector: number, plaintext: Uint8Array, label: string): WriteRecord {
    assertSectorIndex(sector);
    if (plaintext.length !== SECTOR_BYTES) {
      throw new RangeError(`a sector write must be exactly ${SECTOR_BYTES} bytes, got ${plaintext.length}`);
    }
    const ciphertext = this.cipher.encryptSector(this.sequenceNumber(sector), plaintext);
    const record: WriteRecord = {
      version: this.log[sector].length + 1,
      plaintext: Uint8Array.from(plaintext),
      ciphertext: Uint8Array.from(ciphertext),
      label,
    };
    this.log[sector].push(record);
    this.platter[sector] = Uint8Array.from(ciphertext);
    return record;
  }

  /** The bytes currently on the platter. Attacks edit exactly this. */
  ciphertextOf(sector: number): Uint8Array {
    assertSectorIndex(sector);
    return this.platter[sector];
  }

  setCiphertext(sector: number, ciphertext: Uint8Array): void {
    assertSectorIndex(sector);
    if (ciphertext.length !== SECTOR_BYTES) {
      throw new RangeError(`a sector is ${SECTOR_BYTES} bytes, got ${ciphertext.length}`);
    }
    this.platter[sector] = Uint8Array.from(ciphertext);
  }

  history(sector: number): readonly WriteRecord[] {
    assertSectorIndex(sector);
    return this.log[sector];
  }

  hasBeenWritten(sector: number): boolean {
    return this.history(sector).length > 0;
  }

  /** T_j for a block, so the panel can show the tweak the cipher will actually use. */
  tweakFor(sector: number, block: number): Uint8Array {
    return this.cipher.tweakForBlock(this.sequenceNumber(sector), block);
  }

  read(sector: number): SectorRead {
    assertSectorIndex(sector);
    const plaintext = this.cipher.decryptSector(this.sequenceNumber(sector), this.platter[sector]);
    const entries = this.log[sector];
    const expected = entries.length ? entries[entries.length - 1].plaintext : new Uint8Array(SECTOR_BYTES);

    const changedBlocks: number[] = [];
    for (let b = 0; b < BLOCKS_PER_SECTOR; b++) {
      const off = b * BLOCK_BYTES;
      if (!equalBytes(plaintext.subarray(off, off + BLOCK_BYTES), expected.subarray(off, off + BLOCK_BYTES))) {
        changedBlocks.push(b);
      }
    }

    let status: ReadStatus = 'INTACT';
    let staleVersion: number | null = null;
    if (changedBlocks.length > 0) {
      // A read that returns an EARLIER version of this same sector is not
      // corruption: those bytes were written here, by the key holder, and they
      // decrypt perfectly. Nothing in XTS binds a version, so the read is clean
      // and wrong at the same time.
      const older = entries.find((entry) => equalBytes(entry.plaintext, plaintext));
      if (older) {
        status = 'SUCCEEDS_CLEANLY_STALE';
        staleVersion = older.version;
      } else {
        status = 'CORRUPTED_UNDETECTED';
      }
    }

    return { sector, plaintext, expected, status, staleVersion, changedBlocks, failureCode: null };
  }

  readAll(): SectorRead[] {
    return Array.from({ length: SECTOR_COUNT }, (_, i) => this.read(i));
  }

  /** A disk image: ciphertext for every sector, no key, no log. */
  snapshot(label: string): Snapshot {
    return {
      label,
      ciphertext: this.platter.map((sector) => Uint8Array.from(sector)),
    };
  }
}
