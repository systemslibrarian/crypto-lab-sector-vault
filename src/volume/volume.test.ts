import { describe, expect, it } from 'vitest';
import { SectorVolume } from './volume.js';
import { BLOCKS_PER_SECTOR, SECTOR_BYTES, SECTOR_COUNT } from './types.js';
import { textToSector } from './text.js';
import { equalBytes, toHex } from '../crypto/bytes.js';
import { createXtsCipher } from '../crypto/xts.js';

function freshVolume(): SectorVolume {
  return new SectorVolume({
    k1: crypto.getRandomValues(new Uint8Array(16)),
    k2: crypto.getRandomValues(new Uint8Array(16)),
  });
}

describe('SectorVolume', () => {
  it('is sixteen 512-byte sectors of thirty-two blocks', () => {
    expect(SECTOR_COUNT).toBe(16);
    expect(SECTOR_BYTES).toBe(512);
    expect(BLOCKS_PER_SECTOR).toBe(32);
  });

  it('reads back exactly what was written', () => {
    const volume = freshVolume();
    for (let s = 0; s < SECTOR_COUNT; s++) volume.writeText(s, `SECTOR ${s} PAYLOAD`);
    for (const read of volume.readAll()) {
      expect(read.status).toBe('INTACT');
      expect(read.changedBlocks).toEqual([]);
      expect(read.failureCode).toBeNull();
      expect(equalBytes(read.plaintext, read.expected)).toBe(true);
    }
  });

  it('uses the sector number as the XTS data unit sequence number', () => {
    const volume = freshVolume();
    const cipher = createXtsCipher(volume.key);
    volume.writeText(9, 'PAYLOAD');
    expect(toHex(volume.ciphertextOf(9))).toBe(toHex(cipher.encryptSector(9n, textToSector('PAYLOAD'))));
    expect(volume.sequenceNumber(9)).toBe(9n);
  });

  it('exposes the tweak the cipher will really use for a block', () => {
    const volume = freshVolume();
    const cipher = createXtsCipher(volume.key);
    for (const block of [0, 1, 17, 31]) {
      expect(toHex(volume.tweakFor(4, block))).toBe(toHex(cipher.tweakForBlock(4n, block)));
    }
  });

  it('keeps a version history per sector', () => {
    const volume = freshVolume();
    volume.writeText(2, 'FIRST');
    volume.writeText(2, 'SECOND');
    volume.writeText(2, 'THIRD');
    expect(volume.history(2).map((entry) => entry.version)).toEqual([1, 2, 3]);
    expect(volume.history(2).map((entry) => entry.label)).toEqual(['FIRST', 'SECOND', 'THIRD']);
    expect(volume.hasBeenWritten(2)).toBe(true);
    expect(volume.hasBeenWritten(3)).toBe(false);
  });

  it('never returns a failure code, because XTS has none for a read', () => {
    const volume = freshVolume();
    volume.writeText(0, 'PAYLOAD');
    const scrambled = crypto.getRandomValues(new Uint8Array(SECTOR_BYTES));
    volume.setCiphertext(0, scrambled);
    const read = volume.read(0);
    expect(read.failureCode).toBeNull();
    expect(read.plaintext.length).toBe(SECTOR_BYTES);
  });

  it('rejects out-of-range sectors and wrong-sized writes', () => {
    const volume = freshVolume();
    expect(() => volume.read(-1)).toThrow(RangeError);
    expect(() => volume.read(SECTOR_COUNT)).toThrow(RangeError);
    expect(() => volume.write(0, new Uint8Array(511), 'short')).toThrow(/exactly 512 bytes/);
    expect(() => volume.setCiphertext(0, new Uint8Array(13))).toThrow(/512 bytes/);
  });

  it('snapshots ciphertext only, and detaches it from the platter', () => {
    const volume = freshVolume();
    volume.writeText(1, 'BEFORE');
    const snap = volume.snapshot('before');
    volume.writeText(1, 'AFTER');
    expect(Object.keys(snap)).toEqual(['label', 'ciphertext']);
    expect(snap.ciphertext.length).toBe(SECTOR_COUNT);
    expect(toHex(snap.ciphertext[1])).not.toBe(toHex(volume.ciphertextOf(1)));
  });
});
