import { describe, expect, it } from 'vitest';
import { SectorVolume } from './volume.js';
import { flipCiphertextBit, relocateBlock, relocateSector, rollbackSector } from './attacks.js';
import { BLOCK_BYTES, BLOCKS_PER_SECTOR, SECTOR_BYTES } from './types.js';
import { printableFraction } from './text.js';
import { equalBytes, toHex } from '../crypto/bytes.js';

function loadedVolume(): SectorVolume {
  const volume = new SectorVolume({
    k1: crypto.getRandomValues(new Uint8Array(16)),
    k2: crypto.getRandomValues(new Uint8Array(16)),
  });
  for (let s = 0; s < 16; s++) volume.writeText(s, `SECTOR ${String(s).padStart(2, '0')} :: ROSTER ENTRY`);
  return volume;
}

describe('bit flip', () => {
  it('damages exactly one block and leaves the other thirty-one perfect', () => {
    const volume = loadedVolume();
    flipCiphertextBit(volume, 5, 19, 3);
    const read = volume.read(5);
    expect(read.changedBlocks).toEqual([1]);
    expect(read.status).toBe('CORRUPTED_UNDETECTED');
    expect(read.failureCode).toBeNull();
  });

  it('leaves every other sector untouched', () => {
    const volume = loadedVolume();
    flipCiphertextBit(volume, 5, 19, 3);
    for (const read of volume.readAll()) {
      if (read.sector !== 5) expect(read.status).toBe('INTACT');
    }
  });

  it('turns the hit block into something that no longer reads as text', () => {
    const volume = loadedVolume();
    flipCiphertextBit(volume, 5, 4, 0);
    const read = volume.read(5);
    const damaged = read.plaintext.subarray(0, BLOCK_BYTES);
    // The written sectors are pure ASCII; a block of AES output essentially
    // never is. This is what "decrypts to garbage" means, measured.
    expect(printableFraction(damaged)).toBeLessThan(0.9);
    expect(printableFraction(read.expected.subarray(0, BLOCK_BYTES))).toBe(1);
  });

  it('changes exactly one ciphertext byte', () => {
    const volume = loadedVolume();
    const result = flipCiphertextBit(volume, 2, 100, 7);
    expect(result.bytesChanged).toBe(1);
    expect(result.touchedSectors).toEqual([2]);
  });

  it('rejects offsets and bit indices outside a sector', () => {
    const volume = loadedVolume();
    expect(() => flipCiphertextBit(volume, 0, SECTOR_BYTES, 0)).toThrow(RangeError);
    expect(() => flipCiphertextBit(volume, 0, -1, 0)).toThrow(RangeError);
    expect(() => flipCiphertextBit(volume, 0, 0, 8)).toThrow(RangeError);
  });
});

describe('relocation', () => {
  it('a block copied to another offset decrypts to different, wrong plaintext with no error', () => {
    const volume = loadedVolume();
    relocateBlock(volume, { sector: 3, block: 0 }, { sector: 3, block: 7 });
    const read = volume.read(3);
    expect(read.changedBlocks).toEqual([7]);
    expect(read.status).toBe('CORRUPTED_UNDETECTED');
    expect(read.failureCode).toBeNull();
    // Not a copy of block 0's plaintext: the tweak for block 7 is a different
    // field element, so the same ciphertext yields unrelated bytes.
    expect(
      equalBytes(read.plaintext.subarray(7 * BLOCK_BYTES, 8 * BLOCK_BYTES), read.expected.subarray(0, BLOCK_BYTES)),
    ).toBe(false);
  });

  it('a whole sector copied to another sector number decrypts to noise, silently', () => {
    const volume = loadedVolume();
    relocateSector(volume, 6, 7);
    const read = volume.read(7);
    expect(read.status).toBe('CORRUPTED_UNDETECTED');
    expect(read.changedBlocks.length).toBe(BLOCKS_PER_SECTOR);
    expect(read.failureCode).toBeNull();
    expect(printableFraction(read.plaintext)).toBeLessThan(0.5);
  });

  it('copying a block back over its own address is a no-op', () => {
    const volume = loadedVolume();
    const result = relocateBlock(volume, { sector: 4, block: 9 }, { sector: 4, block: 9 });
    expect(result.bytesChanged).toBe(0);
    expect(volume.read(4).status).toBe('INTACT');
  });

  it('rejects addresses outside the volume', () => {
    const volume = loadedVolume();
    expect(() => relocateBlock(volume, { sector: 0, block: BLOCKS_PER_SECTOR }, { sector: 0, block: 0 })).toThrow(RangeError);
    expect(() => relocateSector(volume, 0, 16)).toThrow(RangeError);
  });
});

describe('rollback', () => {
  it('decrypts perfectly and correctly — it is stale, not corrupted', () => {
    const volume = loadedVolume();
    volume.writeText(8, 'BALANCE 000100');
    volume.writeText(8, 'BALANCE 900100');
    rollbackSector(volume, 8, 1);
    const read = volume.read(8);
    expect(read.status).toBe('SUCCEEDS_CLEANLY_STALE');
    expect(read.staleVersion).toBe(1);
    expect(read.failureCode).toBeNull();
    // Every byte is a byte the key holder wrote to this exact sector.
    expect(printableFraction(read.plaintext)).toBe(1);
  });

  it('is distinguished from corruption by evidence, not by labelling', () => {
    const volume = loadedVolume();
    volume.writeText(8, 'BALANCE 000100');
    volume.writeText(8, 'BALANCE 900100');
    const rolled = Uint8Array.from(volume.history(8)[0].ciphertext);
    rolled[0] ^= 0x01; // an old image with one bit changed is corruption again
    volume.setCiphertext(8, rolled);
    expect(volume.read(8).status).toBe('CORRUPTED_UNDETECTED');
  });

  it('restoring the current version changes nothing', () => {
    const volume = loadedVolume();
    volume.writeText(8, 'ONE');
    volume.writeText(8, 'TWO');
    const result = rollbackSector(volume, 8, 3);
    expect(result.bytesChanged).toBe(0);
    expect(volume.read(8).status).toBe('INTACT');
  });

  it('refuses a version the sector never had', () => {
    const volume = loadedVolume();
    expect(() => rollbackSector(volume, 8, 99)).toThrow(/no version 99/);
  });
});

describe('no attack in this module ever touches a key', () => {
  it('reproduces every edit with ciphertext alone', () => {
    // The adversary model, checked structurally: replay each attack against a
    // bare copy of the platter bytes and confirm the results are identical. If
    // any of these functions secretly needed K1 or K2, this could not agree.
    const volume = loadedVolume();
    const before = Array.from({ length: 16 }, (_, s) => Uint8Array.from(volume.ciphertextOf(s)));
    flipCiphertextBit(volume, 1, 33, 2);
    relocateBlock(volume, { sector: 2, block: 3 }, { sector: 2, block: 4 });
    relocateSector(volume, 9, 10);

    const replay = before.map((sector) => Uint8Array.from(sector));
    replay[1][33] ^= 1 << 2;
    replay[2].set(replay[2].subarray(3 * BLOCK_BYTES, 4 * BLOCK_BYTES), 4 * BLOCK_BYTES);
    replay[10] = Uint8Array.from(replay[9]);

    for (let s = 0; s < 16; s++) expect(toHex(volume.ciphertextOf(s))).toBe(toHex(replay[s]));
  });
});
