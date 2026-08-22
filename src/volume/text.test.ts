import { describe, expect, it } from 'vitest';
import { printableFraction, sectorToDisplay, textToSector } from './text.js';
import { SECTOR_BYTES } from './types.js';

describe('sector text', () => {
  it('pads a written line out to a full sector with spaces', () => {
    const sector = textToSector('HELLO');
    expect(sector.length).toBe(SECTOR_BYTES);
    expect(sectorToDisplay(sector, 8)).toBe('HELLO   ');
  });

  it('refuses more text than a sector holds', () => {
    expect(() => textToSector('x'.repeat(SECTOR_BYTES + 1))).toThrow(/sector holds/);
  });

  it('renders non-printable bytes visibly rather than swallowing them', () => {
    expect(sectorToDisplay(new Uint8Array([0x41, 0x00, 0xff, 0x7f, 0x42]))).toBe('A···B');
  });

  it('measures how much of a buffer would read as text', () => {
    expect(printableFraction(textToSector('HELLO'))).toBe(1);
    expect(printableFraction(new Uint8Array(16))).toBe(0);
    expect(printableFraction(new Uint8Array(0))).toBe(0);
  });
});
