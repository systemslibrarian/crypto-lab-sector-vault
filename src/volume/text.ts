import { SECTOR_BYTES } from './types.js';

/** Pad a line of text out to one sector with spaces, the way a record would be stored. */
export function textToSector(text: string): Uint8Array {
  const encoded = new TextEncoder().encode(text);
  if (encoded.length > SECTOR_BYTES) {
    throw new RangeError(`text is ${encoded.length} bytes; a sector holds ${SECTOR_BYTES}`);
  }
  const sector = new Uint8Array(SECTOR_BYTES).fill(0x20);
  sector.set(encoded, 0);
  return sector;
}

/**
 * Render sector bytes for reading. Printable ASCII passes through; everything
 * else becomes a middle dot, so decrypted noise LOOKS like noise instead of
 * being silently swallowed by the browser's replacement-character handling.
 */
export function sectorToDisplay(bytes: Uint8Array, limit = SECTOR_BYTES): string {
  let out = '';
  for (let i = 0; i < Math.min(bytes.length, limit); i++) {
    const b = bytes[i];
    out += b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : '·';
  }
  return out;
}

/** The share of bytes in a buffer that would render as printable ASCII text. */
export function printableFraction(bytes: Uint8Array): number {
  if (bytes.length === 0) return 0;
  let printable = 0;
  for (const b of bytes) if (b >= 0x20 && b <= 0x7e) printable++;
  return printable / bytes.length;
}
