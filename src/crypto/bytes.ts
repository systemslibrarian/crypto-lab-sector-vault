/** Byte helpers shared by the crypto core and the UI. No crypto lives here. */

export function toHex(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

export function fromHex(hex: string): Uint8Array<ArrayBuffer> {
  const clean = hex.replace(/\s+/g, '');
  if (clean.length % 2 !== 0) throw new Error(`hex string has odd length: ${clean.length}`);
  if (clean.length && !/^[0-9a-fA-F]+$/.test(clean)) throw new Error('hex string has non-hex characters');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function utf8ToBytes(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export function xorBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  if (a.length !== b.length) throw new Error(`xor length mismatch: ${a.length} vs ${b.length}`);
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
  return out;
}

/** Count the bits that differ between two equal-length buffers. */
export function hammingDistance(a: Uint8Array, b: Uint8Array): number {
  if (a.length !== b.length) throw new Error(`length mismatch: ${a.length} vs ${b.length}`);
  let bits = 0;
  for (let i = 0; i < a.length; i++) {
    let v = a[i] ^ b[i];
    while (v) {
      bits += v & 1;
      v >>>= 1;
    }
  }
  return bits;
}

/**
 * The data unit sequence number as XTS encodes it: a 128-bit LITTLE-endian
 * integer. IEEE 1619's own vectors are the check — sequence number
 * 0x3333333333 becomes `33 33 33 33 33 00 ... 00`, not `00 ... 33 33 33 33 33`.
 */
export function sequenceNumberToBlock(sequenceNumber: bigint): Uint8Array {
  if (sequenceNumber < 0n) throw new Error('data unit sequence number must be non-negative');
  if (sequenceNumber >= 1n << 128n) throw new Error('data unit sequence number exceeds 128 bits');
  const out = new Uint8Array(16);
  let n = sequenceNumber;
  for (let i = 0; i < 16; i++) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}
