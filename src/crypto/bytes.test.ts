import { describe, expect, it } from 'vitest';
import {
  equalBytes,
  fromHex,
  hammingDistance,
  sequenceNumberToBlock,
  toHex,
  utf8ToBytes,
  xorBytes,
} from './bytes.js';

describe('hex', () => {
  it('round-trips arbitrary bytes', () => {
    const bytes = new Uint8Array(256);
    for (let i = 0; i < 256; i++) bytes[i] = i;
    expect(fromHex(toHex(bytes))).toEqual(bytes);
  });

  it('rejects odd-length and non-hex input', () => {
    expect(() => fromHex('abc')).toThrow(/odd length/);
    expect(() => fromHex('zz')).toThrow(/non-hex/);
  });

  it('tolerates whitespace, which is how the spec prints vectors', () => {
    expect(toHex(fromHex('91 7c f6 9e'))).toBe('917cf69e');
  });
});

describe('sequenceNumberToBlock', () => {
  it('encodes little-endian, which is the byte order IEEE 1619 vector 15 prints', () => {
    // The spec lists that vector's data unit sequence number as the byte
    // string 9a 78 56 34 12, which is the integer 0x123456789a laid out
    // low byte first. Getting this backwards silently produces a different
    // tweak and a ciphertext that matches nothing.
    expect(toHex(sequenceNumberToBlock(0x123456789an))).toBe('9a78563412' + '00'.repeat(11));
  });

  it('encodes zero and the maximum', () => {
    expect(toHex(sequenceNumberToBlock(0n))).toBe('00'.repeat(16));
    expect(toHex(sequenceNumberToBlock((1n << 128n) - 1n))).toBe('ff'.repeat(16));
  });

  it('refuses values outside 128 bits', () => {
    expect(() => sequenceNumberToBlock(-1n)).toThrow(/non-negative/);
    expect(() => sequenceNumberToBlock(1n << 128n)).toThrow(/128 bits/);
  });
});

describe('byte utilities', () => {
  it('compares by content, not identity', () => {
    expect(equalBytes(fromHex('0102'), fromHex('0102'))).toBe(true);
    expect(equalBytes(fromHex('0102'), fromHex('0103'))).toBe(false);
    expect(equalBytes(fromHex('0102'), fromHex('010203'))).toBe(false);
  });

  it('xors and refuses mismatched lengths', () => {
    expect(toHex(xorBytes(fromHex('ff00'), fromHex('0ff0')))).toBe('f0f0');
    expect(() => xorBytes(fromHex('ff'), fromHex('ffff'))).toThrow(/length mismatch/);
  });

  it('counts differing bits', () => {
    expect(hammingDistance(fromHex('00'), fromHex('ff'))).toBe(8);
    expect(hammingDistance(fromHex('0000'), fromHex('0001'))).toBe(1);
    expect(hammingDistance(fromHex('abcd'), fromHex('abcd'))).toBe(0);
  });

  it('encodes text as UTF-8', () => {
    expect(toHex(utf8ToBytes('AB'))).toBe('4142');
  });
});
