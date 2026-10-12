import { createCipheriv, createDecipheriv } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { createEme2Cipher, type Eme2Keys } from './eme2.js';
import { fromHex, toHex } from './bytes.js';

/** Independent Figure 1 transcription: BigInt field arithmetic and OpenSSL
 * AES, not noble, gf128.ts or the production transform's loops. All operations
 * allocate. Historical construction only; this is not official validation. */
function reference(keys: Eme2Keys, ad: Uint8Array, data: Uint8Array, decrypt = false): Uint8Array {
  const integer = (b: Uint8Array) => BigInt('0x' + Buffer.from(b).reverse().toString('hex'));
  const block = (n: bigint) => Uint8Array.from(Buffer.from(n.toString(16).padStart(32, '0'), 'hex').reverse());
  const alpha = (n: bigint) => ((n << 1n) & ((1n << 128n) - 1n)) ^ (n >> 127n ? 0x87n : 0n);
  const power = (n: bigint, p: number) => { for (let i = 0; i < p; i++) n = alpha(n); return n; };
  const aes = (n: bigint, inverse = false): bigint => {
    const factory = inverse ? createDecipheriv : createCipheriv;
    const c = factory(`aes-${keys.aes.length * 8}-ecb`, keys.aes, null);
    c.setAutoPadding(false);
    return integer(Buffer.concat([c.update(block(n)), c.final()]));
  };
  const pad = (b: Uint8Array) => integer(Uint8Array.from([...b, 0x80, ...new Uint8Array(15 - b.length)]));
  const chunks = (b: Uint8Array) => Array.from({ length: Math.ceil(b.length / 16) }, (_, i) => b.slice(i * 16, i * 16 + 16));
  const r = integer(keys.adMask);
  const t = ad.length === 0 ? aes(r) : chunks(ad).reduce((sum, b, i) => {
    const mask = power(r, i + 1 + (b.length < 16 ? 1 : 0));
    return sum ^ aes(mask ^ (b.length === 16 ? integer(b) : pad(b))) ^ mask;
  }, 0n);
  const parts = chunks(data);
  const full = parts.filter(b => b.length === 16).length;
  const l = integer(keys.ecbMask);
  const first = parts.map((b, i) => b.length === 16 ? aes(integer(b) ^ power(l, i), decrypt) : pad(b));
  const sum = first.reduce((a, b) => a ^ b, t);
  const partial = full < parts.length;
  const mm = aes(sum, decrypt);
  const mixedSum = partial ? aes(mm, decrypt) : mm;
  const masks = [sum ^ mixedSum];
  const second = [0n];
  for (let i = 1; i < full; i++) {
    const k = i % 128;
    if (k === 0) {
      const before = first[i] ^ masks[0];
      const after = aes(before, decrypt);
      masks.push(before ^ after);
      second[i] = after ^ masks[0];
    } else second[i] = first[i] ^ power(masks[Math.floor(i / 128)], k);
  }
  let tail: Uint8Array = new Uint8Array();
  if (partial) {
    tail = Uint8Array.from(parts[full], (b, i) => b ^ block(mm)[i]);
    second[full] = pad(tail);
  }
  second[0] = second.slice(1).reduce((a, b) => a ^ b, mixedSum ^ t);
  const result = new Uint8Array(data.length);
  for (let i = 0; i < full; i++) result.set(block(aes(second[i], decrypt) ^ power(l, i)), i * 16);
  result.set(tail, full * 16);
  return result;
}

const pattern = (length: number, seed = 0) => Uint8Array.from({ length }, (_, i) => (i * 73 + seed * 19) & 255);
const keys = (size: number): Eme2Keys => ({ aes: pattern(size, 3), ecbMask: pattern(16, 7), adMask: pattern(16, 11) });

describe('historical EME2 construction — independent evidence, no 2025 conformance claim', () => {
  it('matches all six published Rust 0.3.0 regression vectors in both directions', () => {
    const fixture = JSON.parse(readFileSync(new URL('../../tests/fixtures/eme2-rust-0.3.0.json', import.meta.url), 'utf8'));
    expect(fixture.provenance.kind).toContain('NOT official IEEE');
    expect(fixture.vectors).toHaveLength(6);
    for (const v of fixture.vectors) {
      const key = fromHex(v.key);
      // The Rust crate order differs from the archived D9 serialization.
      const k = { aes: key.slice(0, 32), ecbMask: key.slice(32, 48), adMask: key.slice(48) };
      const c = createEme2Cipher(k);
      const ad = fromHex(v.ad), pt = fromHex(v.plaintext), ct = fromHex(v.ciphertext);
      expect(toHex(c.encrypt(ad, pt))).toBe(v.ciphertext);
      expect(c.decrypt(ad, ct)).toEqual(pt);
      expect(reference(k, ad, pt)).toEqual(ct);
      expect(reference(k, ad, ct, true)).toEqual(pt);
    }
  });

  for (const size of [16, 32]) {
    for (const length of [16, 17, 31, 32, 33, 511, 512, 513, 2032, 2047, 2048, 2049, 2064, 2065, 4097, 8192]) {
      it(`cross-checks AES-${size * 8}, ${length} bytes, across empty/full/partial AD`, () => {
        const k = keys(size), cipher = createEme2Cipher(k), pt = pattern(length, length % 17);
        for (const n of [0, 1, 15, 16, 17, 31, 32, 33, 4096]) {
          const ad = pattern(n, 2);
          const expected = reference(k, ad, pt);
          const actual = cipher.encrypt(ad, pt);
          expect(actual.length).toBe(length);
          expect(actual).toEqual(expected);
          expect(cipher.decrypt(ad, expected)).toEqual(pt);
          expect(reference(k, ad, actual, true)).toEqual(pt);
        }
      });
    }
  }

  it('is deterministic, leaves inputs untouched and snapshots key material', () => {
    const k = keys(16), original = { aes: k.aes.slice(), ecbMask: k.ecbMask.slice(), adMask: k.adMask.slice() };
    const cipher = createEme2Cipher(k), ad = pattern(17), pt = pattern(513), adBefore = ad.slice(), ptBefore = pt.slice();
    const a = cipher.encrypt(ad, pt);
    expect(cipher.encrypt(ad, pt)).toEqual(a);
    expect(cipher.decrypt(ad, a)).toEqual(pt);
    expect(ad).toEqual(adBefore); expect(pt).toEqual(ptBefore); expect(k).toEqual(original);
    k.aes.fill(0); k.ecbMask.fill(0); k.adMask.fill(0);
    expect(cipher.encrypt(ad, pt)).toEqual(a);
  });

  it('changes the whole fixed 512-byte sample, without authenticating ciphertext or AD', () => {
    const c = createEme2Cipher(keys(16)), ad = pattern(16), pt = pattern(512), ct = c.encrypt(ad, pt);
    for (const offset of [0, 20, 511]) {
      const edited = ct.slice(); edited[offset] ^= 1;
      const got = c.decrypt(ad, edited);
      for (let i = 0; i < 512; i += 16) expect(got.slice(i, i + 16)).not.toEqual(pt.slice(i, i + 16));
    }
    const wrongAd = ad.slice(); wrongAd[0] ^= 1;
    expect(c.decrypt(wrongAd, ct)).not.toEqual(pt);
    expect(c.decrypt(ad, ct)).toEqual(pt); // old ciphertext remains valid forever under the same AD
    expect(c.hashAssociatedData(new Uint8Array())).not.toEqual(c.hashAssociatedData(new Uint8Array([0])));
    expect(c.hashAssociatedData(pattern(15))).not.toEqual(c.hashAssociatedData(pattern(16)));
  });

  it('rejects invalid keys and exhibit resource bounds, not attacker-edited valid-length bytes', () => {
    const k = keys(16);
    for (const n of [0, 15, 24, 33]) expect(() => createEme2Cipher({ ...k, aes: pattern(n) })).toThrow();
    expect(() => createEme2Cipher({ ...k, ecbMask: pattern(15) })).toThrow();
    expect(() => createEme2Cipher({ ...k, adMask: pattern(17) })).toThrow();
    const c = createEme2Cipher(k);
    for (const n of [0, 15, 8193]) {
      expect(() => c.encrypt(new Uint8Array(), pattern(n))).toThrow();
      expect(() => c.decrypt(new Uint8Array(), pattern(n))).toThrow();
    }
    expect(() => c.hashAssociatedData(pattern(4097))).toThrow();
    expect(() => c.decrypt(pattern(17), pattern(513))).not.toThrow();
  });
});
