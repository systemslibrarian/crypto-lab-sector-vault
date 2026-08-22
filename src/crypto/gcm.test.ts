import { describe, expect, it } from 'vitest';
import {
  buildAad,
  GCM_NONCE_BYTES,
  GCM_TAG_BYTES,
  gcmOverheadBytes,
  importGcmKey,
  openSector,
  sealSector,
  VERSION_BYTES,
} from './gcm.js';
import { fromHex, toHex } from './bytes.js';

/**
 * NIST SP 800-38D / "The Galois-Counter Mode of Operation" test cases, run
 * against the browser's own AES-GCM. The comparison panel's BAD_TAG results are
 * only worth something if the AEAD underneath is really AES-GCM, so pin it.
 */
const GCM_KATS = [
  {
    name: 'test case 2 (AES-128, no AAD)',
    key: '00000000000000000000000000000000',
    nonce: '000000000000000000000000',
    aad: '',
    pt: '00000000000000000000000000000000',
    ct: '0388dace60b6a392f328c2b971b2fe78',
    tag: 'ab6e47d42cec13bdf53a67b21257bddf',
  },
  {
    name: 'test case 3 (AES-128, 60-byte plaintext)',
    key: 'feffe9928665731c6d6a8f9467308308',
    nonce: 'cafebabefacedbaddecaf888',
    aad: '',
    pt: 'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255',
    ct: '42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985',
    tag: '4d5c2af327cd64a62cf35abd2ba6fab4',
  },
  {
    name: 'test case 4 (AES-128, with associated data)',
    key: 'feffe9928665731c6d6a8f9467308308',
    nonce: 'cafebabefacedbaddecaf888',
    aad: 'feedfacedeadbeeffeedfacedeadbeefabaddad2',
    pt: 'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39',
    ct: '42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091',
    tag: '5bc94fbc3221a5db94fae95ae7121a47',
  },
  {
    name: 'test case 14 (AES-256, zero key)',
    key: '0000000000000000000000000000000000000000000000000000000000000000',
    nonce: '000000000000000000000000',
    aad: '',
    pt: '00000000000000000000000000000000',
    ct: 'cea7403d4d606b6e074ec5d3baf39d18',
    tag: 'd0d1c8a799996bf0265b98b5d48ab919',
  },
];

describe('AES-GCM known-answer tests (NIST SP 800-38D)', () => {
  for (const v of GCM_KATS) {
    it(v.name, async () => {
      const key = await crypto.subtle.importKey('raw', fromHex(v.key), 'AES-GCM', false, ['encrypt']);
      const sealed = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: fromHex(v.nonce), additionalData: fromHex(v.aad) },
        key,
        fromHex(v.pt),
      );
      expect(toHex(new Uint8Array(sealed))).toBe(v.ct + v.tag);
    });
  }
});

describe('sector records', () => {
  const plaintext = new Uint8Array(512).fill(0x41);

  it('binds the sector index, so a relocated record fails its tag', async () => {
    const key = await importGcmKey(crypto.getRandomValues(new Uint8Array(16)));
    const record = await sealSector(key, 'sector-aad', 3, 1, plaintext);
    const atHome = await openSector(key, 'sector-aad', 3, record);
    expect(atHome.ok).toBe(true);
    const moved = await openSector(key, 'sector-aad', 4, record);
    expect(moved.ok).toBe(false);
    if (!moved.ok) expect(moved.code).toBe('BAD_TAG');
  });

  it('fails the tag on any single flipped ciphertext bit', async () => {
    const key = await importGcmKey(crypto.getRandomValues(new Uint8Array(16)));
    const record = await sealSector(key, 'sector-aad', 3, 1, plaintext);
    for (const offset of [0, 7, 300, record.sealed.length - 1]) {
      const tampered = { ...record, sealed: Uint8Array.from(record.sealed) };
      tampered.sealed[offset] ^= 0x01;
      const opened = await openSector(key, 'sector-aad', 3, tampered);
      expect(opened.ok).toBe(false);
    }
  });

  it('stage two authenticates a replayed old record: an AEAD gives no freshness', async () => {
    const key = await importGcmKey(crypto.getRandomValues(new Uint8Array(16)));
    const old = await sealSector(key, 'sector-aad', 3, 1, plaintext);
    await sealSector(key, 'sector-aad', 3, 2, new Uint8Array(512).fill(0x42));
    const replayed = await openSector(key, 'sector-aad', 3, old);
    expect(replayed.ok).toBe(true);
  });

  it('stage three binds the version into the AAD, so the version cannot be edited', async () => {
    const key = await importGcmKey(crypto.getRandomValues(new Uint8Array(16)));
    const record = await sealSector(key, 'sector-and-version-aad', 3, 1, plaintext);
    const relabelled = { ...record, version: 2 };
    const opened = await openSector(key, 'sector-and-version-aad', 3, relabelled);
    expect(opened.ok).toBe(false);
    // ...but the untouched record still opens, carrying its true version. That
    // is exactly why the freshness decision needs a store outside the record.
    const honest = await openSector(key, 'sector-and-version-aad', 3, record);
    expect(honest.ok && honest.version).toBe(1);
  });

  it('draws a fresh nonce for every write', async () => {
    const key = await importGcmKey(crypto.getRandomValues(new Uint8Array(16)));
    const nonces = new Set<string>();
    for (let i = 0; i < 200; i++) {
      nonces.add(toHex((await sealSector(key, 'sector-aad', 3, i + 1, plaintext)).nonce));
    }
    expect(nonces.size).toBe(200);
  });

  it('measures the data expansion each stage costs', async () => {
    const key = await importGcmKey(crypto.getRandomValues(new Uint8Array(16)));
    const stageTwo = await sealSector(key, 'sector-aad', 3, 1, plaintext);
    // Measured, not assumed: sealed = ciphertext + tag, and the nonce is stored
    // beside it. The version adds eight more bytes at stage three.
    const measured = stageTwo.sealed.length - plaintext.length + stageTwo.nonce.length;
    expect(measured).toBe(GCM_TAG_BYTES + GCM_NONCE_BYTES);
    expect(gcmOverheadBytes('sector-aad')).toBe(measured);
    expect(gcmOverheadBytes('sector-and-version-aad')).toBe(measured + VERSION_BYTES);
  });

  it('builds distinct AAD for every sector and version', () => {
    const seen = new Set<string>();
    for (let sector = 0; sector < 16; sector++) {
      seen.add(toHex(buildAad('sector-aad', sector, 1)));
      for (let version = 1; version <= 8; version++) {
        seen.add(toHex(buildAad('sector-and-version-aad', sector, version)));
      }
    }
    expect(seen.size).toBe(16 + 16 * 8);
  });

  it('refuses a key that is not 128 or 256 bits', async () => {
    await expect(importGcmKey(new Uint8Array(24))).rejects.toThrow(/16 or 32 bytes/);
  });
});
