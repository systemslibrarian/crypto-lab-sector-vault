/**
 * AES-GCM (NIST SP 800-38D) via WebCrypto, used only as the CONTRAST in act 5.
 *
 * This is a real AEAD doing real authentication — no simulation — so the tag
 * failures the comparison panel reports are failures the browser's own
 * cryptography produced.
 *
 * Two design choices here are load-bearing for the lab's honesty:
 *
 * 1. THE NONCE IS FRESH AND STORED. A tempting shortcut for a disk is to use
 *    the sector number as the GCM nonce, which needs no storage at all. That
 *    reuses a nonce under one key on every single rewrite of that sector, which
 *    is catastrophic for GCM — it leaks the XOR of the plaintexts and, worse,
 *    the authentication subkey, so forgery becomes possible. So every seal
 *    draws 96 fresh random bits and stores them beside the ciphertext. That
 *    storage, plus the tag, IS the data expansion act 5 is about.
 *
 * 2. THE SECTOR IDENTITY GOES IN THE AAD, NOT THE NONCE. Binding the sector
 *    index (and, at stage three, the version) as associated data is what makes
 *    a relocated or stale record fail its tag rather than merely decrypt
 *    differently.
 */

export const GCM_NONCE_BYTES = 12;
export const GCM_TAG_BYTES = 16;
export const VERSION_BYTES = 8;

/** How much room a construction needs beyond the sector's own bytes. */
export type GcmStage = 'sector-aad' | 'sector-and-version-aad';

export interface SectorRecord {
  /** 96 fresh random bits, drawn per write and stored in the clear. */
  nonce: Uint8Array;
  /** Ciphertext with the 16-byte GCM tag appended, exactly as WebCrypto emits it. */
  sealed: Uint8Array;
  /**
   * Monotonic write counter. Stored in the clear AND bound into the AAD at
   * stage three, so a record cannot be replayed under a different version
   * number — but nothing here stops it being replayed under its OWN version
   * number. That is what the trusted store outside this module is for.
   */
  version: number;
}

export function gcmOverheadBytes(stage: GcmStage): number {
  return GCM_NONCE_BYTES + GCM_TAG_BYTES + (stage === 'sector-and-version-aad' ? VERSION_BYTES : 0);
}

/**
 * The associated data. Stage two binds the sector identity; stage three also
 * binds the version. Both are fixed-width big-endian so no two (sector,
 * version) pairs can produce the same AAD by re-splitting the bytes.
 */
export function buildAad(stage: GcmStage, sectorIndex: number, version: number): Uint8Array {
  const width = stage === 'sector-and-version-aad' ? 16 : 8;
  const aad = new Uint8Array(width);
  const view = new DataView(aad.buffer);
  view.setBigUint64(0, BigInt(sectorIndex));
  if (stage === 'sector-and-version-aad') view.setBigUint64(8, BigInt(version));
  return aad;
}

export async function importGcmKey(raw: Uint8Array): Promise<CryptoKey> {
  if (raw.length !== 16 && raw.length !== 32) {
    throw new Error(`AES-GCM key must be 16 or 32 bytes, got ${raw.length}`);
  }
  return crypto.subtle.importKey('raw', raw as BufferSource, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

export async function sealSector(
  key: CryptoKey,
  stage: GcmStage,
  sectorIndex: number,
  version: number,
  plaintext: Uint8Array,
  nonce: Uint8Array = crypto.getRandomValues(new Uint8Array(GCM_NONCE_BYTES)),
): Promise<SectorRecord> {
  const sealed = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce as BufferSource, additionalData: buildAad(stage, sectorIndex, version) as BufferSource },
    key,
    plaintext as BufferSource,
  );
  return { nonce: Uint8Array.from(nonce), sealed: new Uint8Array(sealed), version };
}

export type GcmOpenResult =
  | { ok: true; plaintext: Uint8Array; version: number }
  | { ok: false; code: 'BAD_TAG'; detail: string };

/**
 * Open a record AS FOUND AT `sectorIndex`. The AAD is rebuilt from where the
 * record actually sits and from the version the record itself carries, so a
 * record moved to another sector, or edited in any way, cannot verify.
 */
export async function openSector(
  key: CryptoKey,
  stage: GcmStage,
  sectorIndex: number,
  record: SectorRecord,
): Promise<GcmOpenResult> {
  try {
    const plaintext = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: record.nonce as BufferSource,
        additionalData: buildAad(stage, sectorIndex, record.version) as BufferSource,
      },
      key,
      record.sealed as BufferSource,
    );
    return { ok: true, plaintext: new Uint8Array(plaintext), version: record.version };
  } catch {
    // WebCrypto reports every GCM authentication failure as one opaque
    // OperationError and says nothing about which byte moved. That is correct
    // AEAD behaviour: the tag either verifies or it does not.
    return {
      ok: false,
      code: 'BAD_TAG',
      detail: `GCM tag did not verify for the record found at sector ${sectorIndex}`,
    };
  }
}
