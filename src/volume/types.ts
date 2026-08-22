/** Geometry and vocabulary shared by the volume, the attacks and the panels. */

/**
 * 512 bytes, because that is the scope SP 800-38E was written for: storage
 * devices whose data unit is exactly the sector, with no room beside it for a
 * nonce or a tag. Changing this number to something convenient would quietly
 * change the argument the lab is making.
 */
export const SECTOR_BYTES = 512;
export const SECTOR_COUNT = 16;
export const BLOCK_BYTES = 16;
export const BLOCKS_PER_SECTOR = SECTOR_BYTES / BLOCK_BYTES;
export const VOLUME_BYTES = SECTOR_BYTES * SECTOR_COUNT;

/**
 * What a read actually got, judged against the lab's own write log.
 *
 * None of these is something XTS reports. XTS returns bytes and nothing else;
 * every status below is the LAB's out-of-band knowledge of what was written,
 * which a real disk driver does not have. That gap is the demo.
 */
export type ReadStatus =
  /** The bytes read are the bytes written. */
  | 'INTACT'
  /**
   * The bytes read were never written to this sector by anyone holding the key.
   * The mode raises nothing, so this is CORRUPTED (UNDETECTED) — corrupted is
   * what happened, undetected is what the construction did about it.
   */
  | 'CORRUPTED_UNDETECTED'
  /**
   * The bytes read are a genuine earlier version of this sector: they decrypt
   * perfectly and are internally consistent, because nothing in XTS binds a
   * version. Not corruption. Not a failure. Just stale data, returned cleanly,
   * with no signal at all.
   */
  | 'SUCCEEDS_CLEANLY_STALE';

export const READ_STATUS_LABEL: Record<ReadStatus, string> = {
  INTACT: 'INTACT',
  CORRUPTED_UNDETECTED: 'CORRUPTED (UNDETECTED)',
  SUCCEEDS_CLEANLY_STALE: 'SUCCEEDS CLEANLY (STALE)',
};

export interface BlockAddress {
  sector: number;
  block: number;
}

export function assertSectorIndex(index: number): void {
  if (!Number.isInteger(index) || index < 0 || index >= SECTOR_COUNT) {
    throw new RangeError(`sector index must be an integer in 0..${SECTOR_COUNT - 1}, got ${index}`);
  }
}

export function assertBlockIndex(index: number): void {
  if (!Number.isInteger(index) || index < 0 || index >= BLOCKS_PER_SECTOR) {
    throw new RangeError(`block index must be an integer in 0..${BLOCKS_PER_SECTOR - 1}, got ${index}`);
  }
}
