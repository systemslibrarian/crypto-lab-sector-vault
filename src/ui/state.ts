import { SectorVolume, type Snapshot } from '../volume/volume.js';
import { SECTOR_COUNT } from '../volume/types.js';

/**
 * The volume ships with content already on it, because an empty disk teaches
 * nothing: the acts are about the difference between what was written and what
 * comes back, and that difference needs a "what was written".
 */
export const INITIAL_SECTORS: string[] = [
  'VOLUME LABEL: SECTOR VAULT / XTS-AES-128 / 16 SECTORS x 512 BYTES',
  'PAYROLL 2026-Q3  ROW 001  NAME: A. OKONKWO   NET: 004120.00',
  'PAYROLL 2026-Q3  ROW 002  NAME: B. LINDQVIST NET: 003880.00',
  'PAYROLL 2026-Q3  ROW 003  NAME: C. NAKAMURA  NET: 005240.00',
  'ACCESS LIST  ADMIN: root, ops   READONLY: audit   DENY: guest',
  'ACCESS LIST  MFA REQUIRED: yes  SESSION TTL: 900s  LOCKOUT: 5',
  'CONFIG  backup.enabled=true  backup.target=vault-b  retain=30d',
  'CONFIG  integrity.checks=none  <-- this line is the whole lab',
  'LEDGER 2026-08-01  OPENING BALANCE          000100.00 EUR',
  'LEDGER 2026-08-02  TRANSFER IN              000000.00 EUR',
  'LEDGER 2026-08-03  TRANSFER OUT             000000.00 EUR',
  'AUDIT LOG  0900 login root ok   0902 read sector 4   0903 idle',
  'AUDIT LOG  1100 login audit ok  1101 read sector 8   1102 idle',
  'FREE SPACE  ................................................',
  'FREE SPACE  ................................................',
  'FREE SPACE  ................................................',
];

/** The second write to sector 9. Rolling back to version 1 unmakes it. */
export const ROLLBACK_TARGET_UPDATE = 'LEDGER 2026-08-02  TRANSFER IN              250000.00 EUR';

export interface AppState {
  volume: SectorVolume;
  selectedSector: number;
  selectedBlock: number;
  /** The block index the tweak ladder is currently sitting on. */
  ladderStep: number;
  snapshots: Snapshot[];
  /** Newest first. Every edit an adversary made, in order. */
  log: string[];
}

export function createState(): AppState {
  // Session-only keys, in memory, never persisted. Two independent 128-bit
  // keys: K1 for the data, K2 for the tweak.
  const volume = new SectorVolume({
    k1: crypto.getRandomValues(new Uint8Array(16)),
    k2: crypto.getRandomValues(new Uint8Array(16)),
  });
  for (let sector = 0; sector < SECTOR_COUNT; sector++) {
    volume.writeText(sector, INITIAL_SECTORS[sector]);
  }
  // Sector 9 is written a second time, so the volume arrives with a sector that
  // has a history. Act 3's rollback needs an earlier version to restore, and a
  // disk that has only ever been written once is not the disk anybody has.
  volume.writeText(9, ROLLBACK_TARGET_UPDATE);
  return {
    volume,
    selectedSector: 9,
    selectedBlock: 0,
    ladderStep: 0,
    snapshots: [volume.snapshot('image 1 — the volume as found')],
    log: [],
  };
}

export interface LabContext {
  state: AppState;
  /** Re-render every data-driven surface. Controls keep their identity. */
  refresh(): void;
  /** Record an adversary action and re-render. */
  record(message: string): void;
  /** Throw the volume away and start again with fresh keys. */
  reset(): void;
}
