/**
 * Act 5 — the three-stage comparison, run for real on every cell.
 *
 * Nothing in this table is written down in advance. Each cell builds a small
 * volume under one construction, performs one attack on the stored bytes, then
 * attempts the read and reports what actually came back. If a claim in the
 * panel is wrong, it is wrong because the cryptography did something else, not
 * because the prose drifted.
 *
 * The three stages exist because the obvious story — "add an AEAD and rollback
 * dies too" — is false. An AEAD authenticates a ciphertext; it does not provide
 * freshness. RFC 5116 section 1.1 says so explicitly: the AEAD interface "does
 * not address" anti-replay. Stage two proves it: a whole old record replayed at
 * its own sector number authenticates perfectly.
 */
import { createXtsCipher, type XtsKeyPair } from '../crypto/xts.js';
import {
  gcmOverheadBytes,
  importGcmKey,
  openSector,
  sealSector,
  type GcmStage,
  type SectorRecord,
} from '../crypto/gcm.js';
import { equalBytes } from '../crypto/bytes.js';
import { SECTOR_BYTES } from './types.js';
import { textToSector } from './text.js';

export const CONSTRUCTIONS = ['xts', 'gcm-sector-aad', 'gcm-sector-version-aad'] as const;
export type ConstructionId = (typeof CONSTRUCTIONS)[number];

export const ATTACKS = ['bit-modification', 'relocation', 'rollback'] as const;
export type AttackId = (typeof ATTACKS)[number];

export type OutcomeCode = 'CORRUPTED_UNDETECTED' | 'SUCCEEDS_CLEANLY' | 'BAD_TAG' | 'STALE_VERSION' | 'NO_EFFECT';

export const CONSTRUCTION_LABEL: Record<ConstructionId, string> = {
  xts: 'XTS-AES',
  'gcm-sector-aad': 'AES-GCM, sector identity as AAD',
  'gcm-sector-version-aad': 'AES-GCM + protected monotonic version',
};

export const ATTACK_LABEL: Record<AttackId, string> = {
  'bit-modification': 'Bit modification',
  relocation: 'Relocation',
  rollback: 'Rollback',
};

export interface ComparisonCell {
  construction: ConstructionId;
  attack: AttackId;
  outcome: OutcomeCode;
  /** The wording the panel prints. Chosen from the outcome, never hand-entered per cell. */
  label: string;
  /** Why that outcome, in one line. */
  detail: string;
  /** Did the CONSTRUCTION ITSELF raise anything? This is the column that matters. */
  raisedByConstruction: boolean;
}

export interface ComparisonReport {
  cells: ComparisonCell[];
  /** Extra stored bytes per 512-byte sector, measured from the real records. */
  overheadBytes: Record<ConstructionId, number>;
  overheadPercent: Record<ConstructionId, number>;
  attackerControlsVersionStore: boolean;
  /** The two versions written to the sector under attack, for the panel's caption. */
  originalText: string;
  updatedText: string;
}

const V1_TEXT = 'ACCT 4417  BALANCE 000100.00  HOLD NONE';
const V2_TEXT = 'ACCT 4417  BALANCE 900100.00  HOLD NONE';
const NEIGHBOUR_TEXT = 'ACCT 9002  BALANCE 000000.00  HOLD FULL';

function outcomeLabel(construction: ConstructionId, attack: AttackId, outcome: OutcomeCode): string {
  switch (outcome) {
    case 'CORRUPTED_UNDETECTED':
      return 'CORRUPTED (UNDETECTED)';
    case 'BAD_TAG':
      return 'BAD_TAG';
    case 'STALE_VERSION':
      return 'STALE_VERSION';
    case 'NO_EFFECT':
      return 'no effect';
    case 'SUCCEEDS_CLEANLY':
      // Both wordings mean the same thing — the read returned wrong data and
      // the construction said nothing — but an AEAD deserves the sharper one,
      // because its tag genuinely verified.
      return construction === 'xts' ? 'succeeds cleanly' : 'still authenticates';
    default:
      return attack;
  }
}

function cell(
  construction: ConstructionId,
  attack: AttackId,
  outcome: OutcomeCode,
  detail: string,
): ComparisonCell {
  return {
    construction,
    attack,
    outcome,
    label: outcomeLabel(construction, attack, outcome),
    detail,
    raisedByConstruction: outcome === 'BAD_TAG' || outcome === 'STALE_VERSION',
  };
}

/** The XTS column. Sector 3 is the target; sector 4 is the neighbour it is confused with. */
function runXtsColumn(key: XtsKeyPair): ComparisonCell[] {
  const cipher = createXtsCipher(key);
  const target = 3n;
  const neighbour = 4n;
  const v1 = textToSector(V1_TEXT);
  const v2 = textToSector(V2_TEXT);
  const ctV1 = cipher.encryptSector(target, v1);
  const ctV2 = cipher.encryptSector(target, v2);
  const ctNeighbour = cipher.encryptSector(neighbour, textToSector(NEIGHBOUR_TEXT));

  const judge = (stored: Uint8Array, attack: AttackId, detail: string): ComparisonCell => {
    const read = cipher.decryptSector(target, stored);
    if (equalBytes(read, v2)) return cell('xts', attack, 'NO_EFFECT', 'the read returned the current version unchanged');
    if (equalBytes(read, v1)) {
      return cell('xts', attack, 'SUCCEEDS_CLEANLY', detail);
    }
    return cell('xts', attack, 'CORRUPTED_UNDETECTED', detail);
  };

  const flipped = Uint8Array.from(ctV2);
  flipped[19] ^= 0x01;

  const relocated = Uint8Array.from(ctNeighbour);

  return [
    judge(
      flipped,
      'bit-modification',
      'one flipped ciphertext bit makes its own 16-byte block decrypt to noise; XTS has no tag to check, so the read simply returns it',
    ),
    judge(
      relocated,
      'relocation',
      'tweak is position-bound: the block decrypts under the tweak of where it now sits, so it yields different, wrong plaintext and no error',
    ),
    judge(
      ctV1,
      'rollback',
      'those exact bytes were written to this exact sector by the key holder, so they decrypt perfectly; nothing in XTS binds a version',
    ),
  ];
}

async function runGcmColumn(
  stage: GcmStage,
  construction: ConstructionId,
  rawKey: Uint8Array,
  attackerControlsVersionStore: boolean,
): Promise<ComparisonCell[]> {
  const key = await importGcmKey(rawKey);
  const target = 3;
  const neighbour = 4;
  const versioned = stage === 'sector-and-version-aad';

  const recordV1 = await sealSector(key, stage, target, 1, textToSector(V1_TEXT));
  const recordV2 = await sealSector(key, stage, target, 2, textToSector(V2_TEXT));
  const recordNeighbour = await sealSector(key, stage, neighbour, 1, textToSector(NEIGHBOUR_TEXT));

  // The trusted store. It has to live somewhere the attacker cannot reach —
  // a TPM, a secure element, a signed Merkle root held off the volume — or
  // stage three has only moved the rollback target one level down.
  const trustedVersion = attackerControlsVersionStore ? 1 : 2;

  const judge = async (stored: SectorRecord, attack: AttackId, cleanDetail: string): Promise<ComparisonCell> => {
    const opened = await openSector(key, stage, target, stored);
    if (!opened.ok) {
      return cell(construction, attack, 'BAD_TAG', 'the GCM tag did not verify, so the read failed closed and returned no plaintext');
    }
    if (versioned && opened.version < trustedVersion) {
      return cell(
        construction,
        attack,
        'STALE_VERSION',
        `the tag verified, but the record carries version ${opened.version} and the protected store expects ${trustedVersion}`,
      );
    }
    return cell(construction, attack, 'SUCCEEDS_CLEANLY', cleanDetail);
  };

  const flipped: SectorRecord = { ...recordV2, sealed: Uint8Array.from(recordV2.sealed) };
  flipped.sealed[19] ^= 0x01;

  const rollbackDetail = versioned
    ? 'the tag verifies AND the version store was rolled back with it, so nothing is left to notice — the target moved, it did not disappear'
    : 'the tag verifies: the record is authentic, correctly placed and simply old. An AEAD authenticates a ciphertext; RFC 5116 section 1.1 is explicit that it does not address anti-replay';

  return [
    await judge(flipped, 'bit-modification', 'the read returned the current version unchanged'),
    await judge(recordNeighbour, 'relocation', 'the read returned the current version unchanged'),
    await judge(recordV1, 'rollback', rollbackDetail),
  ];
}

export async function runComparison(options: { attackerControlsVersionStore: boolean }): Promise<ComparisonReport> {
  const xtsKey: XtsKeyPair = {
    k1: crypto.getRandomValues(new Uint8Array(16)),
    k2: crypto.getRandomValues(new Uint8Array(16)),
  };
  const gcmKey = crypto.getRandomValues(new Uint8Array(16));

  const cells = [
    ...runXtsColumn(xtsKey),
    ...(await runGcmColumn('sector-aad', 'gcm-sector-aad', gcmKey, options.attackerControlsVersionStore)),
    ...(await runGcmColumn(
      'sector-and-version-aad',
      'gcm-sector-version-aad',
      gcmKey,
      options.attackerControlsVersionStore,
    )),
  ];

  const overheadBytes: Record<ConstructionId, number> = {
    xts: 0,
    'gcm-sector-aad': gcmOverheadBytes('sector-aad'),
    'gcm-sector-version-aad': gcmOverheadBytes('sector-and-version-aad'),
  };
  const overheadPercent = {
    xts: 0,
    'gcm-sector-aad': (overheadBytes['gcm-sector-aad'] / SECTOR_BYTES) * 100,
    'gcm-sector-version-aad': (overheadBytes['gcm-sector-version-aad'] / SECTOR_BYTES) * 100,
  };

  return {
    cells,
    overheadBytes,
    overheadPercent,
    attackerControlsVersionStore: options.attackerControlsVersionStore,
    originalText: V1_TEXT,
    updatedText: V2_TEXT,
  };
}

export function findCell(report: ComparisonReport, construction: ConstructionId, attack: AttackId): ComparisonCell {
  const found = report.cells.find((c) => c.construction === construction && c.attack === attack);
  if (!found) throw new Error(`no comparison cell for ${construction} / ${attack}`);
  return found;
}
