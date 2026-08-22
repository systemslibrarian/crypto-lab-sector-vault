/**
 * Every check XTS-AES actually performs on a read, run for real.
 *
 * This is the evidence half of the negative claim. The page cannot simply
 * assert that nothing was detected — it has to reach the state, run the checks
 * the construction genuinely has, and print their outcomes. Two of them exist
 * and both pass; the other two rows are the exhibit, because they name checks
 * the mode does not have at all. The absence of a failure code is the finding,
 * and inventing one to look thorough would teach the opposite of the lesson.
 */
import { createXtsCipher, XTS_BLOCK_BYTES, XtsError, type XtsFailureCode, type XtsKeyPair } from '../crypto/xts.js';

export interface ConstructionCheck {
  name: string;
  /** The code this check can raise, or null when the construction has no such check. */
  code: XtsFailureCode | null;
  outcome: 'pass' | 'fail' | 'no-such-check';
  detail: string;
}

export function runXtsChecks(
  key: XtsKeyPair,
  sequenceNumber: bigint,
  ciphertext: Uint8Array,
): ConstructionCheck[] {
  const checks: ConstructionCheck[] = [];

  // 1. KEY_LENGTH_INVALID — really attempted, not assumed.
  let cipher: ReturnType<typeof createXtsCipher> | null = null;
  try {
    cipher = createXtsCipher(key);
    checks.push({
      name: 'Key length',
      code: 'KEY_LENGTH_INVALID',
      outcome: 'pass',
      detail: `K1 and K2 are both ${key.k1.length} bytes, so XTS-AES-${key.k1.length * 8} is well formed`,
    });
  } catch (error) {
    checks.push({
      name: 'Key length',
      code: 'KEY_LENGTH_INVALID',
      outcome: 'fail',
      detail: error instanceof XtsError ? `${error.code}: ${error.message}` : String(error),
    });
  }

  // 2. MALFORMED_SECTOR — the decrypt is really run and its outcome reported.
  if (cipher === null) {
    checks.push({
      name: 'Data unit length',
      code: 'MALFORMED_SECTOR',
      outcome: 'fail',
      detail: 'not reached: the key was rejected before any data unit could be processed',
    });
  } else {
    try {
      const plaintext = cipher.decryptSector(sequenceNumber, ciphertext);
      checks.push({
        name: 'Data unit length',
        code: 'MALFORMED_SECTOR',
        outcome: 'pass',
        detail: `${ciphertext.length} bytes in, ${plaintext.length} bytes out, a whole number of ${plaintext.length / XTS_BLOCK_BYTES} blocks`,
      });
    } catch (error) {
      checks.push({
        name: 'Data unit length',
        code: 'MALFORMED_SECTOR',
        outcome: 'fail',
        detail: error instanceof XtsError ? `${error.code}: ${error.message}` : String(error),
      });
    }
  }

  // 3 and 4. The rows that do not exist. XTS stores no tag, no checksum and no
  // counter, so there is nothing for a check to compare against.
  checks.push({
    name: 'Data authenticity',
    code: null,
    outcome: 'no-such-check',
    detail: 'no tag, no checksum, no redundancy is stored, so nothing can be compared against the ciphertext',
  });
  checks.push({
    name: 'Freshness',
    code: null,
    outcome: 'no-such-check',
    detail: 'nothing in the construction binds a version, so an older ciphertext for this sector is indistinguishable from the current one',
  });

  return checks;
}
