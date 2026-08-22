/**
 * The lab's negative claim, in one place, so the page and its tests cannot
 * disagree about what is being claimed.
 *
 * Scoped to the construction, deliberately. "Full-disk encryption does not
 * detect modification" would be false, and contradicted by act 5 of this very
 * lab — dm-integrity, filesystem checksumming and T10 Protection Information
 * all detect exactly these attacks. The claim is about XTS.
 */
export const NEGATIVE_CLAIM_ID = 'NEG-1';

export const NEGATIVE_CLAIM =
  'XTS-based, confidentiality-only full-disk encryption does not detect adversarial modification or rollback.';

export const NEGATIVE_CLAIM_EVIDENCE =
  'This read is the evidence. Every check XTS-AES actually performs reported success, no failure code was available to raise, and the bytes handed back are not the bytes that were written.';
