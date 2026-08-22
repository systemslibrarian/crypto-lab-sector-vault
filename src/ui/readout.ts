import type { SectorRead } from '../volume/volume.js';
import type { SectorVolume } from '../volume/volume.js';
import { XTS_FAILURE_CODES } from '../crypto/xts.js';
import { runXtsChecks } from '../volume/checks.js';
import { NEGATIVE_CLAIM, NEGATIVE_CLAIM_EVIDENCE, NEGATIVE_CLAIM_ID } from '../volume/negative-claim.js';
import { BLOCKS_PER_SECTOR, SECTOR_BYTES } from '../volume/types.js';
import { h } from './dom.js';
import {
  definition,
  statusLabel,
  TONE_ALARM,
  TONE_INFO,
  TONE_OK,
  toneForStatus,
  verdictPill,
} from './format.js';

/**
 * The device the whole lab turns on.
 *
 * A HEADLINE verdict that reads as success and failure at once, then two
 * columns: everything a real full-disk-encryption stack has — the checks the
 * construction actually performs, run for real, with their outcomes — beside
 * the lab's own write log, which no disk driver keeps. When every check on the
 * left reports success and the right-hand column says the data is wrong, that
 * state IS the negative claim's evidence fixture, and the claim is printed
 * inside it rather than left in a README.
 *
 * `data-check` is rendered from the real outcome of a real check, so a test can
 * enumerate the verdicts the page painted rather than trusting prose. The two
 * rows carrying `data-missing-check` are the exhibit: they name checks the
 * construction does not have, which is why no code exists to raise.
 */
export function readout(volume: SectorVolume, read: SectorRead): HTMLElement {
  const tone = toneForStatus(read.status);
  const damaged = read.changedBlocks.length;
  const checks = runXtsChecks(volume.key, volume.sequenceNumber(read.sector), volume.ciphertextOf(read.sector));
  const performed = checks.filter((c) => c.outcome !== 'no-such-check');
  const allPassed = performed.every((c) => c.outcome === 'pass');

  const headline =
    read.status === 'INTACT'
      ? 'DECRYPTED — AND INTACT'
      : read.status === 'SUCCEEDS_CLEANLY_STALE'
        ? 'DECRYPTED — AND ROLLED BACK'
        : 'DECRYPTED — AND MODIFIED';

  const reported = h('div', { class: 'readout-col' }, [
    h('h4', { text: 'What XTS reported' }),
    verdictPill(TONE_INFO, `READ OK — ${SECTOR_BYTES} BYTES RETURNED`, 'construction-report'),
    h(
      'ul',
      { class: 'checks', role: 'list' },
      checks.map((check) =>
        h(
          'li',
          check.outcome === 'no-such-check'
            ? { role: 'listitem', class: 'check-row-item', 'data-missing-check': check.name }
            : { role: 'listitem', class: 'check-row-item', 'data-check': check.outcome },
          [
            check.outcome === 'no-such-check'
              ? verdictPill(TONE_ALARM, `${check.name}: NO SUCH CHECK`, 'missing-check')
              : verdictPill(TONE_OK, `${check.name}: PASS`, 'check'),
            h('span', { class: 'check-detail', text: check.detail }),
          ],
        ),
      ),
    ),
    h('dl', {}, [
      definition('failure code', read.failureCode === null ? 'none — there is none to give' : read.failureCode),
      definition('errors raised', '0'),
      definition('codes this mode has', XTS_FAILURE_CODES.join(' · ')),
    ]),
    h('p', {
      class: 'readout-note',
      text: 'Both of those codes are about malformed input — a data unit under 16 bytes, or a key of the wrong length. Neither one can fire on a ciphertext an adversary edited, because XTS carries no tag, no checksum and no redundancy to test.',
    }),
  ]);

  const actual = h('div', { class: 'readout-col' }, [
    h('h4', { text: 'What actually happened' }),
    verdictPill(tone, statusLabel(read.status), 'ground-truth'),
    h('dl', {}, [
      definition('blocks differing', `${damaged} of ${BLOCKS_PER_SECTOR}`),
      definition(
        'first differing block',
        damaged ? `block ${read.changedBlocks[0]} (bytes ${read.changedBlocks[0] * 16}–${read.changedBlocks[0] * 16 + 15})` : '—',
      ),
      read.staleVersion !== null
        ? definition('version returned', `version ${read.staleVersion}, which is not the current one`)
        : null,
    ] as HTMLElement[]),
    h('p', {
      class: 'readout-note',
      text:
        read.status === 'INTACT'
          ? 'The bytes read are the bytes written.'
          : read.status === 'SUCCEEDS_CLEANLY_STALE'
            ? 'Not corruption. Those bytes were written to this exact sector by the key holder, so they decrypt perfectly. They are simply old, and nothing in XTS binds a version.'
            : 'These bytes were never written here by anyone holding the key. The read returned them anyway.',
    }),
    h('p', {
      class: 'readout-note',
      text: 'This column is the lab’s own write log. A shipping disk driver does not have it, which is why the left-hand column is the whole of what a real system would know.',
    }),
  ]);

  const parts: HTMLElement[] = [
    h('div', { class: 'readout-headline' }, [
      h('span', { class: 'readout-headline-label', text: `SECTOR ${read.sector} READ` }),
      verdictPill(tone, headline, 'headline'),
    ]),
    h('div', { class: 'readout' }, [reported, actual]),
  ];

  // The evidence fixture: every performed check passed, and the data is wrong
  // anyway. Printed here, in the state that demonstrates it, not in a README
  // and not behind a disclosure.
  if (read.status !== 'INTACT' && allPassed) {
    parts.push(
      h('div', { class: 'neg-claim', 'data-negative-claim': NEGATIVE_CLAIM_ID }, [
        h('span', { class: 'neg-claim-label', text: `${NEGATIVE_CLAIM_ID} — NEGATIVE CLAIM` }),
        h('p', { class: 'neg-claim-text', text: NEGATIVE_CLAIM }),
        h('p', { class: 'neg-claim-evidence', text: NEGATIVE_CLAIM_EVIDENCE }),
      ]),
    );
  }

  return h('div', {}, parts);
}
