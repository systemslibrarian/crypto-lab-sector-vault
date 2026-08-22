import type { SectorRead } from '../volume/volume.js';
import { XTS_FAILURE_CODES } from '../crypto/xts.js';
import { BLOCKS_PER_SECTOR, SECTOR_BYTES } from '../volume/types.js';
import { h } from './dom.js';
import { definition, statusLabel, TONE_INFO, toneForStatus, verdictPill } from './format.js';

/**
 * The device the whole lab turns on: two columns, side by side.
 *
 * The left column is everything a real full-disk-encryption stack has — bytes
 * came back, and that is the end of the report. The right column is the lab's
 * own write log, which no disk driver keeps. When the two disagree and the left
 * column still says nothing, that gap IS the negative claim.
 */
export function readout(read: SectorRead): HTMLElement {
  const tone = toneForStatus(read.status);
  const damaged = read.changedBlocks.length;

  const actual = h('div', { class: 'readout-col' }, [
    h('h4', { text: 'What actually happened' }),
    verdictPill(tone, statusLabel(read.status)),
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
  ]);

  const reported = h('div', { class: 'readout-col' }, [
    h('h4', { text: 'What XTS reported' }),
    verdictPill(TONE_INFO, `READ OK — ${SECTOR_BYTES} BYTES RETURNED`),
    h('dl', {}, [
      definition('failure code', read.failureCode === null ? 'none — there is none to give' : read.failureCode),
      definition('errors raised', '0'),
      definition('codes this mode has', XTS_FAILURE_CODES.join(' · ')),
    ]),
    h('p', {
      class: 'readout-note',
      text: `Both of those codes are about malformed input — a data unit under 16 bytes, or a key of the wrong length. Neither one can fire on a ciphertext an adversary edited, because XTS carries no tag, no checksum and no redundancy to test.`,
    }),
  ]);

  return h('div', { class: 'readout' }, [reported, actual]);
}
