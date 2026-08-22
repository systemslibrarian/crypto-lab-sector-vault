import {
  ATTACK_LABEL,
  ATTACKS,
  CONSTRUCTION_LABEL,
  CONSTRUCTIONS,
  findCell,
  runComparison,
  type ComparisonReport,
} from '../volume/comparison.js';
import { XTS_FAILURE_CODES } from '../crypto/xts.js';
import { GCM_NONCE_BYTES, GCM_TAG_BYTES, VERSION_BYTES } from '../crypto/gcm.js';
import { SECTOR_BYTES } from '../volume/types.js';
import { actCard, h, replace, scroller } from './dom.js';
import { percent, TONE_ALARM, TONE_OK, TONE_STALE, verdictPill } from './format.js';

/**
 * Act 5 — three stages, not two.
 *
 * Every cell in this table is produced by running the attack against the real
 * construction when the panel renders. The interesting cell is stage two's
 * rollback: an AEAD authenticates a ciphertext, and RFC 5116 section 1.1 is
 * explicit that the interface does not address anti-replay. A whole old record
 * replayed at its own sector number authenticates perfectly, so "add an AEAD
 * and rollback dies too" is simply false — and the false part is the part worth
 * teaching.
 */
export function mountComparisonPanel(): { root: HTMLElement; refresh: () => void } {
  const root = actCard('act-compare', 'ACT 5', 'What integrity would actually buy you');

  root.append(
    h('p', { class: 'lede' }, [
      'Run the same three attacks against three constructions. Not two — three, because the obvious story is wrong. ',
      'Bolting an AEAD onto a sector catches modification and relocation immediately, and does nothing whatsoever about a rolled-back sector, because authenticating a ciphertext is not the same as knowing it is current.',
    ]),
  );

  const storeToggle = h('input', { type: 'checkbox', id: 'attacker-owns-store' }) as HTMLInputElement;
  root.append(
    h('div', { class: 'check-row' }, [
      storeToggle,
      h('label', { for: 'attacker-owns-store' }, [
        'The attacker also controls the version store (they own the whole volume, and the counter lives on it)',
      ]),
    ]),
  );

  const tableHost = h('div', { role: 'status', 'aria-live': 'polite', id: 'comparison' });
  const codesHost = h('div', {});
  const costHost = h('div', {});
  root.append(tableHost, codesHost, costHost);

  root.append(
    h('h3', { text: 'Two things that have to be said alongside that table' }),
    h('ul', { class: 'notes', role: 'list' }, [
      h('li', { role: 'listitem' }, [
        h('strong', { text: 'The nonce. ' }),
        `Using the sector number as the GCM nonce needs no storage at all — and reuses one nonce under one key on every rewrite of that sector, which is catastrophic for GCM: it leaks the XOR of the two plaintexts and, worse, the authentication subkey, after which forgery is possible. That is a separate disaster, and Nonce Collision and Nonce Guard already teach it. So the stages above draw ${GCM_NONCE_BYTES * 8} fresh random bits per write and store them. That storage is the cost this act is about.`,
      ]),
      h('li', { role: 'listitem' }, [
        h('strong', { text: '"Protected" is load-bearing. ' }),
        'The version counter has to be authenticated AND held somewhere the attacker cannot roll back too — a separate trusted store, a secure element, or a Merkle structure over the whole volume with its root kept off the disk. Tick the box above and watch stage three fall back to stage two. Without that, stage three has only moved the rollback target one level down, and a panel that ended on a clean win would be lying.',
      ]),
    ]),
  );

  root.append(
    h('h3', { text: 'Why XTS omits all of it' }),
    h('p', { class: 'lede' }, [
      'NIST SP 800-38E scopes XTS-AES to storage devices where the data unit is the sector — exactly 512 or 4096 bytes, with nowhere to put a nonce or a tag — and states plainly that the mode provides confidentiality only, not authentication of the data or its source. ',
      'The mode was written to expand data by zero bytes, and everything in the table above costs bytes.',
    ]),
    h('p', { class: 'lede' }, [
      'That is a design choice with a cost, not an oversight, and it is not true that nobody does the other thing. ',
      'dm-integrity carries a per-sector tag underneath dm-crypt; filesystem-level checksumming (ZFS, Btrfs) detects modification at the block level; and T10 Protection Information adds eight bytes of metadata per sector on enterprise SAS drives precisely so there is room. Those designs all buy the metadata space that SP 800-38E assumes away.',
    ]),
  );

  root.append(
    h('details', { class: 'more' }, [
      h('summary', { text: 'The same lesson in the streaming domain' }),
      h('p', {}, [
        'Stream Ward makes the neighbouring point about a file split into segments: per-segment AEAD authenticates every frame perfectly while ordering, truncation and replay stay broken, until a chain state binds each segment to the ones before it. ',
        'One-shot AEAD authenticates content. Binding position, order or version is a separate job, and it always costs storage. ',
        h('a', { href: 'https://systemslibrarian.github.io/crypto-lab-stream-ward/', target: '_blank', rel: 'noopener' }, [
          'Stream Ward',
        ]),
        '.',
      ]),
    ]),
  );

  let report: ComparisonReport | null = null;
  let pending = 0;

  async function recompute(): Promise<void> {
    const ticket = ++pending;
    const next = await runComparison({ attackerControlsVersionStore: storeToggle.checked });
    if (ticket !== pending) return;
    report = next;
    draw();
  }

  storeToggle.addEventListener('change', () => {
    void recompute();
  });

  function draw(): void {
    if (!report) {
      replace(tableHost, [h('p', { class: 'readout-note', text: 'Running the nine experiments…' })]);
      return;
    }
    const current = report;

    const head = h('tr', {}, [
      h('th', { scope: 'col', text: 'Construction' }),
      ...ATTACKS.map((attack) => h('th', { scope: 'col', text: ATTACK_LABEL[attack] })),
    ]);
    const body = CONSTRUCTIONS.map((construction) =>
      h('tr', {}, [
        h('th', { scope: 'row', text: CONSTRUCTION_LABEL[construction] }),
        ...ATTACKS.map((attack) => {
          const cell = findCell(current, construction, attack);
          // Tone tracks SYSTEM INTEGRITY, not the return value: a read that
          // succeeded and handed back stale or attacker-chosen bytes is an
          // alarm, however cleanly it succeeded. The glyph then separates the
          // two alarm kinds, because "corrupted" and "succeeded, but old" are
          // different things and neither of them is a rejection.
          const tone = cell.raisedByConstruction
            ? TONE_OK
            : cell.outcome === 'SUCCEEDS_CLEANLY'
              ? TONE_STALE
              : TONE_ALARM;
          return h('td', {}, [
            verdictPill(tone, cell.label),
            h('span', { class: 'cell-detail', text: cell.detail }),
          ]);
        }),
      ]),
    );

    replace(tableHost, [
      scroller(
        'Three attacks against three constructions',
        h('table', { class: 'matrix' }, [
          h('caption', {
            class: 'readout-note',
            text: `Every cell run live. Green means the construction itself refused; red means the read returned attacker-chosen or stale bytes and said nothing. "${current.originalText}" was written, then updated to "${current.updatedText}".`,
          }),
          h('thead', {}, [head]),
          h('tbody', {}, body),
        ]),
      ),
    ]);

    // ── The failure-code inventory. The gaps are the exhibit. ────────────
    const observed = new Map<string, Set<string>>();
    for (const construction of CONSTRUCTIONS) observed.set(construction, new Set());
    for (const cell of current.cells) {
      if (cell.raisedByConstruction) observed.get(cell.construction)?.add(cell.outcome);
    }
    const allCodes = [...XTS_FAILURE_CODES, 'BAD_TAG', 'STALE_VERSION'];
    replace(codesHost, [
      h('h3', { text: 'Every failure code each construction can produce' }),
      scroller(
        'Failure codes by construction',
        h('table', { class: 'matrix' }, [
          h('caption', {
            class: 'readout-note',
            text: 'The first two are input validation — a data unit under 16 bytes, a key of the wrong length — and belong to every construction here, because all three refuse malformed input. The last two are the only codes that can ever fire because of something an adversary did.',
          }),
          h('thead', {}, [
            h('tr', {}, [
              h('th', { scope: 'col', text: 'Failure code' }),
              ...CONSTRUCTIONS.map((c) => h('th', { scope: 'col', text: CONSTRUCTION_LABEL[c] })),
            ]),
          ]),
          h(
            'tbody',
            {},
            allCodes.map((code) =>
              h('tr', {}, [
                h('th', { scope: 'row', text: code }),
                ...CONSTRUCTIONS.map((construction) => {
                  const isInputCode = (XTS_FAILURE_CODES as readonly string[]).includes(code);
                  const has = isInputCode || observed.get(construction)?.has(code) === true;
                  return h('td', {}, [
                    verdictPill(has ? TONE_OK : TONE_ALARM, has ? 'available' : 'no such code'),
                  ]);
                }),
              ]),
            ),
          ),
        ]),
      ),
    ]);

    // ── What the integrity costs in stored bytes ─────────────────────────
    replace(costHost, [
      h('h3', { text: 'What it costs, in bytes' }),
      scroller(
        'Storage overhead per sector by construction',
        h('table', { class: 'matrix' }, [
          h('thead', {}, [
            h('tr', {}, [
              h('th', { scope: 'col', text: 'Construction' }),
              h('th', { scope: 'col', text: 'Extra bytes per 512-byte sector' }),
              h('th', { scope: 'col', text: 'Expansion' }),
              h('th', { scope: 'col', text: 'What the bytes are' }),
            ]),
          ]),
          h('tbody', {}, [
            h('tr', {}, [
              h('th', { scope: 'row', text: CONSTRUCTION_LABEL.xts }),
              h('td', { text: String(current.overheadBytes.xts) }),
              h('td', { text: percent(current.overheadPercent.xts) }),
              h('td', { text: 'nothing at all — a sector goes in at 512 bytes and comes out at 512 bytes, which is the whole reason the mode exists' }),
            ]),
            h('tr', {}, [
              h('th', { scope: 'row', text: CONSTRUCTION_LABEL['gcm-sector-aad'] }),
              h('td', { text: String(current.overheadBytes['gcm-sector-aad']) }),
              h('td', { text: percent(current.overheadPercent['gcm-sector-aad']) }),
              h('td', { text: `${GCM_NONCE_BYTES}-byte nonce + ${GCM_TAG_BYTES}-byte tag` }),
            ]),
            h('tr', {}, [
              h('th', { scope: 'row', text: CONSTRUCTION_LABEL['gcm-sector-version-aad'] }),
              h('td', { text: String(current.overheadBytes['gcm-sector-version-aad']) }),
              h('td', { text: percent(current.overheadPercent['gcm-sector-version-aad']) }),
              h('td', { text: `${GCM_NONCE_BYTES}-byte nonce + ${GCM_TAG_BYTES}-byte tag + ${VERSION_BYTES}-byte version, and a trusted store for the expected version` }),
            ]),
          ]),
        ]),
      ),
      h('p', {
        class: 'readout-note',
        text: `On a device whose sector is exactly ${SECTOR_BYTES} bytes, those extra bytes have nowhere to go. That is the constraint SP 800-38E was written under, and it is why the answer was a mode with no integrity rather than a mode with weak integrity.`,
      }),
    ]);
  }

  draw();
  void recompute();

  return { root, refresh: draw };
}
