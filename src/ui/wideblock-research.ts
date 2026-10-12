import { h, replace } from './dom.js';
import { runEme2Experiment, type Eme2Experiment, type DiffusionResult } from '../volume/eme2-experiment.js';
import { toHex } from '../crypto/bytes.js';
import type { Eme2Keys } from '../crypto/eme2.js';

function freshKeys(): Eme2Keys {
  const bytes = crypto.getRandomValues(new Uint8Array(48));
  return { aes: bytes.slice(32), ecbMask: bytes.slice(16, 32), adMask: bytes.slice(0, 16) };
}

export function buildWideblockResearch(): HTMLElement {
  const section = h('section', { id: 'wideblock-research', class: 'card', 'aria-labelledby': 'eme2-title' });
  section.append(
    h('h2', { id: 'eme2-title', text: 'EME2: see a change spread across a data unit' }),
    h('p', { class: 'lede', text: 'Flip one ciphertext bit in XTS and EME2, then compare the decrypted bytes. EME2 spreads the change more widely. Neither mode detects the attacker.' }),
    h('p', { class: 'readout-note' }, [
      'Research implementation of the historical EME* / EME2 construction. ',
      h('a', { href: 'https://eprint.iacr.org/2004/125', target: '_blank', rel: 'noopener noreferrer' }, ['Halevi’s paper, 27 May 2004']),
      ' supplies the algorithm; the ',
      h('a', { href: 'https://web.archive.org/web/20171018232831/http://siswg.net/index2.php?Itemid=41&gid=156&option=com_docman&task=doc_view', target: '_blank', rel: 'noopener noreferrer' }, ['archived IEEE P1619.2/D9 draft, December 2008']),
      ' fixes the byte encoding. This is not a claim of IEEE 1619.2-2025 conformance. Tests use independent AES backends and published third-party regression vectors, not official IEEE vectors.',
    ]),
    h('p', {}, [
      h('a', { href: 'https://standards.ieee.org/ieee/1619.2/11949/', target: '_blank', rel: 'noopener noreferrer' }, ['IEEE 1619.2-2025 (published 20 November 2025; active)']),
      ' specifies EME2-AES encryption with associated data for storage without authentication. EAD is not AEAD. AES-GCM detects unauthenticated changes; valid old ciphertext still needs trusted version state to prevent rollback, as Act 5 shows.',
    ]),
  );
  const size = h('select', { id: 'eme2-size' }, [
    h('option', { value: '512', text: '512 bytes — one sector' }),
    h('option', { value: '513', text: '513 bytes — partial final block' }),
    h('option', { value: '2064', text: '2064 bytes — mask renewal' }),
  ]);
  const choice = h('select', { id: 'eme2-experiment' }, [
    h('option', { value: 'ciphertext-bit', text: 'Flip a ciphertext bit' }),
    h('option', { value: 'plaintext-bit', text: 'Change a plaintext bit' }),
    h('option', { value: 'splice', text: 'Splice a ciphertext block' }),
    h('option', { value: 'wrong-ad', text: 'Read at another address' }),
    h('option', { value: 'replay', text: 'Restore an old version' }),
    h('option', { value: 'clean', text: 'Read the original data' }),
  ]);
  const rekey = h('button', { type: 'button', id: 'eme2-rekey', text: 'Try fresh session keys' });
  section.append(h('div', { class: 'controls' }, [
    h('div', { class: 'field' }, [h('label', { for: 'eme2-size', text: 'Data unit size' }), size]),
    h('div', { class: 'field' }, [h('label', { for: 'eme2-experiment', text: 'Experiment' }), choice]),
    rekey,
  ]));
  const status = h('div', { id: 'eme2-status', role: 'status', 'aria-live': 'polite' });
  const maps = h('div', { class: 'eme2-comparison' });
  section.append(status, maps, h('p', { class: 'readout-note', text: 'Each tile represents up to 16 bytes. “Changed” means at least one byte differs in this run; diffusion counts are observations, not a guarantee that every bit or block must change. This separate synthetic exhibit uses fresh in-memory keys and does not write to the volume above.' }));

  let keys = freshKeys();
  function resultCard(name: string, result: DiffusionResult, output: string): HTMLElement {
    return h('div', { class: 'eme2-result' }, [
      h('h3', { text: name }),
      h('p', { 'data-eme2-count': name, text: `${result.changedBlocks} of ${result.changed.length} blocks changed; ${result.changedBits} ${result.changedBits === 1 ? 'bit differs' : 'bits differ'}.` }),
      h('ol', { class: 'eme2-map', role: 'list', 'aria-label': `${name} changed-block map` }, result.changed.map((changed, i) =>
        h('li', { class: changed ? 'changed' : '', role: 'listitem', text: `${i + 1}: ${changed ? 'Changed' : 'Same'}` }))),
      h('details', { class: 'more' }, [
        h('summary', { text: `${output}: first 64 bytes in hex` }),
        h('code', { class: 'eme2-hex', text: toHex(result.bytes.subarray(0, 64)) }),
      ]),
    ]);
  }
  function refresh(): void {
    const result = runEme2Experiment(keys, Number(size.value), choice.value as Eme2Experiment);
    replace(status, [h('p', { text: result.result }), h('p', { class: 'readout-note', text: result.detail })]);
    replace(maps, [resultCard('XTS-AES', result.xts, result.outputLabel), resultCard('EME2-AES', result.eme2, result.outputLabel)]);
  }
  size.addEventListener('change', refresh);
  choice.addEventListener('change', refresh);
  rekey.addEventListener('click', () => { keys = freshKeys(); refresh(); });
  refresh();
  return section;
}
