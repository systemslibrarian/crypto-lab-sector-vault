import { XTS_FAILURE_CODES } from '../crypto/xts.js';
import { SECTOR_BYTES, SECTOR_COUNT } from '../volume/types.js';
import { h, replace } from './dom.js';
import type { LabContext } from './state.js';

/** What the adversary has done to this volume so far. */
export function mountLogPanel(ctx: LabContext): { root: HTMLElement; refresh: () => void } {
  const root = h('section', { class: 'card', id: 'session-log', 'aria-labelledby': 'log-title' }, [
    h('h2', { id: 'log-title', text: 'What has been done to this volume' }),
  ]);
  const resetButton = h('button', { type: 'button', id: 'reset-volume' }, [
    'Reformat with fresh keys',
  ]) as HTMLButtonElement;
  resetButton.addEventListener('click', () => {
    ctx.reset();
  });
  root.append(h('div', { class: 'controls' }, [resetButton]));
  const listHost = h('div', { role: 'status', 'aria-live': 'polite', id: 'log-host' });
  root.append(listHost);

  function refresh(): void {
    const entries = ctx.state.log;
    replace(listHost, [
      entries.length === 0
        ? h('p', {
            class: 'readout-note',
            text: 'Nothing yet. Every write, flip, copy, rollback and disk image will be listed here, newest first.',
          })
        : h(
            'ul',
            { class: 'log', role: 'list' },
            entries.slice(0, 20).map((entry) => h('li', { role: 'listitem', text: entry })),
          ),
    ]);
  }

  return { root, refresh };
}

/** Honest scoping, in-page. The same claims the README makes. */
export function scopeCard(): HTMLElement {
  return h('section', { class: 'card', id: 'scope', 'aria-labelledby': 'scope-title' }, [
    h('h2', { id: 'scope-title', text: 'Scope, and what this does not prove' }),

    h('h3', { text: 'The negative claim this lab exists to demonstrate' }),
    h('p', {
      text: 'XTS-based, confidentiality-only full-disk encryption does not detect adversarial modification or rollback. Acts 2 and 3 are the evidence: every read returns bytes, no read raises anything, and the mode has no failure code that could apply.',
    }),
    h('p', {
      class: 'readout-note',
      text: 'That claim is pinned to XTS, not to full-disk encryption in general. Act 5 names integrity-enabled storage designs that do detect exactly these attacks; a claim that contradicted its own act 5 would be an overclaim.',
    }),

    h('h3', { text: 'What is real' }),
    h('ul', { class: 'scope-list' }, [
      h('li', {
        text: 'XTS-AES-128 per NIST SP 800-38E and IEEE Std 1619-2007: XEX tweaking, the GF(2^128) alpha ladder and ciphertext stealing, all written out in this repository and verified against the standard’s own published vectors.',
      }),
      h('li', {
        text: 'The AES block cipher itself comes from @noble/ciphers, an audited implementation, through its raw single-block API. The mode around it is this lab’s; the primitive inside it is not, deliberately.',
      }),
      h('li', {
        text: 'The AES-GCM in act 5 is the browser’s own WebCrypto implementation. Every BAD_TAG in that table is a tag your browser refused to verify.',
      }),
      h('li', {
        text: `The volume is ${SECTOR_COUNT} sectors of ${SECTOR_BYTES} bytes. Both keys are generated per session with crypto.getRandomValues, held in memory only, and never written to storage or sent anywhere.`,
      }),
    ]),

    h('h3', { text: 'What is a teaching device, not part of the cryptography' }),
    h('ul', { class: 'scope-list' }, [
      h('li', {
        text: 'The write log. This page remembers every plaintext ever written so it can print "what actually happened" beside "what XTS reported". A real disk driver has no such log — that is the entire point of the two-column read-out, and it is why the right-hand column is knowledge you would not have.',
      }),
      h('li', {
        text: 'The trusted version store in act 5 is a JavaScript number. In a real deployment it has to be a TPM, a secure element, or a Merkle root kept off the volume, and the checkbox in that act is there so the difference is not glossed over.',
      }),
      h('li', {
        text: 'Sector contents are short ASCII lines padded with spaces, so that damaged plaintext is legible as damage. Real disk sectors are not this compressible or this readable.',
      }),
    ]),

    h('h3', { text: 'What this does NOT prove' }),
    h('ul', { class: 'scope-list' }, [
      h('li', { text: 'It does not show a weakness in AES, or in XTS as a confidentiality mode. XTS does what it claims; the lab is about what it never claimed.' }),
      h('li', { text: 'It does not show that any particular product is vulnerable. BitLocker, FileVault and LUKS all layer other mechanisms around the mode, and what those buy is a question about each product, not about XTS.' }),
      h('li', { text: 'It does not measure how hard these attacks are to mount in practice. Every one of them assumes write access to the stored ciphertext, which is a real threat model for cloud volumes, backups and stolen hardware, and not a given everywhere else.' }),
      h('li', { text: 'It does not evaluate the narrowing attacks on XTS itself (the mode’s known malleability granularity and the plaintext-manipulation literature); the acts here are about the absence of authentication, not about distinguishing attacks.' }),
    ]),

    h('h3', { text: 'Not production cryptography' }),
    h('p', {
      text: `This is a teaching demo. It runs entirely in your browser with no backend, its keys live for as long as the tab does, and it exists to be broken. Do not use it to protect anything. The failure codes XTS itself can raise are ${XTS_FAILURE_CODES.join(' and ')}, and both are about malformed input.`,
    }),

    h('details', { class: 'more' }, [
      h('summary', { text: 'Standards and prior art' }),
      h('ul', { class: 'scope-list' }, [
        h('li', { text: 'NIST SP 800-38E (2010) — Recommendation for Block Cipher Modes of Operation: the XTS-AES Mode for Confidentiality on Storage Devices. Cited here specifically for its storage-device scope and its statement that the mode does not authenticate the data or its source.' }),
        h('li', { text: 'IEEE Std 1619-2007 — Standard for Cryptographic Protection of Data on Block-Oriented Storage Devices, whose Annex B vectors this implementation is checked against.' }),
        h('li', { text: 'Rogaway (2004), "Efficient Instantiations of Tweakable Blockciphers and Refinements to Modes OCB and PMAC" — the XEX construction XTS is built on.' }),
        h('li', { text: 'RFC 5116 section 1.1 — the AEAD interface, and its explicit statement that anti-replay is not addressed by it. That sentence is why act 5 has three stages.' }),
      ]),
    ]),
  ]);
}
