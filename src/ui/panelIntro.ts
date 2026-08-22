import { h } from './dom.js';

/** The hero, in the fleet's standard three-role shape. */
export function heroBlock(): HTMLElement {
  return h('div', { class: 'cl-hero' }, [
    h('div', { class: 'cl-hero-main' }, [
      h('h1', { class: 'cl-hero-title', text: 'Sector Vault' }),
      h('p', { class: 'cl-hero-sub', text: 'XTS-AES · NIST SP 800-38E' }),
      h('p', {
        class: 'cl-hero-desc',
        text: 'Runs real XTS-AES over a 16-sector volume so you can flip a ciphertext bit, move a block, roll a sector back to yesterday, and watch every one of those reads return plaintext with no error raised.',
      }),
    ]),
    h('aside', { class: 'cl-hero-why', 'aria-label': 'Why it matters' }, [
      h('span', { class: 'cl-hero-why-label', text: 'WHY IT MATTERS' }),
      h('p', {
        class: 'cl-hero-why-text',
        text: 'Full-disk encryption is the default on laptops, phones and cloud volumes, and the mode nearly all of it uses checks nothing about whether the data you read is the data you wrote. Anyone who can write to the disk can change what comes back. Bolting on an authenticated mode fixes less of that than almost everyone expects.',
      }),
    ]),
  ]);
}

/** A plain-language on-ramp: no maths, no hex, before anything else. */
export function introCard(): HTMLElement {
  return h('section', { class: 'card', id: 'intro', 'aria-labelledby': 'intro-title' }, [
    h('h2', { id: 'intro-title', text: 'What this is, in plain language' }),
    h('p', {
      text: 'When a laptop encrypts its disk, it cannot afford to store anything extra. A sector is exactly 512 or 4096 bytes on the hardware, and after encryption it has to be exactly 512 or 4096 bytes again — so there is no room for a checksum, a signature, or a "this is version 7" marker. The mode built for that constraint is called XTS, and it is what BitLocker, FileVault, LUKS and most cloud disks use.',
    }),
    h('p', {
      text: 'XTS keeps your data secret. That is all it does. It has no way to tell you that someone changed the encrypted bytes on the disk, because it never stored anything that could disagree with them. Change one bit and the affected chunk comes back as sixteen bytes of noise — and the disk reports a perfectly successful read.',
    }),
    h('p', {
      text: 'Below you get a small encrypted volume and the same access an attacker with your disk would have: you can edit the encrypted bytes, but not read the keys. Break it yourself, and watch what does and does not get noticed. Then, in the last act, add real authenticated encryption and find out which of the three attacks it actually stops.',
    }),
    h('p', {
      class: 'readout-note',
      text: 'Every operation on this page is real cryptography running in your browser. Nothing is mocked, and nothing is precomputed.',
    }),
  ]);
}
