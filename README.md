# Sector Vault — XTS-AES, and the integrity check that isn't there

A browser demo of **XTS-AES** (NIST SP 800-38E / IEEE Std 1619-2007), the mode
almost all full-disk encryption uses. Write to a 16-sector volume, then edit the
encrypted bytes the way anyone holding the disk can: flip one bit, copy a block
somewhere else, put yesterday's sector back. Every one of those reads returns
plaintext and raises nothing, because the construction has nothing to raise it
with. Then add real AES-GCM and find out which of the three attacks that
actually stops.

**Live demo:** https://systemslibrarian.github.io/crypto-lab-sector-vault/

---

## What It Is

**The primitives.** XTS-AES exactly as NIST SP 800-38E and IEEE Std 1619-2007
define it: two independent keys, K1 for the data and K2 for the tweak;
`T_j = AES-K2(data unit sequence number) ⊗ α^j` in GF(2¹²⁸) modulo
`x¹²⁸ + x⁷ + x² + x + 1`; the XEX sandwich `C = AES-K1(P ⊕ T_j) ⊕ T_j`; and
ciphertext stealing for a data unit that is not a whole number of blocks. The
contrast in act 5 is AES-GCM (NIST SP 800-38D) through WebCrypto, with a fresh
96-bit nonce per write and the sector identity — and, at stage three, a
monotonic version — bound as associated data.

**What is hand-rolled and what is borrowed.** The tweak algebra, the XEX
tweaking and the ciphertext stealing are written out in `src/crypto/`, because
they are the thing this lab teaches and hiding them in a library would defeat
the point. The AES block cipher underneath is
[`@noble/ciphers`](https://github.com/paulmillr/noble-ciphers)' audited raw
single-block API (`expandKeyLE` + `encryptBlock`/`decryptBlock`) — that library
exposes ECB but has no XTS, so building XEX over its vetted block primitive is
both the honest option and the only one. WebCrypto was not usable for the
primitive: it exposes no raw single-block AES, and the usual workaround (AES-CBC
under a zero IV over one block) coerces the very operation being taught into
something unreadable.

**The problem.** A sector is exactly 512 or 4096 bytes on the hardware and has
to stay exactly that after encryption, so there is nowhere to put a nonce, a
tag, or a version number. SP 800-38E answers that constraint with a mode that
expands data by zero bytes — and states plainly that it provides confidentiality
only, not authentication of the data or its source.

**The security model.** The adversary can read and write the stored ciphertext
and cannot read the keys. That is the model for a stolen laptop, a snapshotted
cloud volume, a backup server, or a malicious storage backend. Under it, XTS
keeps the plaintext secret and offers no opinion whatsoever about whether the
bytes it decrypts are the bytes anybody wrote.

**The negative claim.** *XTS-based, confidentiality-only full-disk encryption
does not detect adversarial modification or rollback.* It is pinned to XTS, not
to full-disk encryption in general: act 5 names integrity-enabled storage
designs that do detect exactly these attacks, and a claim that contradicted its
own act 5 would be an overclaim. It is asserted as a test, not as prose — see
`e2e/claims.spec.ts` and the `NEG-1` case in `src/crypto/xts.test.ts`.

**Not production cryptography.** A teaching demo, running entirely in the
browser with no backend, whose session keys live as long as the tab does. It
exists to be broken. Do not use it to protect anything.

## Exhibits

1. **The disk.** Sixteen 512-byte sectors under XTS-AES-128. Write text into a
   sector, read it back, and inspect the ciphertext block by block. Every read
   prints two columns: *what XTS reported* — bytes returned, failure code none,
   errors raised zero, always — beside *what actually happened*, which the page
   knows only because it keeps a write log no disk driver has.
2. **The tweak, one multiplication at a time.** The headline mechanism, stepped
   rather than described. `T₀ = AES-K2(sector)`, then one multiply by α per
   block: a single left shift of all 128 bits and one conditional XOR of `0x87`,
   with the carry bit that decides it called out on the real bytes. Beside it,
   the XEX sandwich for the selected block — P, T, P⊕T, the AES output, and the
   ciphertext — compared byte-for-byte against what is actually on the platter.
3. **Flip one bit.** Choose a sector, a byte offset and a bit. Its own 16-byte
   block decrypts to noise; the other thirty-one are perfect; nothing is raised.
   The panel measures how much of the damaged block still reads as text, so
   "decrypts to garbage" is a number rather than an adjective.
4. **Move it, or put it back.** Copy a ciphertext block to another offset, or a
   whole sector to another sector number, and the page prints the tweak that
   made those bytes beside the tweak they are now being read under. That is
   **CORRUPTED (UNDETECTED)** — corrupted is what happened, undetected is what
   the construction did about it. Then restore an earlier image of a sector:
   that one decrypts perfectly and correctly, because nothing binds a version.
   Wrong data, no corruption, no signal at all.
5. **Watermarking.** XTS is deterministic per (sector, block index), so two disk
   images can be diffed directly. Take snapshots and read off, with no key,
   exactly which 16-byte blocks changed and which returned to a value they held
   before — a rollback, visible from the ciphertext alone.
6. **What integrity would actually buy you.** Three attacks against three
   constructions, all nine cells run live when the panel renders:

   | | Bit modification | Relocation | Rollback |
   |---|---|---|---|
   | **XTS-AES** | CORRUPTED (UNDETECTED) | CORRUPTED (UNDETECTED) — tweak is position-bound | succeeds cleanly |
   | **AES-GCM, sector identity as AAD** | BAD_TAG | BAD_TAG | still authenticates |
   | **AES-GCM + protected monotonic version** | BAD_TAG | BAD_TAG | STALE_VERSION |

   The interesting cell is the middle row's last one. An AEAD authenticates a
   ciphertext; it does not provide freshness, and RFC 5116 §1.1 says so in as
   many words. A whole old record replayed at its own sector number
   authenticates perfectly. A checkbox on that panel hands the version store to
   the attacker as well, and stage three falls straight back to stage two —
   because "protected" is load-bearing, and a panel that ended on a clean win
   would be lying.

## When to Use It

- **Use XTS** when you are encrypting a block device in place, the data unit is
  a fixed-size sector, and there is genuinely nowhere to store per-sector
  metadata. It is the right answer to that constraint and it is a good one:
  position-bound, zero-expansion, parallel, seekable.
- **Use it alongside something else** when the threat model includes an attacker
  who can *write* to the storage. dm-integrity, filesystem checksumming and T10
  Protection Information all exist because that combination is common.
- **Do NOT use XTS** as if it were authenticated encryption. It carries no tag,
  and there is no configuration, key size or library that adds one. If you need
  to know that stored data is unmodified and current, you need a tag, a nonce
  and a freshness anchor, and you need somewhere to put them.
- **Do NOT use this repository's code** for anything but learning.

## Live Demo

https://systemslibrarian.github.io/crypto-lab-sector-vault/

Write to a sector and watch its ciphertext change. Select a block and step the
tweak ladder through the GF(2¹²⁸) shift-and-reduce. Flip a bit and watch exactly
one block die while the failure-code list stays empty. Copy a block somewhere it
does not belong. Roll a sector back and get a clean read of stale data. Take two
disk images and read the diff with no key. Then open act 5 and hand the attacker
the version store.

## What Can Go Wrong

The attacks the page lets you run, and what each one costs in the real world:

- **Silent single-block modification.** One flipped ciphertext bit replaces
  sixteen plaintext bytes with unpredictable noise, and the read succeeds. On a
  filesystem that is a corrupted inode, a mangled config line, or — if the
  attacker knows the layout — sixteen bytes of a security decision replaced with
  bytes nobody chose. The attacker does not get to choose the result, but they
  do get to choose *where* it lands, and nothing reports it.
- **Relocation.** Ciphertext is bound to its position by the tweak, so moving it
  does not hand the attacker a chosen plaintext — it hands the reader different,
  wrong plaintext. That is a weaker attack than a chosen-plaintext swap and a
  much worse outcome than an error: the data is wrong and the system is content.
- **Rollback.** The one that survives an AEAD. Restoring an earlier ciphertext
  for a sector returns data that is authentic, correctly placed, internally
  consistent and out of date. Revoked credentials come back. A patched
  configuration un-patches itself. A balance returns to what it was.
- **Watermarking and change tracking.** Determinism per (sector, block index)
  means anyone holding two disk images learns which blocks changed and when,
  without a key. How much that costs depends entirely on what the plaintext is:
  a database index changing on a schedule leaks a great deal, a compressed
  archive almost nothing.
- **The nonce trap in the fix.** The obvious way to add GCM to a disk — use the
  sector number as the nonce — reuses one nonce under one key on every rewrite,
  which leaks the XOR of the plaintexts and the authentication subkey, after
  which forgery is possible. That is a worse failure than the one being fixed.
  See [Nonce Collision](https://systemslibrarian.github.io/crypto-lab-nonce-collision/)
  and [Nonce Guard](https://systemslibrarian.github.io/crypto-lab-nonce-guard/).
- **The trusted store in the fix.** A version counter only defeats rollback if
  the attacker cannot roll the counter back too. On a volume they fully control,
  it has to live in a TPM, a secure element, or a Merkle structure whose root is
  kept off the disk. Otherwise stage three has moved the rollback target, not
  removed it.
- **What this demo does NOT prove.** It shows no weakness in AES, and none in
  XTS as a confidentiality mode — XTS does what it claims. It does not show that
  any particular product is vulnerable; BitLocker, FileVault and LUKS all layer
  other mechanisms around the mode. It does not measure how hard these attacks
  are to mount. And it does not touch the distinguishing and
  plaintext-manipulation literature on XTS itself; the subject here is the
  absence of authentication, not the mode's malleability granularity.

## Real-World Usage

XTS-AES is what BitLocker (XTS-AES-128/256 since Windows 10), FileVault 2,
LUKS/dm-crypt (`aes-xts-plain64`, the default in cryptsetup), VeraCrypt, and
most cloud block-storage encryption use. NIST approved it in SP 800-38E in 2010,
scoped explicitly to storage devices, and the standard is unusually direct that
the mode "does not provide authentication of the data or its source".

That is a design choice with a cost, not an oversight — and it is not true that
nobody pays the cost. `dm-integrity` carries a per-sector tag underneath
dm-crypt; ZFS and Btrfs checksum at the block level; and T10 Protection
Information adds eight bytes of metadata per sector on enterprise SAS drives
precisely so that there is room. Each of those buys the metadata space
SP 800-38E assumes away.

## How to Run Locally

```bash
npm install
npm run dev          # http://localhost:5173/crypto-lab-sector-vault/
npm test             # unit + KAT suite (Vitest)
npm run build        # typecheck, then production build
npm run test:a11y    # WCAG 2.1 AA gate against the production build
npm run test:claims  # the claims suite: does the page tell the truth?
```

The a11y and claims suites need a browser once:
`npx playwright install chromium`.

## Related Demos

- **[Stream Ward](https://systemslibrarian.github.io/crypto-lab-stream-ward/)** —
  the same lesson in the streaming domain. Per-segment AEAD authenticates every
  frame perfectly while ordering, truncation and replay stay broken, until a
  chain state binds each segment to the ones before it. One-shot AEAD
  authenticates *content*; binding position, order or version is a separate job,
  and it always costs storage. Sector Vault is the storage-domain half of that
  pair, where the metadata room does not exist at all.
- **[AES Modes](https://systemslibrarian.github.io/crypto-lab-aes-modes/)** —
  ECB, CBC, CTR and GCM side by side, for what a mode of operation is before XTS
  specialises one for disks.
- **[Nonce Collision](https://systemslibrarian.github.io/crypto-lab-nonce-collision/)**
  and **[Nonce Guard](https://systemslibrarian.github.io/crypto-lab-nonce-guard/)** —
  what happens when the GCM nonce in act 5's fix is derived instead of stored.
- **[Padding Oracle](https://systemslibrarian.github.io/crypto-lab-padding-oracle/)** —
  the opposite failure: a mode that *does* report something, and reports too much.

## Build & Verify

`npm test` runs **119 unit tests** across 12 files. **26 of them are
known-answer tests against published vectors**, covering 16 vectors in total:

| Source | File | What is pinned |
|---|---|---|
| IEEE Std 1619-2007 Annex B / NIST SP 800-38E | `src/crypto/xts.test.ts` | Vectors 1, 2, 3 and 15–18 in full — including all four ciphertext-stealing lengths — plus vectors 4 (XTS-AES-128, 512 bytes) and 10 (XTS-AES-256, 512 bytes) by their published 32-byte prefix |
| FIPS-197 Appendix C | `src/crypto/aes-block.test.ts` | AES-128, AES-192 and AES-256 single-block encryption and decryption, so the borrowed primitive is checked before any mode vector is trusted |
| NIST SP 800-38D | `src/crypto/gcm.test.ts` | GCM test cases 2, 3, 4 and 14, so act 5's BAD_TAG results come from something demonstrably AES-GCM |

Beyond the stored vectors, `src/crypto/xts.cross.test.ts` runs an **independent
cross-implementation oracle**: OpenSSL's own `aes-128-xts` and `aes-256-xts`
through `node:crypto`, over thirteen data-unit lengths and random keys and
sequence numbers, both directions. That is what covers the 480 bytes of vectors
4 and 10 that this repository transcribes only a prefix of, and it is the check
that a from-scratch implementation agreeing with itself cannot give you.

`npm run test:a11y` runs the **WCAG 2.1 AA gate**: `@axe-core/playwright` over
the *production build*, driven through every state the lab paints — the arrival
state, the tweak ladder in both branches of the GF(2¹²⁸) reduction, a damaged
block cell, a corrupted sector tile, an `aria-invalid` refusal, a relocated
block, a stale read, the 512-cell watermark grid, act 5 with and without a
protected version store, all four disclosures open, four hover states and three
focus rings — at 1280px and 380px. It asserts axe's `incomplete` bucket as well
as `violations`, computes contrast arithmetically over composited backdrops,
measures non-text contrast per border side, and checks reflow, which axe has no
rule for. `e2e/nontext-baseline.ts` is **empty**, and that is the terminal state
of its ratchet rather than an unrun check.

`npm run test:claims` runs **22 tests that check the page tells the truth**,
built on independent re-derivation rather than internal agreement: the tweak
ladder is re-checked with BigInt shifts instead of the source's byte-at-a-time
carry chain, the damaged-block counter against an independent count of the cells
the page painted, the storage overhead against the byte counts printed beside
it, and the failure-code inventory against a read-out that names the same codes
in entirely different markup.

**The negative claim is a fixture, not a disclaimer.** Five of those claims
tests drive the page into a state where every check XTS actually performs — key
length and data-unit length, both really executed against the real key and the
real stored bytes — reports success, and the data is wrong anyway. They assert
that the fixture is reachable through the UI, that every rendered check verdict
in it is green (enumerated from what the page painted, not from a flag the test
sets), that the two checks the mode does NOT have are rendered as absences
rather than quietly omitted, and that the claim itself is on screen in that
state: visible, inside the panel that demonstrates it, not behind a disclosure
and not only in this README. It retires with its fixture — repair the sector and
the claim is gone.

Every one of those suites was **mutation-tested**: seven separate inversions in
the source — the reduction condition, the α ladder, the rollback classification,
the stage-two rollback outcome, the block-cell fill rule, the negative claim's
own rendering, and a check inside its fixture — each with the build succeeding
and the bundle hash changing, and each confirmed to make the owning test fail by
name. Three of those runs exposed real gaps, which were fixed rather than
explained: a page-level check that only ever inspected block 0 (where α⁰ is the
identity, so a broken ladder was invisible), an O(n²) test that timed out under
load, and two unreachable failure branches in the check inventory, which were
made reachable and tested rather than deleted or left dead.

## Performance

Everything runs in the browser on 8 KB of data, so there is nothing to tune. The
whole volume is 16 × 512 bytes = 512 AES blocks; encrypting or decrypting a
sector is 32 block operations plus 32 GF(2¹²⁸) doublings, and the page
re-decrypts every sector on every render without a measurable pause. Act 5 is
the slowest thing here, and it is slow only in the sense that it awaits nine
real WebCrypto operations before painting — which is why the gate waits on its
table rather than on a timer.

---

*One of the browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
