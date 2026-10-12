# EME2 research exhibit: construction and validation

The runnable exhibit implements the historical EME* / EME2 construction with
AES-128 or AES-256, independent 128-bit masks, byte-oriented associated data,
partial final blocks and mask renewal after every 128 full blocks. It is real
encryption/decryption, not a simulated diffusion display. **It is not a claim
of IEEE 1619.2-2025 conformance, production readiness or constant-time behavior.**

## Primary sources actually read

- Shai Halevi, [EME*: extending EME to handle arbitrary-length messages with
  associated data](https://eprint.iacr.org/2004/125), revision 27 May 2004,
  section 3, Figure 1. The AES key and masks correspond to K, L and R. The paper
  permits bit-oriented inputs; this exhibit only supports whole bytes.
  PDF retrieved from the public ePrint mirror at
  `https://eprint.iacr.asia/2004/125.pdf`; SHA-256:
  `b53f96cd449bfb231dad365cfb14f06df52e2fe6de84b98f61af1684971cbaf0`.
- [Archived IEEE P1619.2/D9](https://web.archive.org/web/20171018232831/http://siswg.net/index2.php?Itemid=41&gid=156&option=com_docman&task=doc_view),
  December 2008, section 5.2, Tables 1–3. Retrieved the archived working-group
  PDF, not the domain's current unrelated website. SHA-256:
  `469c733aa8046dca1405880b25fd035d4544deed7da39d9da4670a24e837e3aa`.
  This is an **unapproved historical draft**. Its EME2 vector section D.1 is
  still TBD. Byte-oriented partial blocks use 0x80 followed by zero bytes;
  multiplication by alpha uses little-endian field elements and reduction 0x87.
  The draft's decryption table contains an AES-Enc label where AES-Dec is
  required; the paper's inverse and the draft's accompanying note resolve it.
- [IEEE 1619.2-2025 public record](https://standards.ieee.org/ieee/1619.2/11949/),
  published 20 November 2025, active. This establishes current standardization
  status and confidentiality-only storage scope. The current normative text,
  requirements and official test vectors were **not** available for validation.
  Do not infer that the historical draft's details are unchanged in 2025.

## Keys and implementation limits

`createEme2Cipher` accepts named fields: `aes` = KAES, `ecbMask` = KECB/L,
`adMask` = KAD/R. The historical D9 serialized order is KAD | KECB | KAES.
The UI uses that order to partition 48 fresh random bytes for AES-128. The
masks are secret independent values, not AES keys used for extra derivations.

The core supports 16–8192 data bytes and 0–4096 AD bytes. These are deliberate
resource bounds for this exhibit, **not IEEE maximum lengths**. The UI compares
512 bytes, 513 bytes (partial block) and 2064 bytes (mask renewal at block 129).
For comparison, XTS uses the same AES-128 key and its independent tweak key
is the EME2 ECB mask. This facilitates a teaching comparison; it is not advice
to reuse keys across production modes. Nothing is stored or transmitted.

## Evidence and its limits

`src/crypto/eme2.test.ts` independently transcribes the paper using BigInt field
arithmetic and Node/OpenSSL AES. The browser engine uses byte-wise GF arithmetic
and noble AES. Cross-checks cover both AES key sizes, empty/full/partial AD,
one-block messages, all partial-byte boundary types represented by 17/31/33
bytes, sector lengths, 128-block mask renewal, and exhibit maximum lengths.
Both directions are checked against each other, not just self-round trips.

The six frozen fixtures in `tests/fixtures/eme2-rust-0.3.0.json` are published
**third-party self-generated regression vectors**, from
[`eme2` 0.3.0](https://docs.rs/crate/eme2/0.3.0/source/tests/kat/mod.rs),
source commit `9b607a8ecbf934861cc12bb6457a1b7f1f749559`. The fixture records
the source-file fingerprint. These are not official IEEE known-answer vectors.
Its unnamed draft extract is not treated as the normative standard. Its key
serialization KAES | KECB | KAD differs from D9; tests explicitly map named
components before comparing. Both browser code and independent reference match
the published ciphertexts. Fixture attribution/license is in
`tests/fixtures/eme2-rust-LICENSE-MIT.txt`.

Additional tests verify input/key isolation, determinism, malformed-input
limits, changed AD returning different plaintext without an authentication
error, fixed-sample whole-unit diffusion and exact recovery of old ciphertext.
The experiment tests use measured output blocks; they do not promise that
every block must change for every key/input. Browser tests drive every choice,
partial blocks, mask renewal, rekeying, source visibility and mobile reflow.

EME2 is length-preserving and deterministic at fixed key, AD and length.
There is no tag to fail. Bit changes and splices can corrupt more of the
plaintext, but an attacker who restores a valid old data unit under the same
AD gets that old plaintext back intact. Trusted version state and an
authenticated construction are separate lessons, preserved in Act 5.

## Remaining standards validation

To make an IEEE 1619.2-2025 conformance claim, obtain an authorized copy of the
current normative construction and its official vectors; compare key layout,
length/domain requirements, byte encoding, AD and partial-block handling,
mask-renewal boundaries and usage requirements. Add versioned official tests
for both encryption and decryption. Passing the historical and third-party
cross-checks above does not discharge that requirement.
