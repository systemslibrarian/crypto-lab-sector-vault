4. Sector Vault

crypto-lab-sector-vault · ENCRYPTION

Thesis. A mode in wide use for disk encryption has no integrity check at all — and adding one turns out to fix less than you would expect.

Construction. XTS-AES per NIST SP 800-38E / IEEE 1619. Two keys: K1 for data, K2 for the tweak. Tweak T = AES-K2(sector) ⊗ α^j in GF(2¹²⁸) per 16-byte block; ciphertext stealing for partial final blocks. Use @noble/ciphers, which exposes AES-ECB — build XEX+CTS over a vetted single-block primitive rather than coercing WebCrypto AES-CBC with a zero IV. Verify against IEEE 1619 vectors before anything else ships.

Acts
The disk. A 16-sector volume. Write plaintext, inspect ciphertext, watch the tweak change per sector and per block index.
Bit flip. Flip one ciphertext bit. That 16-byte block decrypts to garbage. Every other block is perfect. No error is raised, because there is nothing to raise one with.
Relocation. Copy a ciphertext block to a different offset, or a whole sector to a different sector number. Do not call this "failing." XTS has no authentication and raises nothing — the tweak changed, so the block simply decrypts to different, wrong plaintext, silently. Label it CORRUPTED (UNDETECTED) everywhere it appears, including the comparison table in act 5. The distinction is the entire thesis of the lab, and describing position-binding as a failure smuggles in a detection event that does not exist. Then copy a sector back over itself from an earlier snapshot — that one decrypts perfectly and correctly, because nothing binds a version. Wrong data, no corruption, no signal at all.
Watermarking. XTS is deterministic per (sector, block index). Take two snapshots, diff the ciphertext, read off exactly which blocks changed and which reverted — no key required.
Three stages, not two — the real climax. Revision 3 said running acts 2–4 under AES-GCM produces BAD_TAG every time. That is false for rollback, and the false part is the interesting part. AEAD authenticates a ciphertext; it does not provide freshness. RFC 5116 is explicit that the AEAD interface does not address anti-replay. Build the comparison as three columns on one panel:
	Bit modification	Relocation	Rollback
XTS	CORRUPTED (UNDETECTED)	CORRUPTED (UNDETECTED) — tweak is position-bound	succeeds cleanly
GCM, sector identity as AAD	BAD_TAG	BAD_TAG	still authenticates
GCM + protected monotonic version	BAD_TAG	BAD_TAG	STALE_VERSION
Two things must be said honestly alongside it. First, the nonce. Using the sector number as the GCM nonce reuses a nonce under one key on every rewrite — a separate catastrophic failure, and the one Nonce Collision and Nonce Guard already teach. A fresh nonce per write must be stored, which is the data-expansion cost this act is about. Second, "protected" is load-bearing. The version counter has to be authenticated and held somewhere the attacker cannot roll back too, which in practice means a separate trusted store or a Merkle structure over the volume. Otherwise stage three has only moved the rollback target, and the panel should say so rather than ending on a clean win. Then show why XTS omits all of this: SP 800-38E's scope is storage devices where the sector is exactly 512 or 4096 bytes with nowhere to put a nonce or a tag, and the mode was written to avoid data expansion. Do not say nobody does this — dm-integrity, filesystem-level checksumming, and T10 Protection Information all provide the metadata room. It is a design choice with a cost. Cross-link: Stream Ward already teaches that per-segment AEAD authenticates every frame while ordering breaks until a chain state binds them. This is the same lesson in the storage domain, and the two READMEs should point at each other.

Negative claim (NEG-1). XTS-based confidentiality-only full-disk encryption does not detect adversarial modification or rollback. Pin it to XTS, not to full-disk encryption in general — Act 5 names integrity-enabled storage designs, and a NEG-1 that contradicts its own Act 5 is the exact overclaim this document keeps having to repair. Evidence: acts 2–4 report DECRYPTED — AND MODIFIED, with no failure code available, because the construction has none.

Failure codes. From XTS itself, deliberately almost empty: MALFORMED_SECTOR · KEY_LENGTH_INVALID. The comparison panel adds BAD_TAG (stages two and three) and STALE_VERSION (stage three only). The gaps in that table are the exhibit.

Repo description.

Browser demo: real XTS-AES over a 16-sector volume — flip a bit and it decrypts to different plaintext with no error. Then add AES-GCM and watch modification and relocation die on the tag while a rolled-back sector still authenticates perfectly.

Prior art. NIST SP 800-38E (cite specifically for the storage-device scope and the stated absence of authentication of data or source); IEEE 1619-2007; Rogaway's XEX.