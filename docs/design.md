# Design

## FF1 tokens

`fpe.py` implements FF1 from NIST SP 800-38G Rev. 1 (Algorithms 7 and 8): a 10-round Feistel network with an AES CBC-MAC round function, for radix 2–36. It matches all nine NIST FF1 sample vectors (AES-128/192/256, radix 10 and 36, with and without a tweak), which the tests check. Domains below the standard's minimum (radix^n ≥ 10^6) are refused.

`FF1Radix10Cipher` encrypts the 9 digits between the 6-digit BIN and the check digit under the tweak `BIN:<bin>|TWEAK:EPOCH:<e>|MERCH:<merchant>`, then recomputes the Luhn check digit. For a fixed BIN, merchant and epoch this is a permutation of the 10^9 possible numbers, so decryption is exact and two cards never share a token.

## Hybrid key encapsulation

`pqc_kem.py` combines ML-KEM-768 (FIPS 203) with X25519, both from pyca `cryptography`. The ML-KEM public key is 1,184 bytes and its ciphertext 1,088 bytes. The two shared secrets go through HKDF-SHA256 together with the X25519 ephemeral and recipient public keys, salted with a hash of the recipient's full public key. This combiner follows the style of X-Wing but not its specification, so it doesn't interoperate with X-Wing and hasn't been reviewed.

ML-KEM decapsulation never fails: a tampered ciphertext gives an unrelated key, and the AES-GCM envelope then refuses to open.

## Vault

- `tokenize` derives a per-transaction key (DUKPT-style, from a base derivation key and key serial number), makes the FF1 token and seals `{pan, merchant, ksn, epoch}` with AES-256-GCM under a key from the hybrid KEM. The authenticated data binds the epoch, merchant and serial number.
- Records are indexed by (merchant, token).
- `detokenize` only answers for tokens on record for that merchant. It returns the card number from the envelope and, for current tokens, also checks that inverting FF1 gives the same number.
- `rotate_epoch` creates fresh random keys, re-tokenises and re-seals every record, and keeps each old token as an alias.
- Each epoch's keys (ML-KEM and X25519 private keys, FF1 key, base derivation key) are sealed with AES-256-GCM under the master key and stored with the records, so a restart or another replica sees the same vault.
- Every operation is written to an HMAC-chained audit log.

## Results

`python -m pqcpayment bench` checks the code's own invariants on generated card numbers:

| Check | Result |
|---|---|
| FF1 against the NIST SP 800-38G samples (in the tests) | 9 of 9 |
| 1,000 generated card numbers, 3 BINs: distinct tokens, exact decryption, valid Luhn digit, BIN kept | 1,000 of 1,000 each |
| FF1 time per card (one core, Python) | about 0.12–0.18 ms |
| hybrid key-exchange round trips that agree | 50 of 50; about 1.2 ms per trial; 1,120-byte ciphertext |
| one-bit flips in the ML-KEM ciphertext give a different key | 50 of 50 |
| 12-card vault rotated: records re-sealed, old tokens resolve, audit log verifies | 12 of 12, yes |

These are consistency checks, not security results. FF1 is a permutation, so the token checks only show the code isn't broken, and ML-KEM's security comes from the library rather than anything measured here.

## DUKPT

The per-transaction key derivation is only modelled on ANSI X9.24. It uses HMAC-SHA256 rather than X9.24-3's AES derivation and isn't compatible with it, one counter is shared by all terminals, and the per-transaction MAC is stored but not verified.
