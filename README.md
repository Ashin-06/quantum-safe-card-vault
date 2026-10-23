# Card Vault (`pqcpayment`)

A model of a card-data vault with four parts:

1. **Format-preserving tokens** (`fpe.py`): FF1 from NIST SP 800-38G Rev. 1, using AES-256. It turns a 16-digit card number into a 16-digit token that has the same BIN and a valid Luhn check digit.
2. **PAN envelopes** (`pqc_kem.py`): each card number is sealed with AES-256-GCM. The AES key comes from a hybrid KEM: a hand-written Module-LWE KEM combined with X25519.
3. **Per-transaction keys** (`hsm.py`): DUKPT-style derivation from a base derivation key and a key serial number.
4. **Key rotation and audit** (`hsm.py`): moving to a new key epoch re-wraps every record and keeps earlier tokens resolving. An HMAC-chained log records every operation.

> **Reference implementation, not reviewed, not for real card data.**
> - FF1 is written here in Python (checked against the NIST sample vectors).
> - The lattice KEM is **not ML-KEM** and its security hasn't been analysed.
> - Keys live in process memory, despite the class name `QuantumSafeHSMVault`.
> - Nothing here is constant-time.

## How it works

**FF1** (`FF1`) follows Algorithms 7 and 8 of SP 800-38G Rev. 1: a 10-round Feistel network with an AES CBC-MAC round function. It supports radix 2–36. It matches all nine NIST FF1 sample vectors (AES-128/192/256, radix 10 and 36, with and without a tweak), and the test suite checks them. It refuses domains below the standard's minimum, radix^n ≥ 10⁶.

**Tokens** (`FF1Radix10Cipher`) work like this:
- The 9 digits between the 6-digit BIN and the check digit are encrypted with FF1 under the tweak `BIN:<bin>|TWEAK:EPOCH:<e>|MERCH:<merchant>`.
- The Luhn check digit is then recomputed.
- For a fixed BIN, merchant and epoch, this is a permutation of the 10⁹ possible numbers. Decryption is exact, and two cards never share a token under the same merchant and epoch.

**Hybrid KEM.**

The lattice half reuses ML-KEM's ring R_q = Z₃₃₂₉[X]/(X²⁵⁶+1), with rank 2, CBD noise η = 2, and a Fujisaki–Okamoto transform with re-encryption and implicit rejection. It has no NTT, no ciphertext compression and its own encodings, so:
- FIPS 203 test vectors don't apply;
- it doesn't interoperate with ML-KEM;
- the ciphertext is 1,536 bytes, compared with 768 bytes for ML-KEM-512.

The X25519 half comes from `cryptography`. The two shared secrets go through HKDF-SHA256, together with the X25519 ephemeral and recipient public keys (in the style of X-Wing, not the X-Wing spec).

**Vault.**
- `tokenize` derives a DUKPT-style transaction key, makes the FF1 token, and seals `{pan, merchant, ksn, epoch}` in a KEM + AES-GCM envelope. The AAD binds the epoch, merchant and KSN.
- Records are indexed by (merchant, token).
- `detokenize` only answers for tokens on record for that merchant. It returns the PAN from the envelope, and for current tokens it also checks that the FF1 inverse gives the same PAN.
- `rotate_epoch` creates fresh random keys, re-tokenizes and re-wraps every record, and keeps each old token as a legacy alias.
- Without a test seed, every epoch's keys come from `os.urandom`.

## Results

`python -m pqcpayment bench`, which checks the code's own invariants on generated card numbers:

| Check | Result |
|---|---|
| FF1 vs NIST SP 800-38G samples (in the tests) | 9/9 |
| 1,000 generated PANs, 3 BINs: distinct tokens, exact decryption, Luhn-valid, BIN kept | 1,000/1,000 each |
| FF1 time per card (one core, Python) | ~0.12 ms |
| hybrid KEM round trips that agree | 50/50; ~2.5 ms per trial (1 encapsulation + 2 decapsulations); 1,568-byte ciphertext |
| one-bit flips in the lattice ciphertext rejected | 50/50 |
| 12-card vault rotated: records re-wrapped, old tokens resolve, audit chain verifies | 12/12, yes |

These are consistency checks, not security results:
- FF1 is a permutation, so the token checks show only that the code isn't broken.
- Rejecting a flipped bit is a smoke test of the FO transform, not evidence of CCA security.

Problems fixed during the audit are in the git history. They include:
- a master seed hard-coded in the source, from which anyone could derive every key;
- detokenization that ignored which merchant was asking;
- a ciphertext-malleable KEM combiner;
- an unkeyed audit chain.

## Run it

```bash
pip install -r requirements.txt
python -m pytest -q                        # 22 tests
python -m pqcpayment bench
python -m pqcpayment serve --port 8020     # API + console at http://127.0.0.1:8020
```

Endpoints:
- `POST /tokenize`
- `POST /detokenize`
- `POST /kem/handshake`
- `POST /hsm/rotate`
- `GET /hsm/status`
- `GET /bench`
- `GET /health`

Set `PQCPAYMENT_API_KEY` to require it in the `X-API-Key` header (the console has a field for it). Without the key the server runs open, and `serve` refuses to bind a non-loopback address.

Requests are capped at 8 KB, fields are pattern-checked, and validation errors never echo the submitted card number.

## Limits

- **The lattice KEM is not post-quantum assurance.** Until it is replaced with ML-KEM-768 from a vetted library (liboqs, or OpenSSL 3.5+ / pyca `cryptography` once it exposes ML-KEM), treat the hybrid as no stronger than X25519.
- **No side-channel protection.** FF1, the lattice arithmetic and the comparisons run in Python and NumPy, with timing that depends on the data.
- **Not an HSM.** Every key is a Python `bytes` object in the server process: the KEM keys, FF1 keys, BDKs and the audit key. There is no key wrapping, no access control within the process and no destruction of retired keys, which are kept so that legacy tokens still resolve.
- **Tokens look like real cards.** They are Luhn-valid and carry the issuer's BIN. PCI SSC's tokenization guidelines expect a way to tell tokens apart from real PANs. Tokens are also deterministic: the same card at the same merchant and epoch always gets the same token, so token equality reveals card equality.
- **Only 6-digit BINs and 16-digit PANs.** Visa and Mastercard moved to 8-digit BINs in 2022. Encrypting digits 7–8 can change how a token routes.
- **FF1 domain size.** Each (BIN, merchant, epoch) domain has 10⁹ points. That is above NIST's 10⁶ floor, but format-preserving encryption on small domains is where the published attacks are, so it shouldn't be used on much smaller ones.
- **DUKPT is only modelled on X9.24.** It uses HMAC-SHA256 rather than X9.24-3's AES derivation and isn't compatible with it. One counter is shared by all terminals. The per-transaction MAC is stored but never verified. A leaked transaction key gives every key below it in the derivation tree.
- **Rotation is all-at-once.** It decrypts and re-wraps every record while holding the lock. Legacy tokens never expire.
- **The API trusts its caller.** There is one shared API key, with no per-merchant credentials, so anyone with the key can detokenize any merchant's tokens by naming the merchant. Everything is in memory, and the audit log grows without bound.
- **Not reviewed by a cryptographer or a PCI assessor.** A code audit does not make this suitable for card data.
