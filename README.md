# 20 — Quantum-Safe Card Vault (`pqcpayment`)

**Post-Quantum Hybrid Lattice-KEM Payment Vault, Bijective Luhn-Preserving Format-Preserving Encryption (FF1-Feistel) & Zero-Downtime HSM Key Rotation Engine.**

---

## Architecture & Cryptographic Primitives

1. **Bijective Luhn-Preserving Format-Preserving Encryption (`pqcpayment/fpe.py`)**
   - Preserves the 6-digit issuer BIN (`pan[:6]`) so payment routing across legacy ISO 8583 switches (Visa, Mastercard, RuPay) remains 100% transparent.
   - Encrypts the middle 9 account digits (`pan[6:15]`) bijectively via a **10-round Luby-Rackoff Alternating Feistel Network** over $\mathbb{Z}_{10^4} \times \mathbb{Z}_{10^5}$ keyed by AES-256 + HMAC-SHA256 with a domain-separated BIN and merchant/epoch `tweak`.
   - Recomputes the 16th digit via the ISO/IEC 7812-1 Luhn algorithm. Because every input PAN is Luhn-valid, its 16th digit is a deterministic function of its first 15 digits (`pan[15] = Luhn(pan[:15])`), yielding a **100% collision-free bijection** where every token is also 100% Luhn-valid.

2. **Hybrid Module-LWE + Classical X25519 Key Encapsulation (`pqcpayment/pqc_kem.py`)**
   - Implements negacyclic polynomial ring arithmetic in $R_q = \mathbb{Z}_q[X]/(X^n + 1)$ with **NIST FIPS 203 (ML-KEM) prime $q = 3329$, degree $n = 256$, module rank $k = 2$, and centered binomial noise $\eta = 2$**.
   - Enforces **IND-CCA2 security** via the **Fujisaki-Okamoto (FO)** deterministic re-encryption transform and implicit rejection (`SHAKE-256(z || H(ct))`) whenever a tampered ciphertext is detected.
   - Combines the post-quantum Module-LWE shared secret with classical `X25519` ECDH via `HKDF-SHA256(ss_lwe || ss_x25519 || SHA256(pk))`.

3. **Crypto-Agile HSM Vault, DUKPT & Zero-Downtime Key Rotation (`pqcpayment/hsm.py`)**
   - Derives unique per-transaction keys from a Base Derivation Key (BDK) and 80-bit Key Serial Number (KSN) across a 21-bit non-reversible binary counter tree (ANSI X9.24 DUKPT).
   - Supports **Zero-Downtime Epoch Key Rotation** (`rotate_epoch()`), re-wrapping vault envelopes from Epoch $E$ to Epoch $E+1$ while preserving backward-compatible detokenization for in-flight Epoch $E$ tokens and maintaining a **SHA-256 hash-chained audit log**.

---

## Quick Start

```bash
# Run the test suite
python -m pytest -q

# Run the 1,000-PAN + Hybrid PQC-KEM verification benchmark
python -m pqcpayment bench

# Launch the FastAPI server and interactive web console on port 8020
python -m pqcpayment serve --port 8020
```
