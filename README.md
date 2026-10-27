# Card Vault (`pqcpayment`)

A model of a card-data vault with four parts:

1. **Format-preserving tokens** (`fpe.py`): FF1 from NIST SP 800-38G Rev. 1, using AES-256. It turns a 16-digit card number into a 16-digit token that has the same BIN and a valid Luhn check digit.
2. **PAN envelopes** (`pqc_kem.py`): each card number is sealed with AES-256-GCM. The AES key comes from a hybrid KEM: ML-KEM-768 (FIPS 203) combined with X25519, both from pyca `cryptography`.
3. **Per-transaction keys** (`hsm.py`): DUKPT-style derivation from a base derivation key and a key serial number.
4. **Key rotation and audit** (`hsm.py`): moving to a new key epoch re-wraps every record and keeps earlier tokens resolving. An HMAC-chained log records every operation. Records, tokens, the log and every epoch's keys are kept in a database, the keys sealed under a master key.

> **Reference implementation, not reviewed, not for real card data.**
> - FF1 is written here in Python (checked against the NIST sample vectors).
> - ML-KEM-768 and X25519 are the library's, but the combiner that joins them is written here and is not the X-Wing spec.
> - Keys are sealed at rest, but used in process memory, despite the class name `QuantumSafeHSMVault`.
> - Nothing here is constant-time. In production mode the service logs a warning saying all this.

## How it works

**FF1** (`FF1`) follows Algorithms 7 and 8 of SP 800-38G Rev. 1: a 10-round Feistel network with an AES CBC-MAC round function. It supports radix 2–36. It matches all nine NIST FF1 sample vectors (AES-128/192/256, radix 10 and 36, with and without a tweak), and the test suite checks them. It refuses domains below the standard's minimum, radix^n ≥ 10⁶.

**Tokens** (`FF1Radix10Cipher`) work like this:
- The 9 digits between the 6-digit BIN and the check digit are encrypted with FF1 under the tweak `BIN:<bin>|TWEAK:EPOCH:<e>|MERCH:<merchant>`.
- The Luhn check digit is then recomputed.
- For a fixed BIN, merchant and epoch, this is a permutation of the 10⁹ possible numbers. Decryption is exact, and two cards never share a token under the same merchant and epoch.

**Hybrid KEM.**

The post-quantum half is ML-KEM-768 (FIPS 203) from pyca `cryptography` 50: 1,184-byte public key, 1,088-byte ciphertext. The X25519 half also comes from `cryptography`. The two shared secrets go through HKDF-SHA256, together with the X25519 ephemeral and recipient public keys, salted with a hash of the recipient's whole public key. That combiner is in the style of X-Wing, not the X-Wing spec, so it doesn't interoperate with X-Wing and hasn't been reviewed.

ML-KEM decapsulation never fails: a tampered ciphertext gives an unrelated key (implicit rejection), and the AES-GCM envelope then refuses to open.

Until 1.0.0 the post-quantum half was a hand-written Module-LWE KEM that was not ML-KEM; it is gone.

**Vault.**
- `tokenize` derives a DUKPT-style transaction key, makes the FF1 token, and seals `{pan, merchant, ksn, epoch}` in a KEM + AES-GCM envelope. The AAD binds the epoch, merchant and KSN.
- Records are indexed by (merchant, token).
- `detokenize` only answers for tokens on record for that merchant. It returns the PAN from the envelope, and for current tokens it also checks that the FF1 inverse gives the same PAN.
- `rotate_epoch` creates fresh random keys, re-tokenizes and re-wraps every record, and keeps each old token as a legacy alias.
- Without a test seed, every epoch's keys come from `os.urandom`.
- Each epoch's keys (ML-KEM and X25519 private keys, FF1 key, BDK) are sealed with AES-256-GCM under the master key and stored with the records, so a restart or another replica sees the same vault.

## Results

`python -m pqcpayment bench`, which checks the code's own invariants on generated card numbers:

| Check | Result |
|---|---|
| FF1 vs NIST SP 800-38G samples (in the tests) | 9/9 |
| 1,000 generated PANs, 3 BINs: distinct tokens, exact decryption, Luhn-valid, BIN kept | 1,000/1,000 each |
| FF1 time per card (one core, Python) | ~0.12–0.18 ms (varies with machine load) |
| hybrid KEM round trips that agree | 50/50; ~1.2 ms per trial (1 encapsulation + 2 decapsulations); 1,120-byte ciphertext |
| one-bit flips in the ML-KEM ciphertext give a different key | 50/50 |
| 12-card vault rotated: records re-wrapped, old tokens resolve, audit chain verifies | 12/12, yes |

These are consistency checks, not security results:
- FF1 is a permutation, so the token checks show only that the code isn't broken.
- A flipped bit giving a different key shows the wiring is right; ML-KEM's security is the library's, not something this benchmark measures.
- The KEM numbers were re-run for 1.0.0 (before it, with the hand-written lattice KEM: ~2.5 ms per trial, 1,568-byte ciphertext).

Problems fixed during the audit are in the git history. They include:
- a master seed hard-coded in the source, from which anyone could derive every key;
- detokenization that ignored which merchant was asking;
- a ciphertext-malleable KEM combiner;
- an unkeyed audit chain.

## Run it

```bash
pip install -r requirements-dev.lock && pip install -e .
python -m pytest -q                        # 49 tests
python -m pqcpayment bench
python -m pqcpayment serve                 # API + console at http://127.0.0.1:8020
```

Endpoints:
- `POST /tokenize`
- `POST /detokenize`
- `POST /kem/handshake`
- `POST /hsm/rotate`
- `GET /hsm/status`
- `GET /bench`
- `GET /healthz`, `GET /readyz`, `GET /metrics`

**Settings and access.** The service reads `PQCPAYMENT_*` environment variables (see `docs/runbook.md`). Callers send an API key in `X-API-Key` (the console has a field for it) or `Authorization: Bearer`. Each key has a role:
- `merchant`: its user name is its merchant ID, and it can only tokenize and detokenize for that merchant;
- `payments_ops`: tokenize and detokenize for any merchant;
- `key_custodian`: rotate keys, read status, run the KEM demo;
- `auditor`: status and the audit log;
- `monitor`: metrics;
- `admin`: everything, plus `/bench`.

`python -m pqcpayment.ops keygen` makes a key and the hash to configure, plus a master key and an audit key. Without keys the service runs open in development and refuses to listen on anything but loopback. `PQCPAYMENT_ENV=production` refuses to start without hashed keys, `PQCPAYMENT_MASTER_KEY` (seals every epoch's keys), `PQCPAYMENT_AUDIT_KEY` and a database.

**State.** Records, the token index, the audit chain and the sealed epoch keys are kept in SQLite or Postgres (`PQCPAYMENT_DATABASE_URL`). `/readyz` also checks that the epoch keys unseal under the configured master key.

Requests are capped at 8 KB, fields are pattern-checked, and validation errors never echo the submitted card number.

**Docker.**

```bash
docker build -t quantum-safe-card-vault:1.0.0 .
docker run -d -p 8020:8020 -v pqcpayment-data:/data -e PQCPAYMENT_API_KEYS='{"sha256:...": {"user": "ops", "role": "admin"}}' -e PQCPAYMENT_MASTER_KEY=... -e PQCPAYMENT_AUDIT_KEY=... quantum-safe-card-vault:1.0.0
```

The image runs in production mode as a non-root user. Run without keys it exits with a configuration error.

## Limits

- **The KEM combiner is not reviewed.** ML-KEM-768 and X25519 are pyca `cryptography`'s, but the HKDF combiner joining them is written here and is not the X-Wing spec.
- **No side-channel protection.** FF1, the DUKPT-style derivation and the comparisons run in Python, with timing that depends on the data. (ML-KEM and X25519 are the library's.)
- **Not an HSM.** Keys are sealed at rest under a master key that comes from an environment variable, and every key is a Python `bytes` object in the server process while it is used. There is no access control within the process and no destruction of retired keys.
- **Tokens look like real cards.** They are Luhn-valid and carry the issuer's BIN. PCI SSC's tokenization guidelines expect a way to tell tokens apart from real PANs. Tokens are also deterministic: the same card at the same merchant and epoch always gets the same token, so token equality reveals card equality.
- **Only 6-digit BINs and 16-digit PANs.** Visa and Mastercard moved to 8-digit BINs in 2022. Encrypting digits 7–8 can change how a token routes.
- **FF1 domain size.** Each (BIN, merchant, epoch) domain has 10⁹ points. That is above NIST's 10⁶ floor, but format-preserving encryption on small domains is where the published attacks are, so it shouldn't be used on much smaller ones.
- **DUKPT is only modelled on X9.24.** It uses HMAC-SHA256 rather than X9.24-3's AES derivation and isn't compatible with it. One counter is shared by all terminals. The per-transaction MAC is stored but never verified. A leaked transaction key gives every key below it in the derivation tree.
- **Rotation is all-at-once.** It decrypts and re-wraps every record in one database transaction. Legacy tokens never expire. Rotating the master key doesn't re-seal older epochs.
- **`payments_ops` and `admin` keys can read every merchant's cards.** Merchant keys are scoped to their merchant, but there is no per-user authentication behind a key. The audit log grows without bound, and verifying it walks the whole chain.
- **Not reviewed by a cryptographer or a PCI assessor.** A code audit does not make this suitable for card data.

## Production readiness

In place (1.0.0):
- ML-KEM-768 from a vetted library in place of the hand-written lattice KEM.
- Settings checked at startup; production refuses to start without hashed API keys, the master and audit keys and a database, and never listens publicly without keys.
- API keys with roles and merchant scoping, per-client rate limit, request body cap, security headers, CORS only for listed origins, errors and logs that never contain a PAN.
- The vault in a database with migrations; epoch keys sealed under a master key; master- and audit-key rotation; replicas share one vault.
- JSON logs with request IDs, `/healthz`, `/readyz` (including key unsealing), Prometheus `/metrics`.
- Pinned dependency locks, a non-root container image with a health check, CI running ruff, bandit, pip-audit and the tests.
- `SECURITY.md`, `docs/threat-model.md`, `docs/runbook.md`.

Still needed before real use:
- PCI DSS assessment and sign-off by a QSA (and PCI SSC tokenization guidance: tokens distinguishable from PANs), RBI card-tokenization rules and DPDP Act 2023 sign-off.
- A cryptographer's review of FF1, the DUKPT-style derivation and the KEM combiner (or a switch to the X-Wing spec and X9.24-3 AES DUKPT); constant-time implementations.
- An HSM or KMS for the master key and the epoch keys, instead of environment variables and process memory.
- An independent security review and penetration test.
- Validation with the bank's own BIN ranges (8-digit BINs, other PAN lengths) and transaction volumes.
- Real integrations: card networks, acquirers and terminals with genuine DUKPT.
- An on-call team, SLOs and alerting wired to the metrics above.
