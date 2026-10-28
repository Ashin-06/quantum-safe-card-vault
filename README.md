# Card Vault

A vault for card numbers. Merchants get tokens that look like card numbers, so their systems keep working, while the real numbers are stored encrypted in a way meant to stay safe against future quantum computers.

## Features

- Format-preserving tokens with FF1 (NIST SP 800-38G): a 16-digit card number becomes a 16-digit token with the same BIN and a valid check digit.
- Each card number is sealed with AES-256-GCM under a key agreed with ML-KEM-768 (FIPS 203) combined with X25519, both from pyca `cryptography`.
- A separate key for every transaction, derived DUKPT-style.
- Key rotation that re-seals every record while old tokens keep working.
- Tokens are scoped to a merchant: a merchant's key can only look up its own tokens.
- An HMAC-chained audit log of every operation, and all keys sealed at rest under a master key.

How FF1, the key exchange and the vault work is described in [docs/design.md](docs/design.md).

## Quick start

```bash
pip install -r requirements-dev.lock && pip install -e .
python -m pytest -q                        # 49 tests
python -m pqcpayment bench
python -m pqcpayment serve                 # API and console on http://127.0.0.1:8020
```

To run it in a container:

```bash
docker build -t quantum-safe-card-vault .
python -m pqcpayment.ops keygen            # prints an API key, its hash, a master key and an audit key
docker run -d -p 8020:8020 -v pqcpayment-data:/data -e PQCPAYMENT_API_KEYS='{"sha256:...": {"user": "ops", "role": "admin"}}' \
  -e PQCPAYMENT_MASTER_KEY=... -e PQCPAYMENT_AUDIT_KEY=... quantum-safe-card-vault
```

## API

| Endpoint | Purpose |
|---|---|
| `POST /tokenize` | turn a card number into a token for a merchant |
| `POST /detokenize` | get the card number back for a token |
| `POST /hsm/rotate` | move to new keys |
| `GET /hsm/status` | key epoch and vault status |
| `POST /kem/handshake` | key-exchange demo |
| `GET /bench` | the benchmark |
| `GET /healthz`, `/readyz`, `/metrics` | health, readiness (including key unsealing) and Prometheus metrics |

API keys carry a role:
- `merchant`: its user name is its merchant ID, and it can only tokenise and detokenise for that merchant;
- `payments_ops`: tokenise and detokenise for any merchant;
- `key_custodian`: rotate keys and read status;
- `auditor`: status and the audit log;
- `monitor`: metrics;
- `admin`: everything.

Requests are capped at 8 KB, and errors never echo the submitted card number.

## Results

| Check | Result |
|---|---|
| FF1 against NIST's published test vectors | 9 of 9 |
| 1,000 generated card numbers: unique tokens, exact round trip, valid check digit, BIN kept | all 1,000 |
| Hybrid key exchange round trips | 50 of 50, about 1.2 ms each |
| Key rotation: records re-sealed, old tokens resolve, audit log verifies | yes |

These are correctness checks on generated card numbers, not security results. More detail is in [docs/design.md](docs/design.md).

## Configuration

| Variable | Purpose |
|---|---|
| `PQCPAYMENT_ENV=production` | refuse to start without hashed API keys, the master and audit keys and a database |
| `PQCPAYMENT_MASTER_KEY` | seals every epoch's keys |
| `PQCPAYMENT_AUDIT_KEY` | HMAC key for the audit log |
| `PQCPAYMENT_API_KEYS` / `PQCPAYMENT_KEYS_FILE` | hashed API keys with roles |
| `PQCPAYMENT_DATABASE_URL` | `sqlite:///...` or `postgresql://...` |

## Limitations

- FF1, the per-transaction key derivation and the code that combines ML-KEM with X25519 are written in this project and have not been reviewed by a cryptographer; nothing written here is constant-time.
- It is not an HSM. Keys are sealed at rest under a master key from an environment variable and sit in process memory while in use.
- Tokens look like real cards (valid check digit, real BIN), while PCI guidance expects tokens to be distinguishable. Tokens are also deterministic per card, merchant and epoch.
- Only 6-digit BINs and 16-digit card numbers are supported; Visa and Mastercard moved to 8-digit BINs in 2022.
- Rotation re-seals everything in one transaction, and old tokens never expire.
- `payments_ops` and `admin` keys can read every merchant's cards.
- It needs a PCI DSS assessment and an independent security review before it holds real card data.

See [SECURITY.md](SECURITY.md) and [docs/threat-model.md](docs/threat-model.md).
