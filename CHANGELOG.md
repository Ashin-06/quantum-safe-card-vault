# Changelog

All notable changes to this project. Versions follow [semantic versioning](https://semver.org/).

## 1.0.0 — 2026-10-27

### Added
- `pyproject.toml` with a `pqcpayment` console command, and pinned `requirements.lock` /
  `requirements-dev.lock` (generated with `uv pip compile --universal`).
- Container image: slim Python 3.12 base, non-root user, health check on `/healthz`.
- CI on every push: ruff, bandit, pip-audit, pytest with a coverage report.
- Settings from `PQCPAYMENT_*` environment variables, checked at startup.
  `PQCPAYMENT_ENV=production` refuses to start without hashed API keys, `PQCPAYMENT_MASTER_KEY`,
  `PQCPAYMENT_AUDIT_KEY` and `PQCPAYMENT_DATABASE_URL`. No built-in secrets in any mode.
- Roles on API keys: `merchant` (tokenize and detokenize for its own merchant ID only),
  `payments_ops` (any merchant), `key_custodian` (rotation, status, KEM demo), `auditor` (status
  and audit log), `monitor` (metrics), `admin`. Keys can be stored as `sha256:<hex>`;
  `python -m pqcpayment.ops keygen` makes new ones.
- Per-client rate limit, request body cap (chunked bodies now counted instead of refused),
  security headers, CORS only for listed origins.
- JSON logs with request IDs; `/healthz`, `/readyz` (database reachable and epoch keys unseal) and
  Prometheus `/metrics` (`pqcpayment_decisions_total`).
- The vault in a database: SQLite by default, Postgres through `PQCPAYMENT_DATABASE_URL`, numbered
  SQL migrations (`python -m pqcpayment migrate`). Records, the token index, the audit chain and
  every epoch's keys survive restarts and are shared by replicas.
- Epoch keys sealed at rest with AES-256-GCM under `PQCPAYMENT_MASTER_KEY`; master and audit keys
  rotate with `*_PREVIOUS`.
- A warning, logged at startup in production, that FF1, the DUKPT derivation and the KEM combiner
  are unreviewed.
- `SECURITY.md`, `docs/threat-model.md`, `docs/runbook.md`.

### Changed
- **The lattice half of the hybrid KEM is ML-KEM-768 (FIPS 203) from pyca `cryptography` 50.** The
  hand-written Module-LWE KEM is removed, and so is numpy. Envelopes made by earlier versions can't
  be opened. ML-KEM decapsulation never fails, so `/kem/handshake` no longer reports `cca2_valid` /
  `cca2_rejected`; a tampered ciphertext shows as `shared_secrets_match: false`.
- `PQCPAYMENT_API_KEY` (one shared key that could read every merchant's cards) is replaced by
  `PQCPAYMENT_API_KEYS` with roles and merchant scoping. Without keys the service refuses to listen
  on anything but loopback.
- `/health` is replaced by `/healthz` and `/readyz`. `/bench` needs the admin role.

### Benchmark (re-run)
- `python -m pqcpayment bench`: hybrid KEM 50/50 round trips agree and 50/50 one-bit flips in the
  ML-KEM ciphertext give a different key, about 1.2 ms per trial (one encapsulation, two
  decapsulations), 1,120-byte hybrid ciphertext (was 1,568 bytes and about 2.5 ms with the
  hand-written KEM). FF1, token and rotation checks unchanged: 1,000/1,000 and 12/12.
