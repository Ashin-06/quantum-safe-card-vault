# Runbook

How to deploy, configure and operate the card vault. Commands assume the repository root.
**Test card numbers only**: this vault has not been assessed against PCI DSS.

## Deploy

```bash
docker build -t quantum-safe-card-vault:1.0.0 .
python -m pqcpayment.ops keygen          # one API key per client, plus the master and audit keys
docker run -d --name pqcpayment -p 8020:8020 -v pqcpayment-data:/data \
  -e PQCPAYMENT_KEYS_FILE=/run/secrets/pqcpayment-keys.json \
  -e PQCPAYMENT_MASTER_KEY=... -e PQCPAYMENT_AUDIT_KEY=... \
  quantum-safe-card-vault:1.0.0
curl -fsS http://127.0.0.1:8020/readyz
```

The image runs in production mode as a non-root user and keeps its SQLite database in the `/data`
volume. On an empty database it creates epoch 1. It refuses to start, and logs why, when anything
required is missing; it also logs a warning that FF1, the DUKPT derivation and the KEM combiner are
unreviewed, which is expected. Terminate TLS in front of it.

For more than one replica, use Postgres (`PQCPAYMENT_DATABASE_URL=postgresql://user:pass@host/db`),
give every replica the same master and audit keys, and put a shared rate limiter at the ingress.

Without Docker: `pip install -r requirements.lock && pip install -e .`, then `pqcpayment serve`.

## Configure

| Variable | Required in production | Meaning |
|---|---|---|
| `PQCPAYMENT_ENV` | — | `development` (default) or `production` |
| `PQCPAYMENT_API_KEYS` / `PQCPAYMENT_KEYS_FILE` | yes | JSON `{"sha256:<hex>": {"user": "...", "role": "..."}}`. Roles: `merchant` (user = its merchant ID; tokenize/detokenize for that merchant only), `payments_ops` (any merchant), `key_custodian` (`/hsm/rotate`, `/hsm/status`, `/kem/handshake`), `auditor` (`/hsm/status`), `monitor` (`/metrics`), `admin` (all, plus `/bench`) |
| `PQCPAYMENT_MASTER_KEY` | yes | base64 AES-256 key, exactly 32 bytes; seals every epoch's keys |
| `PQCPAYMENT_AUDIT_KEY` | yes | base64, at least 32 bytes; HMAC key for the audit chain |
| `PQCPAYMENT_MASTER_KEY_PREVIOUS`, `PQCPAYMENT_AUDIT_KEY_PREVIOUS` | — | comma-separated older keys still accepted for reading and verifying |
| `PQCPAYMENT_DATABASE_URL` | yes | `sqlite:////data/pqcpayment.db` or `postgresql://...` (default in development: in memory) |
| `PQCPAYMENT_HOST`, `PQCPAYMENT_PORT` | — | default `127.0.0.1:8020`; any non-loopback address needs API keys |
| `PQCPAYMENT_RATE_LIMIT` | — | requests per minute per client (default 120) |
| `PQCPAYMENT_MAX_BODY_BYTES` | — | default 8,000 |
| `PQCPAYMENT_CORS_ORIGINS` | — | comma-separated origins allowed to call from a browser; none by default |
| `PQCPAYMENT_LOG_LEVEL` | — | default `INFO` |
| `FORWARDED_ALLOW_IPS` | — | addresses of proxies whose `X-Forwarded-For` is trusted (uvicorn) |

## Watch

- `GET /healthz`: the process is up (used by the container health check).
- `GET /readyz`: database reachable and every epoch's keys unseal under the configured master
  key(s); 503 otherwise.
- `GET /metrics` (role `monitor`): `http_requests_total`, `http_request_duration_seconds`,
  `errors_total`, `pqcpayment_decisions_total{decision="tokenized|detokenized|detokenize_refused|rotated"}`.
- `GET /hsm/status` (role `auditor`): epochs, DUKPT counter, record count, audit chain verification
  and the last 10 audit entries.
- Logs are one JSON object per line on stdout with a `request_id`; they never contain PANs.

Suggested alerts: `/readyz` failing for 2 minutes; `errors_total{kind="unhandled"}` increasing;
`audit_chain.valid` false; a rise in `detokenize_refused` (someone probing tokens); detokenizations
per merchant far above normal; the DUKPT counter in `/hsm/status` approaching 2,097,151 (rotate).

## Rotate keys

**Epoch keys** (KEM, FF1, BDK): `POST /hsm/rotate` (role `key_custodian`). Every record is
re-tokenized and re-wrapped in one transaction; old tokens keep resolving as legacy aliases. Do it
in a quiet period: the vault is busy for the duration.

**Master key.** Set `PQCPAYMENT_MASTER_KEY_PREVIOUS` to the current key and `PQCPAYMENT_MASTER_KEY`
to a new one, restart, then rotate the epoch keys once: the new epoch is sealed with the new master
key and every record is re-wrapped under it. Older epochs stay sealed with the old master key (they
are not re-sealed), and `/readyz` checks that every epoch unseals, so keep the old key in `_PREVIOUS`.
Re-sealing old epochs under the new key is not implemented.

**Audit key.** Same pattern with `PQCPAYMENT_AUDIT_KEY_PREVIOUS`. Keep old audit keys for as long as
you keep the entries they signed, or verification fails.

**API keys.** Add the new hash to the key file, restart, give the client the new key, then remove
the old hash and restart again.

## Back up and restore

SQLite (in the `/data` volume):

```bash
docker exec pqcpayment python -c "import sqlite3; s=sqlite3.connect('/data/pqcpayment.db'); d=sqlite3.connect('/data/backup.db'); s.backup(d)"
docker cp pqcpayment:/data/backup.db ./pqcpayment-$(date +%F).db
```

Restore: stop the container, copy the backup to `/data/pqcpayment.db` in the volume, start it, check
`/readyz` and `/hsm/status` (`audit_chain.valid: true`). Tokens issued after the backup no longer
resolve.

Postgres: `pg_dump` / `pg_restore` as usual. Migrations are applied automatically on start, or with
`python -m pqcpayment migrate`.

Backups hold encrypted PANs and sealed keys: store them like the database, and keep every master
and audit key that was in use (including `_PREVIOUS`) with a separate custodian.

## Incidents

1. **Leaked API key.** Remove its hash and restart. Find its detokenizations in the audit log
   (merchant, masked token, time). Issue a new key.
2. **Leaked master key.** If the database may also have leaked, treat every PAN in it as exposed
   and follow the card-data breach procedure (card networks, PCI forensic investigator, DPDP Act
   notification). Then set a new master key with the old one in `_PREVIOUS` and rotate the epoch
   keys, so every record is re-wrapped under keys the attacker never had. Keep the old key in
   `_PREVIOUS`: older epochs are not re-sealed and `/readyz` checks that they unseal.
3. **Audit verification fails.** Stop writes if you can, take a copy of the database, and compare
   with the latest backup to find the first broken entry. Treat it as possible tampering.
4. **`/readyz` reports `keys: false`.** The master key doesn't match the database: check
   `PQCPAYMENT_MASTER_KEY` and `_PREVIOUS` against what the epochs were sealed with.
5. **DUKPT counter exhausted.** Tokenize returns 400 "rotate keys"; run `POST /hsm/rotate`.
