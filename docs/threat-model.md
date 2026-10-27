# Threat model

What the card vault protects, from whom, and what is still open. Written for the 1.0.0 code; it
has not been reviewed by anyone independent, a cryptographer or a PCI assessor.

## What it protects

| Asset | Where it lives |
|---|---|
| PANs | only inside KEM + AES-256-GCM envelopes in `records.doc`; BIN and last 4 in clear |
| Epoch keys (ML-KEM-768 + X25519 private keys, FF1 key, DUKPT BDK) | `epochs.sealed_keys`, AES-256-GCM under the master key; unsealed in process memory while in use |
| Master key, audit key | `PQCPAYMENT_MASTER_KEY`, `PQCPAYMENT_AUDIT_KEY` in the environment / secret store |
| Token → card mapping per merchant | `tokens` table |
| Audit trail | `audit_log` table, HMAC chain (masked tokens only) |
| API keys | callers hold the key; the service holds only SHA-256 hashes |

## Trust boundaries

```
merchant / payments ops / key custodian ──(TLS at your ingress)──► vault service ──► database
```

1. **Caller → service.** The API key decides role and, for `merchant` keys, the one merchant ID it
   may act for.
2. **Service → database.** The database holds ciphertext, sealed keys, tokens and masked audit
   entries. A dump without the master key reveals no PAN.

## Threats and what stops them

| Threat | Mitigation | Residual risk |
|---|---|---|
| A merchant reads another merchant's cards | `merchant` keys may only name their own merchant ID (403 otherwise); tokens resolve only under the merchant they were issued to; unissued tokens give 404, not an FF1 "decryption" | `payments_ops` and `admin` keys can read any merchant's cards |
| Database stolen | PANs only in envelopes; epoch keys sealed under the master key | BIN, last 4, network, merchant and timestamps are visible |
| Database and master key stolen | — | Every PAN is readable. Keep the master key in an HSM/KMS. |
| Harvest now, decrypt later (quantum) | Envelope keys come from ML-KEM-768 + X25519 (pyca `cryptography`) | The combiner is written here (not the X-Wing spec) and unreviewed. FF1, DUKPT-style keys and AES are symmetric and not affected in the same way. |
| Tampered envelope or KEM ciphertext | ML-KEM implicit rejection gives an unrelated key; AES-GCM with AAD binding epoch, merchant and KSN refuses to open | — |
| Side channels | — | **Nothing is constant-time.** FF1 and the comparisons run in Python. |
| FF1 weaknesses | FF1 per SP 800-38G Rev. 1, NIST sample vectors pass; domains of 10⁹ per BIN, merchant and epoch, above the 10⁶ floor | Hand-written; small-domain FPE is where published attacks are |
| Tokens mistaken for card numbers | — | Tokens are Luhn-valid and keep the BIN; deterministic per card, merchant and epoch, so equal tokens reveal equal cards |
| DUKPT key compromise | Counter never wraps (refused at 2²¹ − 1; rotation resets) | Not X9.24; one counter for all terminals; a leaked transaction key gives every key below it; the per-transaction MAC is stored, not verified |
| Audit trail edited | HMAC chain; any edit, deletion in the middle or reordering fails verification (`/hsm/status`) | Truncating the newest entries is only caught if the chain head is kept elsewhere |
| Replicas race | DUKPT counters advance with a compare-and-set; audit positions and record IDs are primary keys; rotation runs in one transaction | Rotation holds the transaction for every record |
| Stolen API key | Keys per client, revocable; merchant scoping; detokenizations audited | A stolen `payments_ops` key reads every card until removed |
| Brute force, flooding | 256-bit keys; per-client rate limit; 8 KB body cap; 200,000-token cap; 100-epoch cap; `/bench` admin only | Per process |
| Error messages leak PANs | Validation errors carry no input; vault errors never contain the PAN; unhandled errors return only a request ID; the access log has no bodies | — |
| Misconfigured production start | Production refuses to start without hashed keys, both secrets and a database; `/readyz` fails if the epoch keys don't unseal | Production mode can't check that keys are *good*, only that they exist and have the right shape |

## Not covered

- TLS. Terminate it at your ingress; the service speaks plain HTTP.
- A real HSM, card networks, terminals, and PCI DSS scoping of everything around the service.
- 8-digit BINs and PAN lengths other than 16.
- An insider with database *and* master-key access.
