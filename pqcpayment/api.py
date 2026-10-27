"""
FastAPI service for the card vault: FF1 tokens, ML-KEM-768 + X25519 envelopes, key rotation.

The vault lives in a database (hsm.py, db.py); every epoch's keys are sealed under
PQCPAYMENT_MASTER_KEY and the audit chain is keyed with PQCPAYMENT_AUDIT_KEY. Settings come
from PQCPAYMENT_* environment variables (ops.py). A `merchant` key's user name is its merchant
ID, and it can only tokenize and detokenize for that merchant; `payments_ops` and `admin` keys
can name any merchant.
"""

from __future__ import annotations

from functools import lru_cache
import logging
from pathlib import Path
import time

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from pqcpayment import db, ops
from pqcpayment.bench import run_benchmark
from pqcpayment.hsm import QuantumSafeHSMVault
from pqcpayment.pqc_kem import HybridCiphertext, HybridPQCKEM

log = logging.getLogger("pqcpayment.api")
CRYPTO_WARNING = ("FF1 and the DUKPT-style key derivation are implemented here in Python (FF1 matches the NIST "
                  "samples), nothing is constant-time, and the hybrid KEM combiner is not the X-Wing spec; none of "
                  "it has been reviewed by a cryptographer or a PCI assessor, so do not store real card data")

settings = ops.load_settings()
ops.setup_logging(settings.log_level)
store = db.connect(settings.database_url)
VAULT = QuantumSafeHSMVault(
    engine=store,
    master_key=settings.secret["MASTER_KEY"],
    previous_master_keys=settings.previous["MASTER_KEY"],
    audit_key=settings.secret["AUDIT_KEY"],
    previous_audit_keys=settings.previous["AUDIT_KEY"],
)
if settings.production:
    log.warning("UNREVIEWED CRYPTOGRAPHY: " + CRYPTO_WARNING)

app = FastAPI(
    title="Card Vault (pqcpayment)",
    description=(
        "FF1 format-preserving card tokens, PAN envelopes under a hybrid ML-KEM-768 + X25519 "
        "KEM, and epoch key rotation. A reference implementation, not a PCI-scoped vault."
    ),
    version="1.0.0",
)
# "keys": every epoch's keys unseal under the configured master key(s)
ops.install(app, settings, {"database": lambda: store.connect().close(), "keys": lambda: bool(VAULT.epochs)})

WEB_CONSOLE_PATH = Path(__file__).resolve().parent.parent / "web" / "console.html"
MAX_INDEXED_TOKENS = 200_000
MAX_EPOCHS = 100

MERCHANT = Field(default="MERCH-GLOBAL-01", pattern=r"^[A-Za-z0-9_.:-]{1,64}$")


def _check_merchant(ident: dict, merchant_id: str) -> None:
    if ident["role"] == "demo" or "any_merchant" in ops.ROLES[ident["role"]] or ident["user"] == merchant_id:
        return
    raise HTTPException(status_code=403, detail="this key may only act for its own merchant")


class TokenizeRequest(BaseModel):
    pan: str = Field(..., pattern=r"^[0-9 -]{16,23}$", description="16-digit Luhn-valid PAN")
    merchant_id: str = MERCHANT
    terminal_id: str = Field(default="FFFF987654", pattern=r"^[0-9A-Fa-f]{1,15}$", description="DUKPT terminal prefix (hex)")


class DetokenizeRequest(BaseModel):
    token: str = Field(..., pattern=r"^[0-9 -]{16,23}$", description="16-digit token")
    merchant_id: str = MERCHANT


class KEMHandshakeRequest(BaseModel):
    tamper_ciphertext: bool = Field(
        default=False,
        description="If true, flips 1 bit in the ML-KEM ciphertext; implicit rejection then gives a different key",
    )


class HSMRotateRequest(BaseModel):
    reason: str = Field(default="Scheduled key rotation", max_length=200)


@app.get("/", response_class=HTMLResponse)
def get_console() -> HTMLResponse:
    if WEB_CONSOLE_PATH.exists():
        return HTMLResponse(content=WEB_CONSOLE_PATH.read_text(encoding="utf-8"))
    return HTMLResponse(content="<h1>pqcpayment Card Vault API</h1><p>Console HTML not found.</p>")


@app.post("/tokenize")
def post_tokenize(req: TokenizeRequest, ident: dict = Depends(ops.require("tokenize"))) -> dict:
    _check_merchant(ident, req.merchant_id)
    if VAULT.token_count() >= MAX_INDEXED_TOKENS:
        raise HTTPException(status_code=507, detail="vault is full")
    try:
        out = VAULT.tokenize(pan=req.pan, merchant_id=req.merchant_id, terminal_id=req.terminal_id)
    except ValueError as exc:  # the messages never contain the PAN
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    ops.DECISIONS.labels(decision="tokenized").inc()
    return out


@app.post("/detokenize")
def post_detokenize(req: DetokenizeRequest, ident: dict = Depends(ops.require("detokenize"))) -> dict:
    _check_merchant(ident, req.merchant_id)
    try:
        out = VAULT.detokenize(token=req.token, merchant_id=req.merchant_id)
    except ValueError as exc:
        ops.DECISIONS.labels(decision="detokenize_refused").inc()
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    ops.DECISIONS.labels(decision="detokenized").inc()
    return out


@app.post("/kem/handshake")
def post_kem_handshake(req: KEMHandshakeRequest, ident: dict = Depends(ops.require("kem"))) -> dict:
    t0 = time.perf_counter()
    epoch = VAULT.active_epoch
    kp = VAULT.epochs[epoch].hybrid_keypair

    ct, ss_sender, meta = HybridPQCKEM.encapsulate(kp.public_key)
    sent = ct
    if req.tamper_ciphertext:
        raw = bytearray(ct.mlkem_ct)
        raw[0] ^= 0x01
        sent = HybridCiphertext(mlkem_ct=bytes(raw), x25519_epk_bytes=ct.x25519_epk_bytes)
    ss_receiver = HybridPQCKEM.decapsulate(kp, sent)

    # A throwaway encapsulation to the vault key: its secrets protect nothing, so showing them is safe
    return {
        "epoch": epoch,
        "kem": "ML-KEM-768 (FIPS 203, pyca cryptography) + X25519",
        "pk_fingerprint": kp.public_key.fingerprint(),
        "tamper_injected": req.tamper_ciphertext,
        "shared_secrets_match": ss_receiver == ss_sender,
        "sender_ss_hybrid_hex": ss_sender.hex(),
        "receiver_ss_hybrid_hex": ss_receiver.hex(),
        "ciphertext_bytes": int(meta["ciphertext_bytes"]),
        "latency_ms": round((time.perf_counter() - t0) * 1000.0, 3),
    }


@app.post("/hsm/rotate")
def post_hsm_rotate(req: HSMRotateRequest, ident: dict = Depends(ops.require("rotate"))) -> dict:
    if VAULT.active_epoch >= MAX_EPOCHS:
        raise HTTPException(status_code=409, detail=f"at most {MAX_EPOCHS} epochs are kept")
    out = VAULT.rotate_epoch(reason=req.reason)
    ops.DECISIONS.labels(decision="rotated").inc()
    return out


@app.get("/hsm/status")
def get_hsm_status(ident: dict = Depends(ops.require("status"))) -> dict:
    summary = VAULT.status_summary()
    summary["recent_audit_log"] = [
        {
            "seq": e.seq,
            "timestamp": e.timestamp,
            "action": e.action,
            "epoch": e.epoch,
            "details": e.details,
            "prev_hash": e.prev_hash[:16] + "...",
            "entry_hash": e.entry_hash[:16] + "...",
        }
        for e in VAULT.audit_tail(10)
    ]
    return summary


_bench = lru_cache(maxsize=16)(run_benchmark)


@app.get("/bench")
def get_bench(
    num_pans: int = Query(default=1000, ge=10, le=5000),
    kem_trials: int = Query(default=50, ge=5, le=250),
    ident: dict = Depends(ops.require("bench")),
) -> dict:
    return _bench(num_pans, kem_trials)  # on its own in-memory vault; the service's vault is untouched
