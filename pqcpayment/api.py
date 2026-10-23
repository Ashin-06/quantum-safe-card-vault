"""
FastAPI service for the card vault: FF1 tokens, hybrid-KEM envelopes, key rotation.

One in-memory vault. Set PQCPAYMENT_API_KEY to require it in the X-API-Key header on
every endpoint except / and /health (unset = open, for local use; `python -m pqcpayment
serve` refuses a non-loopback host without it). Everyone holding the key is trusted with
every merchant's cards: there are no per-merchant credentials.
"""

from __future__ import annotations

from functools import lru_cache
import hmac
import os
import threading
import time
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from pqcpayment.bench import run_benchmark
from pqcpayment.hsm import QuantumSafeHSMVault
from pqcpayment.pqc_kem import (
    HybridCiphertext,
    HybridPQCKEM,
    ModuleLWECiphertext,
)

app = FastAPI(
    title="Card Vault (pqcpayment)",
    description=(
        "FF1 format-preserving card tokens, PAN envelopes under a hybrid Module-LWE + X25519 "
        "KEM, and epoch key rotation. A reference implementation, not a PCI-scoped vault."
    ),
    version="1.0.0",
)

VAULT = QuantumSafeHSMVault()
WEB_CONSOLE_PATH = Path(__file__).resolve().parent.parent / "web" / "console.html"
API_KEY = os.environ.get("PQCPAYMENT_API_KEY")
MAX_BODY_BYTES = 8_000
MAX_INDEXED_TOKENS = 200_000
MAX_EPOCHS = 100
_LOCK = threading.Lock()  # ponytail: one lock around the in-memory vault; a real vault shards by key

MERCHANT = Field(default="MERCH-GLOBAL-01", pattern=r"^[A-Za-z0-9_.:-]{1,64}$")


def require_key(x_api_key: str | None = Header(default=None)) -> None:
    if API_KEY and not hmac.compare_digest(x_api_key or "", API_KEY):
        raise HTTPException(401, "missing or wrong X-API-Key")


@app.middleware("http")
async def limit_body(request: Request, call_next):
    if request.method == "POST":
        # Chunked bodies have no length to check up front, so refuse them
        length = request.headers.get("content-length", "0")
        if "transfer-encoding" in request.headers or not length.isdigit() or int(length) > MAX_BODY_BYTES:
            return JSONResponse({"detail": "body must have a Content-Length of at most 8 KB"}, status_code=413)
    return await call_next(request)


@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
    # The default handler echoes the rejected input, which here would put a PAN in the response
    errors = [{k: e[k] for k in ("type", "loc", "msg") if k in e} for e in exc.errors()]
    return JSONResponse({"detail": errors}, status_code=422)


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
        description="If true, flips 1 bit in the Module-LWE ciphertext to trigger FO implicit rejection",
    )


class HSMRotateRequest(BaseModel):
    reason: str = Field(default="Scheduled key rotation", max_length=200)


@app.get("/", response_class=HTMLResponse)
def get_console() -> HTMLResponse:
    if WEB_CONSOLE_PATH.exists():
        return HTMLResponse(content=WEB_CONSOLE_PATH.read_text(encoding="utf-8"))
    return HTMLResponse(
        content="<h1>pqcpayment Card Vault API</h1><p>Console HTML not found.</p>"
    )


@app.get("/health")
def get_health() -> dict:
    return {"status": "ok", "service": "pqcpayment"}


@app.post("/tokenize", dependencies=[Depends(require_key)])
def post_tokenize(req: TokenizeRequest) -> dict:
    with _LOCK:
        if len(VAULT.records_by_token) >= MAX_INDEXED_TOKENS:
            raise HTTPException(status_code=507, detail="vault is full")
        try:
            return VAULT.tokenize(
                pan=req.pan,
                merchant_id=req.merchant_id,
                terminal_id=req.terminal_id,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/detokenize", dependencies=[Depends(require_key)])
def post_detokenize(req: DetokenizeRequest) -> dict:
    with _LOCK:
        try:
            return VAULT.detokenize(token=req.token, merchant_id=req.merchant_id)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/kem/handshake", dependencies=[Depends(require_key)])
def post_kem_handshake(req: KEMHandshakeRequest) -> dict:
    t0 = time.perf_counter()
    with _LOCK:
        bundle = VAULT.epochs[VAULT.active_epoch]
    kp = bundle.hybrid_keypair

    ct, ss_sender, meta = HybridPQCKEM.encapsulate(kp.public_key)
    transmitted_ct = ct
    if req.tamper_ciphertext:
        u_bytes = bytearray(ct.lwe_ct.u_bytes)
        u_bytes[0] ^= 0x01
        transmitted_ct = HybridCiphertext(
            lwe_ct=ModuleLWECiphertext(u_bytes=bytes(u_bytes), v_bytes=ct.lwe_ct.v_bytes),
            x25519_epk_bytes=ct.x25519_epk_bytes,
        )

    decap = HybridPQCKEM.decapsulate(kp, transmitted_ct)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    # A throwaway encapsulation to the vault key: its secrets protect nothing, so showing them is safe
    return {
        "epoch": bundle.epoch,
        "ring_spec": "R_q = Z_3329[X]/(X^256 + 1), k=2, eta=2 (not ML-KEM) + X25519",
        "pk_fingerprint": kp.public_key.fingerprint(),
        "tamper_injected": req.tamper_ciphertext,
        "cca2_valid": decap.cca2_valid,
        "cca2_rejected": decap.cca2_rejected,
        "shared_secrets_match": decap.shared_secret == ss_sender,
        "sender_ss_hybrid_hex": ss_sender.hex(),
        "receiver_ss_hybrid_hex": decap.shared_secret.hex(),
        "ciphertext_bytes": int(meta["ciphertext_bytes"]),
        "latency_ms": round(elapsed_ms, 3),
    }


@app.post("/hsm/rotate", dependencies=[Depends(require_key)])
def post_hsm_rotate(req: HSMRotateRequest) -> dict:
    with _LOCK:
        if len(VAULT.epochs) >= MAX_EPOCHS:
            raise HTTPException(status_code=409, detail=f"at most {MAX_EPOCHS} epochs are kept")
        return VAULT.rotate_epoch(reason=req.reason)


@app.get("/hsm/status", dependencies=[Depends(require_key)])
def get_hsm_status() -> dict:
    with _LOCK:
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
            for e in VAULT.audit_log[-10:]
        ]
    return summary


_bench = lru_cache(maxsize=16)(run_benchmark)


@app.get("/bench", dependencies=[Depends(require_key)])
def get_bench(
    num_pans: int = Query(default=1000, ge=10, le=5000),
    kem_trials: int = Query(default=50, ge=5, le=250),
) -> dict:
    return _bench(num_pans, kem_trials)
