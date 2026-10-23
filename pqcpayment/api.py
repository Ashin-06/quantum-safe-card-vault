"""
FastAPI Service for the Post-Quantum Hybrid Lattice-KEM Payment Vault,
Bijective Luhn-Preserving FF1-Feistel Tokenizer, and Zero-Downtime HSM Key Rotation Engine.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from pqcpayment.bench import run_benchmark
from pqcpayment.hsm import QuantumSafeHSMVault
from pqcpayment.pqc_kem import (
    HybridCiphertext,
    HybridPQCKEM,
    ModuleLWECiphertext,
)

app = FastAPI(
    title="Quantum-Safe Payment Card Vault (pqcpayment)",
    description=(
        "Post-Quantum Hybrid Module-LWE (n=256, q=3329) + X25519 KEM Payment Vault, "
        "Bijective Luhn-Preserving FF1-Feistel Tokenization & Zero-Downtime HSM Key Rotation."
    ),
    version="1.0.0",
)

VAULT = QuantumSafeHSMVault()
WEB_CONSOLE_PATH = Path(__file__).resolve().parent.parent / "web" / "console.html"


class TokenizeRequest(BaseModel):
    pan: str = Field(..., description="16-digit Luhn-valid Primary Account Number")
    merchant_id: str = Field(default="MERCH-GLOBAL-01", description="Merchant / domain tweak")
    terminal_id: str = Field(default="FFFF987654", description="DUKPT terminal prefix")


class DetokenizeRequest(BaseModel):
    token: str = Field(..., description="16-digit Luhn-valid FF1 token")
    merchant_id: str = Field(default="MERCH-GLOBAL-01", description="Merchant / domain tweak")
    epoch: Optional[int] = Field(default=None, description="Optional explicit key epoch")


class KEMHandshakeRequest(BaseModel):
    tamper_ciphertext: bool = Field(
        default=False,
        description="If true, flips 1 bit in the Module-LWE ciphertext to trigger FO-CCA2 implicit rejection",
    )


class HSMRotateRequest(BaseModel):
    reason: str = Field(
        default="Scheduled NIST FIPS 203 Zero-Downtime Key Rotation",
        description="Audit reason for rotating HSM master keys to Epoch E+1",
    )


@app.get("/", response_class=HTMLResponse)
def get_console() -> HTMLResponse:
    if WEB_CONSOLE_PATH.exists():
        return HTMLResponse(content=WEB_CONSOLE_PATH.read_text(encoding="utf-8"))
    return HTMLResponse(
        content="<h1>pqcpayment Quantum-Safe Card Vault API</h1><p>Console HTML not found.</p>"
    )


@app.get("/health")
def get_health() -> dict:
    return {
        "status": "ok",
        "service": "pqcpayment",
        "active_epoch": VAULT.active_epoch,
        "audit_chain_valid": VAULT.verify_audit_log()["valid"],
    }


@app.post("/tokenize")
def post_tokenize(req: TokenizeRequest) -> dict:
    try:
        return VAULT.tokenize(
            pan=req.pan,
            merchant_id=req.merchant_id,
            terminal_id=req.terminal_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/detokenize")
def post_detokenize(req: DetokenizeRequest) -> dict:
    try:
        return VAULT.detokenize(
            token=req.token,
            merchant_id=req.merchant_id,
            epoch=req.epoch,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/kem/handshake")
def post_kem_handshake(req: KEMHandshakeRequest) -> dict:
    t0 = time.perf_counter()
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

    return {
        "epoch": bundle.epoch,
        "ring_spec": "R_q = Z_3329[X]/(X^256 + 1), k=2, eta=2 + X25519",
        "pk_fingerprint": kp.public_key.fingerprint(),
        "tamper_injected": req.tamper_ciphertext,
        "cca2_valid": decap.cca2_valid,
        "cca2_rejected": decap.cca2_rejected,
        "shared_secrets_match": decap.shared_secret == ss_sender,
        "sender_ss_hybrid_hex": ss_sender.hex(),
        "receiver_ss_hybrid_hex": decap.shared_secret.hex(),
        "ss_lwe_hex": meta["ss_lwe_hex"],
        "ss_x25519_hex": meta["ss_x25519_hex"],
        "ciphertext_bytes": int(meta["ciphertext_bytes"]),
        "latency_ms": round(elapsed_ms, 3),
    }


@app.post("/hsm/rotate")
def post_hsm_rotate(req: HSMRotateRequest) -> dict:
    return VAULT.rotate_epoch(reason=req.reason)


@app.get("/hsm/status")
def get_hsm_status() -> dict:
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


@app.get("/bench")
def get_bench(
    num_pans: int = Query(default=1000, ge=10, le=5000),
    kem_trials: int = Query(default=50, ge=5, le=250),
) -> dict:
    return run_benchmark(num_pans=num_pans, kem_trials=kem_trials)
