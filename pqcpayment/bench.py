"""
Comprehensive Benchmark & Cryptographic Verification Suite for pqcpayment:
  - 1,000 Luhn-valid PANs across Visa, Mastercard, and RuPay BINs
  - 100% Bijective FF1-Feistel Encryption/Decryption (0 collisions, 100% exact recovery)
  - 100% Luhn Checksum Preservation & BIN Prefix Preservation
  - 100% Hybrid Module-LWE (n=256, q=3329) + X25519 KEM Handshake Accuracy
  - 100% Fujisaki-Okamoto (FO) CCA2 Implicit Rejection on Tampered Ciphertexts
  - Zero-Downtime HSM Key Rotation & Hash-Chained Audit Log Verification
"""

from __future__ import annotations

import hashlib
import os
import json
import time
from typing import Dict

from pqcpayment.fpe import (
    FF1Radix10Cipher,
    generate_luhn_pan,
    verify_luhn,
)
from pqcpayment.hsm import DUKPTKeyEngine, QuantumSafeHSMVault
from pqcpayment.pqc_kem import (
    HybridCiphertext,
    HybridPQCKEM,
    ModuleLWECiphertext,
)

ISSUER_BINS = (
    ("453201", "VISA"),
    ("541275", "MASTERCARD"),
    ("607094", "RUPAY"),
)


def run_benchmark(num_pans: int = 1000, kem_trials: int = 50) -> Dict[str, object]:
    """
    Execute the end-to-end cryptographic verification and performance benchmark.
    """
    t_start = time.perf_counter()

    # 1. Bijective Luhn-Preserving FF1-Feistel Benchmark over `num_pans` cards
    fpe_key = os.urandom(32)
    cipher = FF1Radix10Cipher(fpe_key)
    tweak = "EPOCH:1|MERCH:BENCH-SWITCH-01"

    input_pans = []
    for idx in range(num_pans):
        bin_prefix, _ = ISSUER_BINS[idx % len(ISSUER_BINS)]
        # Spread sequence numbers across the 9-digit payload space
        seq = (idx * 987_653 + 104_729) % 1_000_000_000
        input_pans.append(generate_luhn_pan(bin_prefix=bin_prefix, account_seq=seq))

    t_fpe_enc_0 = time.perf_counter()
    tokens = [cipher.encrypt_pan(pan, tweak=tweak) for pan in input_pans]
    t_fpe_enc_ms = (time.perf_counter() - t_fpe_enc_0) * 1000.0

    t_fpe_dec_0 = time.perf_counter()
    recovered_pans = [cipher.decrypt_token(tok, tweak=tweak) for tok in tokens]
    t_fpe_dec_ms = (time.perf_counter() - t_fpe_dec_0) * 1000.0

    unique_pans = len(set(input_pans))
    unique_tokens = len(set(tokens))
    collisions = unique_pans - unique_tokens
    exact_decryptions = sum(
        1 for orig, dec in zip(input_pans, recovered_pans) if orig == dec
    )
    luhn_valid_tokens = sum(1 for tok in tokens if verify_luhn(tok))
    bin_preserved_tokens = sum(
        1 for orig, tok in zip(input_pans, tokens) if orig[:6] == tok[:6]
    )

    # 2. Hybrid Module-LWE (n=256, q=3329) + X25519 KEM & FO-CCA2 Tamper Rejection
    t_kem_0 = time.perf_counter()
    kem_success = 0
    cca2_rejections = 0

    kp = HybridPQCKEM.keygen()
    for trial in range(kem_trials):
        coins = hashlib.sha256(f"KEM-TRIAL-{trial}".encode("utf-8")).digest()
        ct, ss_enc, _ = HybridPQCKEM.encapsulate(kp.public_key, coins=coins)
        res_valid = HybridPQCKEM.decapsulate(kp, ct)
        if res_valid.cca2_valid and not res_valid.cca2_rejected and res_valid.shared_secret == ss_enc:
            kem_success += 1

        # Tamper with ciphertext polynomial u or v and verify FO-CCA2 implicit rejection
        u_raw = bytearray(ct.lwe_ct.u_bytes)
        u_raw[trial % len(u_raw)] ^= 0x01
        tampered_ct = HybridCiphertext(
            lwe_ct=ModuleLWECiphertext(u_bytes=bytes(u_raw), v_bytes=ct.lwe_ct.v_bytes),
            x25519_epk_bytes=ct.x25519_epk_bytes,
        )
        res_tampered = HybridPQCKEM.decapsulate(kp, tampered_ct)
        if res_tampered.cca2_rejected and res_tampered.shared_secret != ss_enc:
            cca2_rejections += 1

    t_kem_ms = (time.perf_counter() - t_kem_0) * 1000.0

    # 3. DUKPT Key Isolation & Zero-Downtime HSM Epoch Key Rotation
    vault = QuantumSafeHSMVault()
    sample_cards = input_pans[:12]
    epoch1_tokens = []
    ksn_set = set()
    working_keys = set()

    bdk = vault.epochs[1].bdk
    for i, card in enumerate(sample_cards):
        res = vault.tokenize(card, merchant_id="MERCH-BENCH-VAULT")
        epoch1_tokens.append(str(res["token"]))
        ksn_str = str(res["dukpt"]["ksn"])
        ksn_set.add(ksn_str)
        dk = DUKPTKeyEngine.derive_transaction_key(bdk, ksn_str)
        working_keys.add(dk.working_key_hex)

    rotation_report = vault.rotate_epoch(reason="Benchmark Zero-Downtime Epoch 1 -> 2 Rotation")
    # Verify legacy Epoch 1 tokens still detokenize cleanly after rotation to Epoch 2
    legacy_recovered = [
        vault.detokenize(tok, merchant_id="MERCH-BENCH-VAULT")["pan"]
        for tok in epoch1_tokens
    ]
    legacy_recovery_matches = sum(
        1 for orig, rec in zip(sample_cards, legacy_recovered) if orig == rec
    )
    audit_check = vault.verify_audit_log()

    total_ms = (time.perf_counter() - t_start) * 1000.0

    return {
        "benchmark_suite": "pqcpayment-v1.0-quantum-safe-vault",
        "fpe_bijection": {
            "total_pans_tested": num_pans,
            "unique_input_pans": unique_pans,
            "unique_output_tokens": unique_tokens,
            "collisions": collisions,
            "bijection_rate": round(exact_decryptions / num_pans, 6),
            "exact_decryptions": exact_decryptions,
            "luhn_valid_tokens": luhn_valid_tokens,
            "luhn_valid_rate": round(luhn_valid_tokens / num_pans, 6),
            "bin_preserved_tokens": bin_preserved_tokens,
            "bin_preserved_rate": round(bin_preserved_tokens / num_pans, 6),
            "encrypt_total_ms": round(t_fpe_enc_ms, 3),
            "decrypt_total_ms": round(t_fpe_dec_ms, 3),
            "per_card_encrypt_ms": round(t_fpe_enc_ms / num_pans, 4),
            "per_card_decrypt_ms": round(t_fpe_dec_ms / num_pans, 4),
        },
        "pqc_hybrid_kem": {
            "ring_parameters": "R_q = Z_3329[X]/(X^256 + 1), k=2, eta=2 + X25519",
            "trials": kem_trials,
            "valid_handshakes": kem_success,
            "handshake_accuracy_rate": round(kem_success / kem_trials, 6),
            "tampered_cca2_rejections": cca2_rejections,
            "cca2_rejection_rate": round(cca2_rejections / kem_trials, 6),
            "total_kem_ms": round(t_kem_ms, 3),
            "per_handshake_ms": round(t_kem_ms / kem_trials, 3),
        },
        "hsm_rotation_and_dukpt": {
            "cards_provisioned": len(sample_cards),
            "unique_ksns": len(ksn_set),
            "unique_dukpt_working_keys": len(working_keys),
            "rotated_from_epoch": rotation_report["previous_epoch"],
            "rotated_to_epoch": rotation_report["active_epoch"],
            "rewrapped_records": rotation_report["rewrapped_records"],
            "legacy_token_zero_downtime_matches": legacy_recovery_matches,
            "audit_chain_valid": audit_check["valid"],
            "audit_entries": audit_check["entries_count"],
            "rotation_latency_ms": rotation_report["latency_ms"],
        },
        "total_benchmark_ms": round(total_ms, 2),
        "all_invariants_passed": (
            collisions == 0
            and exact_decryptions == num_pans
            and luhn_valid_tokens == num_pans
            and bin_preserved_tokens == num_pans
            and kem_success == kem_trials
            and cca2_rejections == kem_trials
            and legacy_recovery_matches == len(sample_cards)
            and bool(audit_check["valid"])
        ),
    }


if __name__ == "__main__":
    report = run_benchmark()
    print(json.dumps(report, indent=2))
