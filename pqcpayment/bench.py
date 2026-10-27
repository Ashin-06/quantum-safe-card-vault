"""
Consistency benchmark for pqcpayment, on generated card numbers.

Checks that the implementation keeps the properties its construction promises:
  - FF1 tokenization of N generated PANs (3 sample BINs): no collisions, exact
    decryption, Luhn-valid tokens, BIN kept. FF1 is a permutation, so anything
    else would be a bug; correctness against the standard is the NIST-vector test.
  - Hybrid KEM (ML-KEM-768 + X25519): encapsulate/decapsulate agree, and a one-bit flip in
    the ML-KEM ciphertext gives a different key, so an envelope sealed under the real key
    won't open. That is a smoke test of the wiring; ML-KEM's security is the library's.
  - Vault: 12 cards tokenized, keys rotated, old tokens still resolve, audit chain verifies.
Timings are single-threaded Python on whatever machine runs it.
"""

from __future__ import annotations

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
from pqcpayment.pqc_kem import HybridCiphertext, HybridPQCKEM

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

    # 2. Hybrid ML-KEM-768 + X25519: round trips, and implicit rejection of tampered ciphertexts
    t_kem_0 = time.perf_counter()
    kem_success = 0
    tamper_rejections = 0
    ct_bytes = 0

    kp = HybridPQCKEM.keygen()
    for trial in range(kem_trials):
        ct, ss_enc, meta = HybridPQCKEM.encapsulate(kp.public_key)
        ct_bytes = int(meta["ciphertext_bytes"])
        if HybridPQCKEM.decapsulate(kp, ct) == ss_enc:
            kem_success += 1
        # Flip one bit of the ML-KEM ciphertext: decapsulation must give an unrelated key
        raw = bytearray(ct.mlkem_ct)
        raw[trial % len(raw)] ^= 0x01
        if HybridPQCKEM.decapsulate(kp, HybridCiphertext(bytes(raw), ct.x25519_epk_bytes)) != ss_enc:
            tamper_rejections += 1

    t_kem_ms = (time.perf_counter() - t_kem_0) * 1000.0

    # 3. DUKPT Key Isolation & Zero-Downtime HSM Epoch Key Rotation
    vault = QuantumSafeHSMVault()
    sample_cards = input_pans[:12]
    epoch1_tokens = []
    ksn_set = set()
    working_keys = set()

    bdk = vault.epochs[1].bdk
    for card in sample_cards:
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
            "kem": "ML-KEM-768 (FIPS 203, pyca cryptography) + X25519",
            "trials": kem_trials,
            "valid_handshakes": kem_success,
            "handshake_accuracy_rate": round(kem_success / kem_trials, 6),
            "tampered_ciphertexts_rejected": tamper_rejections,
            "tamper_rejection_rate": round(tamper_rejections / kem_trials, 6),
            "ciphertext_bytes": ct_bytes,
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
            and tamper_rejections == kem_trials
            and legacy_recovery_matches == len(sample_cards)
            and bool(audit_check["valid"])
        ),
    }


if __name__ == "__main__":
    report = run_benchmark()
    print(json.dumps(report, indent=2))
