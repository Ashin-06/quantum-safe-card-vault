"""
Comprehensive test suite for pqcpayment:
  - Bijective Luhn-Preserving FF1-Feistel Format-Preserving Encryption
  - Module-LWE (n=256, q=3329) + X25519 Hybrid PQC-KEM & FO-CCA2 Transform
  - DUKPT Per-Transaction Key Derivation & Zero-Downtime HSM Key Rotation
  - FastAPI Endpoints & 1,000-Card Benchmark Invariants
"""

from __future__ import annotations

import hashlib

import numpy as np
import pytest
from fastapi.testclient import TestClient

from pqcpayment.api import app
from pqcpayment.bench import run_benchmark
from pqcpayment.fpe import (
    FF1,
    FF1Radix10Cipher,
    detect_card_network,
    generate_luhn_pan,
    verify_luhn,
)
from pqcpayment.hsm import DUKPTKeyEngine, QuantumSafeHSMVault
from pqcpayment.pqc_kem import (
    HybridCiphertext,
    HybridPQCKEM,
    ModuleLWECiphertext,
    N_DEGREE,
    Q_PRIME,
    poly_add,
    poly_mul,
    poly_sub,
)


def test_luhn_generation_and_validation() -> None:
    pan = generate_luhn_pan("453201", 123456789)
    assert len(pan) == 16
    assert pan.startswith("453201")
    assert verify_luhn(pan) is True
    assert detect_card_network(pan) == "VISA"
    assert detect_card_network(generate_luhn_pan("541275", 42)) == "MASTERCARD"
    assert detect_card_network(generate_luhn_pan("607094", 42)) == "RUPAY"

    # Flip last digit and confirm Luhn failure
    bad_last = str((int(pan[-1]) + 1) % 10)
    corrupted = pan[:-1] + bad_last
    assert verify_luhn(corrupted) is False


def test_ff1_feistel_bijection_and_tweak_separation() -> None:
    key = hashlib.sha256(b"UNIT-TEST-FF1-KEY").digest()
    cipher = FF1Radix10Cipher(key)

    pan = generate_luhn_pan("453201", 51128303)
    tok_m1 = cipher.encrypt_pan(pan, tweak="MERCH-A")
    tok_m2 = cipher.encrypt_pan(pan, tweak="MERCH-B")

    assert len(tok_m1) == 16
    assert verify_luhn(tok_m1) is True
    assert verify_luhn(tok_m2) is True
    assert tok_m1[:6] == "453201"
    assert tok_m2[:6] == "453201"
    assert tok_m1 != tok_m2

    assert cipher.decrypt_token(tok_m1, tweak="MERCH-A") == pan
    assert cipher.decrypt_token(tok_m2, tweak="MERCH-B") == pan


# NIST SP 800-38G FF1 samples (csrc.nist.gov, "FF1samples.pdf"): key, radix, plaintext, tweak, ciphertext
K128 = "2B7E151628AED2A6ABF7158809CF4F3C"
K192 = K128 + "EF4359D8D580AA4F"
K256 = K192 + "7F036D6F04FC6A94"
T10 = "39383736353433323130"
T36 = "3737373770717273373737"
NIST_FF1_SAMPLES = [
    (K128, 10, "0123456789", "", "2433477484"),
    (K128, 10, "0123456789", T10, "6124200773"),
    (K128, 36, "0123456789abcdefghi", T36, "a9tv40mll9kdu509eum"),
    (K192, 10, "0123456789", "", "2830668132"),
    (K192, 10, "0123456789", T10, "2496655549"),
    (K192, 36, "0123456789abcdefghi", T36, "xbj3kv35jrawxv32ysr"),
    (K256, 10, "0123456789", "", "6657667009"),
    (K256, 10, "0123456789", T10, "1001623463"),
    (K256, 36, "0123456789abcdefghi", T36, "xs8a0azh2avyalyzuwd"),
]


@pytest.mark.parametrize("key, radix, pt, tweak, ct", NIST_FF1_SAMPLES)
def test_ff1_matches_nist_samples(key: str, radix: int, pt: str, tweak: str, ct: str) -> None:
    ff1 = FF1(bytes.fromhex(key), radix)
    assert ff1.encrypt(pt, bytes.fromhex(tweak)) == ct
    assert ff1.decrypt(ct, bytes.fromhex(tweak)) == pt


def test_ff1_rejects_small_domains_and_bad_numerals() -> None:
    ff1 = FF1(bytes(32), 10)
    with pytest.raises(ValueError):
        ff1.encrypt("12345")  # 10^5 < 10^6, below the SP 800-38G minimum
    for bad in ("12345678a", "1_2345678", " 12345678", "-12345678"):
        with pytest.raises(ValueError):
            ff1.encrypt(bad)


def test_negacyclic_polynomial_ring_arithmetic() -> None:
    # Verify X^256 == -1 == 3328 (mod X^256 + 1, 3329)
    x_pow_1 = np.zeros(N_DEGREE, dtype=np.int64)
    x_pow_1[1] = 1
    x_pow_255 = np.zeros(N_DEGREE, dtype=np.int64)
    x_pow_255[255] = 1

    prod = poly_mul(x_pow_1, x_pow_255)
    assert prod[0] == Q_PRIME - 1  # -1 mod 3329
    assert np.all(prod[1:] == 0)

    # Verify distributivity: a * (b + c) == a*b + a*c mod (X^256 + 1, 3329)
    rng = np.random.default_rng(2026)
    a = rng.integers(0, Q_PRIME, size=N_DEGREE, dtype=np.int64)
    b = rng.integers(0, Q_PRIME, size=N_DEGREE, dtype=np.int64)
    c = rng.integers(0, Q_PRIME, size=N_DEGREE, dtype=np.int64)

    lhs = poly_mul(a, poly_add(b, c))
    rhs = poly_add(poly_mul(a, b), poly_mul(a, c))
    assert np.array_equal(lhs, rhs)
    assert np.array_equal(poly_sub(lhs, rhs), np.zeros(N_DEGREE, dtype=np.int64))


def test_hybrid_pqc_kem_and_fo_cca2_tamper_rejection() -> None:
    kp = HybridPQCKEM.keygen(seed=b"TEST-PQC-KEM-SEED-2026" * 3)
    ct, ss_sender, meta = HybridPQCKEM.encapsulate(kp.public_key)

    res_ok = HybridPQCKEM.decapsulate(kp, ct)
    assert res_ok.cca2_valid is True
    assert res_ok.cca2_rejected is False
    assert res_ok.shared_secret == ss_sender
    assert len(res_ok.shared_secret) == 32

    # Flip 1 bit in Module-LWE ciphertext u -> must trigger FO-CCA2 implicit rejection
    u_tampered = bytearray(ct.lwe_ct.u_bytes)
    u_tampered[10] ^= 0x04
    bad_ct = HybridCiphertext(
        lwe_ct=ModuleLWECiphertext(u_bytes=bytes(u_tampered), v_bytes=ct.lwe_ct.v_bytes),
        x25519_epk_bytes=ct.x25519_epk_bytes,
    )
    res_bad = HybridPQCKEM.decapsulate(kp, bad_ct)
    assert res_bad.cca2_valid is False
    assert res_bad.cca2_rejected is True
    assert res_bad.shared_secret != ss_sender

    # Test envelope wrapping and unwrapping
    env = HybridPQCKEM.wrap_envelope(kp.public_key, b"SECRET-PAN-4532015112830366", aad=b"EPOCH:1")
    unwrapped = HybridPQCKEM.unwrap_envelope(kp, env, aad=b"EPOCH:1")
    assert unwrapped == b"SECRET-PAN-4532015112830366"


def test_dukpt_key_isolation_and_hsm_zero_downtime_rotation() -> None:
    vault = QuantumSafeHSMVault()
    pan1 = generate_luhn_pan("453201", 100001)
    pan2 = generate_luhn_pan("541275", 200002)

    t1 = vault.tokenize(pan1, merchant_id="MERCH-01")
    t2 = vault.tokenize(pan2, merchant_id="MERCH-01")

    assert t1["dukpt"]["ksn"] != t2["dukpt"]["ksn"]
    assert t1["dukpt"]["tx_mac_hex"] != t2["dukpt"]["tx_mac_hex"]

    tok1_epoch1 = str(t1["token"])
    tok2_epoch1 = str(t2["token"])

    # Rotate HSM from Epoch 1 -> Epoch 2
    rot = vault.rotate_epoch(reason="Unit Test Rotation")
    assert rot["previous_epoch"] == 1
    assert rot["active_epoch"] == 2
    assert rot["rewrapped_records"] == 2
    assert rot["audit_chain_valid"] is True

    # Verify zero-downtime backward compatibility on Epoch 1 tokens
    assert vault.detokenize(tok1_epoch1, merchant_id="MERCH-01")["pan"] == pan1
    assert vault.detokenize(tok2_epoch1, merchant_id="MERCH-01")["pan"] == pan2


def test_1000_pan_benchmark_invariants() -> None:
    report = run_benchmark(num_pans=1000, kem_trials=25)
    assert report["all_invariants_passed"] is True
    fpe = report["fpe_bijection"]
    assert fpe["collisions"] == 0
    assert fpe["exact_decryptions"] == 1000
    assert fpe["luhn_valid_tokens"] == 1000
    assert fpe["bin_preserved_tokens"] == 1000

    kem = report["pqc_hybrid_kem"]
    assert kem["valid_handshakes"] == 25
    assert kem["tampered_cca2_rejections"] == 25


def test_fastapi_endpoints() -> None:
    client = TestClient(app)

    r_root = client.get("/")
    assert r_root.status_code == 200
    assert "pqcpayment" in r_root.text

    pan = generate_luhn_pan("453201", 777888999)
    r_tok = client.post("/tokenize", json={"pan": pan, "merchant_id": "MERCH-API-TEST"})
    assert r_tok.status_code == 200
    tok_data = r_tok.json()
    token = tok_data["token"]
    assert verify_luhn(token) is True
    assert token[:6] == "453201"

    r_detok = client.post(
        "/detokenize", json={"token": token, "merchant_id": "MERCH-API-TEST"}
    )
    assert r_detok.status_code == 200
    assert r_detok.json()["pan"] == pan

    r_kem_ok = client.post("/kem/handshake", json={"tamper_ciphertext": False})
    assert r_kem_ok.status_code == 200
    assert r_kem_ok.json()["cca2_valid"] is True
    assert r_kem_ok.json()["shared_secrets_match"] is True

    r_kem_bad = client.post("/kem/handshake", json={"tamper_ciphertext": True})
    assert r_kem_bad.status_code == 200
    assert r_kem_bad.json()["cca2_rejected"] is True
    assert r_kem_bad.json()["shared_secrets_match"] is False

    r_rot = client.post("/hsm/rotate", json={"reason": "API Test Rotation"})
    assert r_rot.status_code == 200
    assert r_rot.json()["audit_chain_valid"] is True

    # Legacy token must still detokenize after key rotation
    r_detok_after = client.post(
        "/detokenize", json={"token": token, "merchant_id": "MERCH-API-TEST"}
    )
    assert r_detok_after.status_code == 200
    assert r_detok_after.json()["pan"] == pan
