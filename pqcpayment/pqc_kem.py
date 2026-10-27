"""
Hybrid KEM: ML-KEM-768 (FIPS 203) combined with X25519, both from pyca `cryptography`.

Both primitives are the library's (`cryptography` 47+ exposes ML-KEM, backed by the
OpenSSL it ships). Only the combiner is written here: HKDF-SHA256 over
ss_mlkem || ss_x25519 || X25519 ephemeral key || X25519 recipient key, salted with a hash of
the recipient's whole public key. It is in the style of X-Wing (draft-connolly-cfrg-xwing-kem)
but not the X-Wing spec, so it doesn't interoperate with X-Wing and hasn't been reviewed.

- Binding the X25519 public values matters: X25519 ignores bit 255 of a public key, so
  without them two different ciphertexts decapsulated to the same key.
- The ML-KEM ciphertext needs no binding: ML-KEM's own Fujisaki-Okamoto transform makes its
  shared secret depend on the whole ciphertext.
- ML-KEM decapsulation never fails. A tampered ciphertext gives an unrelated key (implicit
  rejection), so the AES-GCM envelope sealed under the real key then fails to open.
"""

from __future__ import annotations

import base64
import hashlib
import os
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import mlkem, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MLKEM768_PK_BYTES = 1184
MLKEM768_CT_BYTES = 1088
MLKEM_SEED_BYTES = 64  # FIPS 203 (d, z): the whole ML-KEM private key
X25519_BYTES = 32
_RAW = (serialization.Encoding.Raw, serialization.PublicFormat.Raw)


@dataclass(frozen=True)
class HybridPublicKey:
    mlkem_pk_bytes: bytes
    x25519_pk_bytes: bytes

    def to_bytes(self) -> bytes:
        return self.mlkem_pk_bytes + self.x25519_pk_bytes

    def fingerprint(self) -> str:
        return hashlib.sha256(self.to_bytes()).hexdigest()[:16]


@dataclass(frozen=True)
class HybridKeyPair:
    public_key: HybridPublicKey
    mlkem_sk: mlkem.MLKEM768PrivateKey
    x25519_sk: x25519.X25519PrivateKey

    def private_bytes(self) -> bytes:
        """ML-KEM seed (64 bytes) || X25519 private key (32 bytes). Seal it before storing."""
        return self.mlkem_sk.private_bytes_raw() + self.x25519_sk.private_bytes_raw()

    @classmethod
    def from_private_bytes(cls, raw: bytes) -> HybridKeyPair:
        if len(raw) != MLKEM_SEED_BYTES + X25519_BYTES:
            raise ValueError("hybrid private key must be 96 bytes")
        return cls._from_keys(mlkem.MLKEM768PrivateKey.from_seed_bytes(raw[:MLKEM_SEED_BYTES]),
                              x25519.X25519PrivateKey.from_private_bytes(raw[MLKEM_SEED_BYTES:]))

    @classmethod
    def _from_keys(cls, m_sk: mlkem.MLKEM768PrivateKey, x_sk: x25519.X25519PrivateKey) -> HybridKeyPair:
        pk = HybridPublicKey(m_sk.public_key().public_bytes_raw(), x_sk.public_key().public_bytes(*_RAW))
        return cls(public_key=pk, mlkem_sk=m_sk, x25519_sk=x_sk)


@dataclass(frozen=True)
class HybridCiphertext:
    mlkem_ct: bytes
    x25519_epk_bytes: bytes

    def to_bytes(self) -> bytes:
        return self.mlkem_ct + self.x25519_epk_bytes

    def to_b64(self) -> str:
        return base64.b64encode(self.to_bytes()).decode("ascii")

    @classmethod
    def from_b64(cls, b64_str: str) -> HybridCiphertext:
        raw = base64.b64decode(b64_str.encode("ascii"), validate=True)
        if len(raw) != MLKEM768_CT_BYTES + X25519_BYTES:
            raise ValueError(f"Invalid hybrid ciphertext length {len(raw)}")
        return cls(mlkem_ct=raw[:MLKEM768_CT_BYTES], x25519_epk_bytes=raw[MLKEM768_CT_BYTES:])


class HybridPQCKEM:
    """ML-KEM-768 + X25519; the combiner binds both shared secrets and the X25519 public values."""

    @classmethod
    def keygen(cls, seed: Optional[bytes] = None) -> HybridKeyPair:
        """Fresh keys, or (tests only) keys derived from `seed`."""
        if seed is None:
            return HybridKeyPair._from_keys(mlkem.MLKEM768PrivateKey.generate(), x25519.X25519PrivateKey.generate())
        return HybridKeyPair._from_keys(
            mlkem.MLKEM768PrivateKey.from_seed_bytes(hashlib.sha3_512(b"MLKEM768-SEED:" + seed).digest()),
            x25519.X25519PrivateKey.from_private_bytes(hashlib.sha256(b"X25519-SEED:" + seed).digest()),
        )

    @staticmethod
    def _combine_secrets(ss_mlkem: bytes, ss_x25519: bytes, x25519_epk: bytes, recipient_pk: HybridPublicKey) -> bytes:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=hashlib.sha256(recipient_pk.to_bytes()).digest(),
            info=b"PQCPAYMENT-MLKEM768-X25519:HYBRID-KEM-V2",
        )
        return hkdf.derive(ss_mlkem + ss_x25519 + x25519_epk + recipient_pk.x25519_pk_bytes)

    @classmethod
    def encapsulate(cls, hybrid_pk: HybridPublicKey) -> Tuple[HybridCiphertext, bytes, Dict[str, str]]:
        ss_mlkem, mlkem_ct = mlkem.MLKEM768PublicKey.from_public_bytes(hybrid_pk.mlkem_pk_bytes).encapsulate()
        eph_sk = x25519.X25519PrivateKey.generate()
        eph_pk_bytes = eph_sk.public_key().public_bytes(*_RAW)
        ss_x25519 = eph_sk.exchange(x25519.X25519PublicKey.from_public_bytes(hybrid_pk.x25519_pk_bytes))

        ss_hybrid = cls._combine_secrets(ss_mlkem, ss_x25519, eph_pk_bytes, hybrid_pk)
        ct = HybridCiphertext(mlkem_ct=mlkem_ct, x25519_epk_bytes=eph_pk_bytes)
        meta = {"pk_fingerprint": hybrid_pk.fingerprint(), "ciphertext_bytes": str(len(ct.to_bytes()))}
        return ct, ss_hybrid, meta

    @classmethod
    def decapsulate(cls, keypair: HybridKeyPair, hybrid_ct: HybridCiphertext) -> bytes:
        """The shared secret. A tampered ciphertext gives an unrelated one (ML-KEM implicit rejection)."""
        ss_mlkem = keypair.mlkem_sk.decapsulate(hybrid_ct.mlkem_ct)
        ss_x25519 = keypair.x25519_sk.exchange(x25519.X25519PublicKey.from_public_bytes(hybrid_ct.x25519_epk_bytes))
        return cls._combine_secrets(ss_mlkem, ss_x25519, hybrid_ct.x25519_epk_bytes, keypair.public_key)

    @classmethod
    def wrap_envelope(cls, hybrid_pk: HybridPublicKey, plaintext: bytes, aad: bytes = b"") -> Dict[str, str]:
        """Encapsulate a fresh hybrid key and encrypt `plaintext` with AES-256-GCM bound to `aad`."""
        ct, ss_hybrid, _ = cls.encapsulate(hybrid_pk)
        nonce = os.urandom(12)
        return {
            "kem_ciphertext_b64": ct.to_b64(),
            "aes_nonce_hex": nonce.hex(),
            "wrapped_payload_b64": base64.b64encode(AESGCM(ss_hybrid).encrypt(nonce, plaintext, aad)).decode("ascii"),
            "pk_fingerprint": hybrid_pk.fingerprint(),
        }

    @classmethod
    def unwrap_envelope(cls, keypair: HybridKeyPair, envelope: Dict[str, str], aad: bytes = b"") -> bytes:
        ct = HybridCiphertext.from_b64(envelope["kem_ciphertext_b64"])
        key = cls.decapsulate(keypair, ct)
        try:
            return AESGCM(key).decrypt(bytes.fromhex(envelope["aes_nonce_hex"]),
                                       base64.b64decode(envelope["wrapped_payload_b64"].encode("ascii")), aad)
        except InvalidTag as e:
            raise ValueError("envelope failed to open: wrong key, or a tampered ciphertext or payload") from e
