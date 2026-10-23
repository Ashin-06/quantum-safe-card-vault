"""
Hybrid KEM: a hand-written Module-LWE KEM combined with X25519.

The lattice part is NOT ML-KEM (FIPS 203). It borrows ML-KEM's ring and modulus
(R_q = Z_3329[X]/(X^256 + 1), rank k = 2, CBD noise with eta = 2, a Fujisaki-Okamoto
transform with implicit rejection), but it has no NTT, no ciphertext compression and
its own encodings, so it can't be checked against FIPS 203 test vectors, isn't
interoperable, and its concrete security has not been analysed. It is a teaching
implementation in Python, not constant-time and not reviewed.

The X25519 half comes from `cryptography`. The combiner derives the key with
HKDF-SHA256 over ss_lwe || ss_x25519 || X25519 ephemeral key || X25519 recipient key,
in the style of X-Wing (but not the X-Wing spec). Binding the X25519 public values
matters: X25519 ignores bit 255 of a public key, so without them two different
ciphertexts decapsulated to the same key. ss_lwe already depends on H(lwe_ct).

The hybrid is only as strong as X25519 if the lattice part turns out to be weak; a
real deployment would use ML-KEM-768 from a vetted library.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

import numpy as np
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

N_DEGREE = 256
Q_PRIME = 3329
K_RANK = 2
ETA_NOISE = 2
HALF_Q = (Q_PRIME + 1) // 2  # 1665


def poly_add(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    """Addition in R_q = Z_q[X]/(X^256 + 1)."""
    return (a + b) % Q_PRIME


def poly_sub(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    """Subtraction in R_q = Z_q[X]/(X^256 + 1)."""
    return (a - b) % Q_PRIME


def poly_mul(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    """
    Negacyclic polynomial multiplication in R_q = Z_3329[X]/(X^256 + 1).
    Since X^256 = -1 (mod X^256 + 1), coefficients at degree 256 + i wrap
    around with a minus sign to degree i.
    """
    conv = np.convolve(a.astype(np.int64), b.astype(np.int64))
    low = conv[:N_DEGREE]
    high = np.zeros(N_DEGREE, dtype=np.int64)
    high[: N_DEGREE - 1] = conv[N_DEGREE:]
    return (low - high) % Q_PRIME


def sample_uniform_poly(seed: bytes, i: int, j: int) -> np.ndarray:
    """
    Rejection-sample a uniform polynomial in R_q from SHAKE-128(seed || j || i)
    (the same parsing as FIPS 203 SampleNTT, though here it's used outside the NTT domain).
    """
    shake = hashlib.shake_128(seed + bytes([j, i]))
    buf = shake.digest(840)  # Ample bytes for 256 rejection-sampled coefficients < 3329
    coeffs = []
    idx = 0
    while len(coeffs) < N_DEGREE and idx + 3 <= len(buf):
        b0, b1, b2 = buf[idx], buf[idx + 1], buf[idx + 2]
        d1 = b0 + 256 * (b1 & 0x0F)
        d2 = (b1 >> 4) + 16 * b2
        if d1 < Q_PRIME:
            coeffs.append(d1)
        if d2 < Q_PRIME and len(coeffs) < N_DEGREE:
            coeffs.append(d2)
        idx += 3
    return np.array(coeffs, dtype=np.int64)


def sample_cbd_eta2(seed: bytes, nonce: int) -> np.ndarray:
    """
    Sample a polynomial in R_q from the Centered Binomial Distribution CBD_eta (eta = 2)
    using SHAKE-256(seed || nonce). Each coefficient is in {-2, -1, 0, 1, 2} mod q.
    """
    prf_bytes = hashlib.shake_256(seed + bytes([nonce])).digest(128)  # 64 * eta bytes
    bits = np.unpackbits(np.frombuffer(prf_bytes, dtype=np.uint8), bitorder="little")
    bits = bits.reshape((N_DEGREE, 4))
    a = bits[:, 0].astype(np.int64) + bits[:, 1].astype(np.int64)
    b = bits[:, 2].astype(np.int64) + bits[:, 3].astype(np.int64)
    return (a - b) % Q_PRIME


def encode_message_bits(msg_32: bytes) -> np.ndarray:
    """
    Encode a 32-byte (256-bit) message into a polynomial in R_q with
    coefficients in {0, HALF_Q = 1665}.
    """
    if len(msg_32) != 32:
        raise ValueError("Message must be 32 bytes (256 bits)")
    bits = np.unpackbits(np.frombuffer(msg_32, dtype=np.uint8), bitorder="little")
    return bits.astype(np.int64) * HALF_Q


def decode_message_bits(poly: np.ndarray) -> bytes:
    """
    Decode a noisy polynomial in R_q to a 32-byte (256-bit) message by mapping
    coefficients closer to HALF_Q (1665) to 1 and coefficients closer to 0/q to 0.
    Equivalently: bit = (((coeff * 2) + Q_PRIME // 2) // Q_PRIME) & 1.
    """
    centered = ((poly.astype(np.int64) % Q_PRIME) * 2 + (Q_PRIME // 2)) // Q_PRIME
    bits = (centered & 1).astype(np.uint8)
    packed = np.packbits(bits, bitorder="little")
    return packed.tobytes()


def serialize_poly_vec(vec: np.ndarray) -> bytes:
    """Serialize a vector/array of polynomials in R_q as little-endian uint16."""
    return (vec.astype(np.int64) % Q_PRIME).astype("<u2").tobytes()


def deserialize_poly_vec(raw: bytes, shape: Tuple[int, ...]) -> np.ndarray:
    """Deserialize little-endian uint16 bytes back into a polynomial array."""
    arr = np.frombuffer(raw, dtype="<u2").astype(np.int64)
    return arr.reshape(shape) % Q_PRIME


@dataclass(frozen=True)
class ModuleLWEPublicKey:
    rho: bytes       # 32-byte seed generating A in R_q^{k x k}
    t_bytes: bytes   # Serialized public vector t = A*s + e mod q (k x 256 uint16)

    def to_bytes(self) -> bytes:
        return self.rho + self.t_bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> "ModuleLWEPublicKey":
        expected = 32 + K_RANK * N_DEGREE * 2
        if len(data) != expected:
            raise ValueError(f"Invalid ModuleLWEPublicKey length {len(data)}, expected {expected}")
        return cls(rho=data[:32], t_bytes=data[32:])


@dataclass(frozen=True)
class ModuleLWESecretKey:
    s_bytes: bytes                # Serialized secret vector s in R_q^k
    public_key: ModuleLWEPublicKey
    pk_hash: bytes                # H(pk) = SHA3-256(pk)
    z_reject: bytes               # 32-byte secret seed for FO CCA2 implicit rejection


@dataclass(frozen=True)
class ModuleLWECiphertext:
    u_bytes: bytes  # Serialized u in R_q^k
    v_bytes: bytes  # Serialized v in R_q

    def to_bytes(self) -> bytes:
        return self.u_bytes + self.v_bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> "ModuleLWECiphertext":
        u_len = K_RANK * N_DEGREE * 2
        v_len = N_DEGREE * 2
        if len(data) != u_len + v_len:
            raise ValueError(f"Invalid ModuleLWECiphertext length {len(data)}")
        return cls(u_bytes=data[:u_len], v_bytes=data[u_len:])


@dataclass(frozen=True)
class HybridPublicKey:
    lwe_pk: ModuleLWEPublicKey
    x25519_pk_bytes: bytes

    def to_bytes(self) -> bytes:
        return self.lwe_pk.to_bytes() + self.x25519_pk_bytes

    def fingerprint(self) -> str:
        return hashlib.sha256(self.to_bytes()).hexdigest()[:16]


@dataclass(frozen=True)
class HybridKeyPair:
    public_key: HybridPublicKey
    lwe_sk: ModuleLWESecretKey
    x25519_sk: x25519.X25519PrivateKey


@dataclass(frozen=True)
class HybridCiphertext:
    lwe_ct: ModuleLWECiphertext
    x25519_epk_bytes: bytes

    def to_bytes(self) -> bytes:
        return self.lwe_ct.to_bytes() + self.x25519_epk_bytes

    def to_b64(self) -> str:
        return base64.b64encode(self.to_bytes()).decode("ascii")

    @classmethod
    def from_b64(cls, b64_str: str) -> "HybridCiphertext":
        raw = base64.b64decode(b64_str.encode("ascii"))
        return cls(
            lwe_ct=ModuleLWECiphertext.from_bytes(raw[:-32]),
            x25519_epk_bytes=raw[-32:],
        )


@dataclass(frozen=True)
class DecapsulationResult:
    shared_secret: bytes
    cca2_valid: bool
    cca2_rejected: bool
    lwe_shared_secret: bytes
    x25519_shared_secret: bytes


class ModuleLWEKEM:
    """
    Module-LWE KEM over R_3329 = Z_3329[X]/(X^256 + 1) with a Fujisaki-Okamoto transform
    (deterministic re-encryption, implicit rejection). Not ML-KEM; see the module docstring.
    """

    @staticmethod
    def _expand_matrix_a(rho: bytes) -> np.ndarray:
        matrix = np.zeros((K_RANK, K_RANK, N_DEGREE), dtype=np.int64)
        for i in range(K_RANK):
            for j in range(K_RANK):
                matrix[i, j] = sample_uniform_poly(rho, i, j)
        return matrix

    @classmethod
    def keygen(cls, seed: Optional[bytes] = None) -> Tuple[ModuleLWEPublicKey, ModuleLWESecretKey]:
        if seed is None:
            seed = os.urandom(64)
        elif len(seed) < 64:
            seed = hashlib.sha3_512(seed).digest()

        d_seed = seed[:32]
        z_reject = seed[32:64]
        expanded = hashlib.sha3_512(d_seed + bytes([K_RANK])).digest()
        rho, sigma = expanded[:32], expanded[32:]

        a_mat = cls._expand_matrix_a(rho)
        s_vec = np.zeros((K_RANK, N_DEGREE), dtype=np.int64)
        e_vec = np.zeros((K_RANK, N_DEGREE), dtype=np.int64)
        for i in range(K_RANK):
            s_vec[i] = sample_cbd_eta2(sigma, i)
            e_vec[i] = sample_cbd_eta2(sigma, K_RANK + i)

        # Compute t = A * s + e (mod q)
        t_vec = np.zeros((K_RANK, N_DEGREE), dtype=np.int64)
        for i in range(K_RANK):
            acc = np.zeros(N_DEGREE, dtype=np.int64)
            for j in range(K_RANK):
                acc = poly_add(acc, poly_mul(a_mat[i, j], s_vec[j]))
            t_vec[i] = poly_add(acc, e_vec[i])

        pk = ModuleLWEPublicKey(rho=rho, t_bytes=serialize_poly_vec(t_vec))
        pk_hash = hashlib.sha3_256(pk.to_bytes()).digest()
        sk = ModuleLWESecretKey(
            s_bytes=serialize_poly_vec(s_vec),
            public_key=pk,
            pk_hash=pk_hash,
            z_reject=z_reject,
        )
        return pk, sk

    @classmethod
    def _pke_encrypt(
        cls, pk: ModuleLWEPublicKey, msg_32: bytes, r_coins: bytes
    ) -> ModuleLWECiphertext:
        """
        Deterministic CPAPKE encryption used inside the Fujisaki-Okamoto transform:
            u = A^T * r + e_1 (mod q)
            v = t^T * r + e_2 + encode(m) (mod q)
        """
        a_mat = cls._expand_matrix_a(pk.rho)
        t_vec = deserialize_poly_vec(pk.t_bytes, (K_RANK, N_DEGREE))

        r_vec = np.zeros((K_RANK, N_DEGREE), dtype=np.int64)
        e1_vec = np.zeros((K_RANK, N_DEGREE), dtype=np.int64)
        for i in range(K_RANK):
            r_vec[i] = sample_cbd_eta2(r_coins, i)
            e1_vec[i] = sample_cbd_eta2(r_coins, K_RANK + i)
        e2_poly = sample_cbd_eta2(r_coins, 2 * K_RANK)

        # u = A^T * r + e_1
        u_vec = np.zeros((K_RANK, N_DEGREE), dtype=np.int64)
        for i in range(K_RANK):
            acc = np.zeros(N_DEGREE, dtype=np.int64)
            for j in range(K_RANK):
                acc = poly_add(acc, poly_mul(a_mat[j, i], r_vec[j]))
            u_vec[i] = poly_add(acc, e1_vec[i])

        # v = t^T * r + e_2 + mu
        v_poly = np.zeros(N_DEGREE, dtype=np.int64)
        for i in range(K_RANK):
            v_poly = poly_add(v_poly, poly_mul(t_vec[i], r_vec[i]))
        mu_poly = encode_message_bits(msg_32)
        v_poly = poly_add(poly_add(v_poly, e2_poly), mu_poly)

        return ModuleLWECiphertext(
            u_bytes=serialize_poly_vec(u_vec),
            v_bytes=serialize_poly_vec(v_poly),
        )

    @classmethod
    def _pke_decrypt(cls, sk: ModuleLWESecretKey, ct: ModuleLWECiphertext) -> bytes:
        """
        Decrypt CPAPKE ciphertext: w = v - s^T * u (mod q), then threshold decode.
        """
        s_vec = deserialize_poly_vec(sk.s_bytes, (K_RANK, N_DEGREE))
        u_vec = deserialize_poly_vec(ct.u_bytes, (K_RANK, N_DEGREE))
        v_poly = deserialize_poly_vec(ct.v_bytes, (N_DEGREE,))

        s_dot_u = np.zeros(N_DEGREE, dtype=np.int64)
        for i in range(K_RANK):
            s_dot_u = poly_add(s_dot_u, poly_mul(s_vec[i], u_vec[i]))

        w_poly = poly_sub(v_poly, s_dot_u)
        return decode_message_bits(w_poly)

    @classmethod
    def encapsulate(
        cls, pk: ModuleLWEPublicKey, coins: Optional[bytes] = None
    ) -> Tuple[ModuleLWECiphertext, bytes]:
        """
        FO-CCA2 Encapsulation:
          1. Sample 32-byte random message m = H(coins)
          2. (K_bar, r) = G(m || H(pk)) via SHA3-512
          3. ct = PKE.Encrypt(pk, m; r)
          4. ss = SHAKE-256(K_bar || H(ct), 32)
        """
        raw_coins = coins if coins is not None else os.urandom(32)
        m = hashlib.sha3_256(raw_coins).digest()
        pk_hash = hashlib.sha3_256(pk.to_bytes()).digest()

        g_out = hashlib.sha3_512(m + pk_hash).digest()
        k_bar, r_coins = g_out[:32], g_out[32:]

        ct = cls._pke_encrypt(pk, m, r_coins)
        ct_hash = hashlib.sha3_256(ct.to_bytes()).digest()
        shared_secret = hashlib.shake_256(k_bar + ct_hash).digest(32)
        return ct, shared_secret

    @classmethod
    def decapsulate(
        cls, sk: ModuleLWESecretKey, ct: ModuleLWECiphertext
    ) -> Tuple[bytes, bool]:
        """
        FO-CCA2 Decapsulation with Implicit Rejection:
          1. m' = PKE.Decrypt(sk, ct)
          2. (K'_bar, r') = G(m' || H(pk))
          3. ct' = PKE.Encrypt(pk, m'; r')
          4. If ct == ct' (constant-time): return (SHAKE-256(K'_bar || H(ct), 32), True)
             Else (tampered ciphertext!): return (SHAKE-256(z || H(ct), 32), False)
        """
        m_prime = cls._pke_decrypt(sk, ct)
        g_out = hashlib.sha3_512(m_prime + sk.pk_hash).digest()
        k_bar_prime, r_prime = g_out[:32], g_out[32:]

        ct_reencrypted = cls._pke_encrypt(sk.public_key, m_prime, r_prime)
        ct_bytes = ct.to_bytes()
        ct_hash = hashlib.sha3_256(ct_bytes).digest()

        is_cca2_valid = hmac.compare_digest(ct_bytes, ct_reencrypted.to_bytes())
        if is_cca2_valid:
            ss = hashlib.shake_256(k_bar_prime + ct_hash).digest(32)
            return ss, True
        else:
            # FIPS 203 implicit rejection: deterministic pseudorandom key from secret z
            ss_reject = hashlib.shake_256(sk.z_reject + ct_hash).digest(32)
            return ss_reject, False


class HybridPQCKEM:
    """
    Hybrid KEM pairing the Module-LWE KEM above with X25519 ECDH; the combiner binds both
    shared secrets and the X25519 public values.
    """

    @classmethod
    def keygen(cls, seed: Optional[bytes] = None) -> HybridKeyPair:
        lwe_pk, lwe_sk = ModuleLWEKEM.keygen(seed=seed)
        if seed is not None:
            x_seed = hashlib.sha256(b"X25519-SEED:" + seed).digest()
            x_sk = x25519.X25519PrivateKey.from_private_bytes(x_seed)
        else:
            x_sk = x25519.X25519PrivateKey.generate()
        x_pk_bytes = x_sk.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return HybridKeyPair(
            public_key=HybridPublicKey(lwe_pk=lwe_pk, x25519_pk_bytes=x_pk_bytes),
            lwe_sk=lwe_sk,
            x25519_sk=x_sk,
        )

    @staticmethod
    def _combine_secrets(
        ss_lwe: bytes,
        ss_x25519: bytes,
        x25519_epk: bytes,
        recipient_pk: HybridPublicKey,
        context: bytes = b"HYBRID-KEM-VALID",
    ) -> bytes:
        pk_digest = hashlib.sha256(recipient_pk.to_bytes()).digest()
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=pk_digest,
            info=b"PQCPAYMENT-LWE-X25519:" + context,
        )
        return hkdf.derive(ss_lwe + ss_x25519 + x25519_epk + recipient_pk.x25519_pk_bytes)

    @classmethod
    def encapsulate(
        cls, hybrid_pk: HybridPublicKey, coins: Optional[bytes] = None
    ) -> Tuple[HybridCiphertext, bytes, Dict[str, str]]:
        lwe_ct, ss_lwe = ModuleLWEKEM.encapsulate(hybrid_pk.lwe_pk, coins=coins)

        if coins is not None:
            eph_seed = hashlib.sha256(b"X25519-EPH:" + coins).digest()
            eph_sk = x25519.X25519PrivateKey.from_private_bytes(eph_seed)
        else:
            eph_sk = x25519.X25519PrivateKey.generate()

        eph_pk_bytes = eph_sk.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        peer_x_pk = x25519.X25519PublicKey.from_public_bytes(hybrid_pk.x25519_pk_bytes)
        ss_x25519 = eph_sk.exchange(peer_x_pk)

        ss_hybrid = cls._combine_secrets(ss_lwe, ss_x25519, eph_pk_bytes, hybrid_pk)
        ct = HybridCiphertext(lwe_ct=lwe_ct, x25519_epk_bytes=eph_pk_bytes)
        meta = {
            "ss_lwe_hex": ss_lwe.hex(),
            "ss_x25519_hex": ss_x25519.hex(),
            "ss_hybrid_hex": ss_hybrid.hex(),
            "pk_fingerprint": hybrid_pk.fingerprint(),
            "ciphertext_bytes": str(len(ct.to_bytes())),
        }
        return ct, ss_hybrid, meta

    @classmethod
    def decapsulate(
        cls, keypair: HybridKeyPair, hybrid_ct: HybridCiphertext
    ) -> DecapsulationResult:
        ss_lwe, cca2_valid = ModuleLWEKEM.decapsulate(keypair.lwe_sk, hybrid_ct.lwe_ct)

        peer_eph_pk = x25519.X25519PublicKey.from_public_bytes(hybrid_ct.x25519_epk_bytes)
        ss_x25519 = keypair.x25519_sk.exchange(peer_eph_pk)

        epk = hybrid_ct.x25519_epk_bytes
        if cca2_valid:
            ss_hybrid = cls._combine_secrets(ss_lwe, ss_x25519, epk, keypair.public_key)
        else:
            # Implicit rejection propagates into the hybrid combiner so tampered
            # ciphertexts never yield the sender's shared secret
            ss_hybrid = cls._combine_secrets(
                ss_lwe,
                hashlib.sha256(keypair.lwe_sk.z_reject + hybrid_ct.to_bytes()).digest(),
                epk,
                keypair.public_key,
                context=b"HYBRID-KEM-IMPLICIT-REJECT",
            )

        return DecapsulationResult(
            shared_secret=ss_hybrid,
            cca2_valid=cca2_valid,
            cca2_rejected=not cca2_valid,
            lwe_shared_secret=ss_lwe,
            x25519_shared_secret=ss_x25519,
        )

    @classmethod
    def wrap_envelope(
        cls, hybrid_pk: HybridPublicKey, plaintext: bytes, aad: bytes = b""
    ) -> Dict[str, str]:
        """
        Encapsulate a fresh Hybrid PQC+X25519 key and encrypt `plaintext`
        with AES-256-GCM bound to `aad`.
        """
        ct, ss_hybrid, _ = cls.encapsulate(hybrid_pk)
        nonce = os.urandom(12)
        aesgcm = AESGCM(ss_hybrid)
        ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
        return {
            "kem_ciphertext_b64": ct.to_b64(),
            "aes_nonce_hex": nonce.hex(),
            "wrapped_payload_b64": base64.b64encode(ciphertext).decode("ascii"),
            "pk_fingerprint": hybrid_pk.fingerprint(),
        }

    @classmethod
    def unwrap_envelope(
        cls, keypair: HybridKeyPair, envelope: Dict[str, str], aad: bytes = b""
    ) -> bytes:
        """
        Decapsulate the Hybrid PQC+X25519 ciphertext (enforcing FO-CCA2 validity)
        and decrypt the AES-256-GCM envelope.
        """
        ct = HybridCiphertext.from_b64(envelope["kem_ciphertext_b64"])
        decap = cls.decapsulate(keypair, ct)
        if decap.cca2_rejected:
            raise ValueError("FO-CCA2 integrity check failed: tampered PQC-KEM ciphertext rejected")

        nonce = bytes.fromhex(envelope["aes_nonce_hex"])
        wrapped = base64.b64decode(envelope["wrapped_payload_b64"].encode("ascii"))
        aesgcm = AESGCM(decap.shared_secret)
        return aesgcm.decrypt(nonce, wrapped, aad)
