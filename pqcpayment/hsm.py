"""
Crypto-Agile Post-Quantum HSM Vault, DUKPT-Style Per-Transaction Key Derivation,
and Zero-Downtime Epoch Key Rotation Engine with Tamper-Evident Hash-Chained Audit Log.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import struct
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

from pqcpayment.fpe import (
    FF1Radix10Cipher,
    detect_card_network,
    verify_luhn,
)
from pqcpayment.pqc_kem import (
    HybridKeyPair,
    HybridPQCKEM,
)

COUNTER_MASK_21BIT = 0x1FFFFF  # 21-bit DUKPT transaction counter (max 2,097,151 txns per IPEK)


@dataclass(frozen=True)
class DUKPTTransactionKey:
    ksn: str
    iksn: str
    counter: int
    tree_depth_hops: int
    ipek_fingerprint: str
    working_key_hex: str
    tx_fpe_key: bytes
    tx_mac_key: bytes
    tx_dek_key: bytes


class DUKPTKeyEngine:
    """
    ANSI X9.24-inspired Derived Unique Key Per Transaction (DUKPT) Engine.

    Given a 32-byte Base Derivation Key (BDK) and a 10-byte (20-hex-char) Key
    Serial Number (KSN = 59-bit IKSN device prefix || 21-bit transaction counter):
      1. Derives the Initial PIN/PAN Encryption Key (IPEK) from BDK and IKSN.
      2. Traverses the 21-bit binary derivation tree by iteratively masking each
         set bit of the counter from MSB (bit 20) to LSB (bit 0) through a
         non-reversible one-way PRF (HMAC-SHA256).
      3. Derives domain-separated per-transaction FPE, MAC, and DEK subkeys.
    Compromising any single transaction's working key reveals zero information
    about the BDK, IPEK, or past/future transaction keys.
    """

    @staticmethod
    def format_ksn(terminal_id_hex: str, counter: int) -> str:
        """
        Build a 20-hex-character (80-bit) KSN from a terminal/key-set hex prefix
        and a 21-bit transaction counter (1 <= counter <= 0x1FFFFF).
        """
        clean_prefix = terminal_id_hex.upper().replace(" ", "")
        clean_prefix = (clean_prefix + "F" * 15)[:15]
        base_int = int(clean_prefix, 16) << 20
        ksn_int = (base_int & ~COUNTER_MASK_21BIT) | (counter & COUNTER_MASK_21BIT)
        return f"{ksn_int:020X}"

    @staticmethod
    def derive_ipek(bdk: bytes, ksn_bytes: bytes) -> bytes:
        """
        Derive the 32-byte Initial Key (IPEK) from the BDK and the 80-bit KSN
        with its lower 21 counter bits cleared.
        """
        ksn_int = int.from_bytes(ksn_bytes, "big")
        iksn_int = ksn_int & ~COUNTER_MASK_21BIT
        iksn_bytes = iksn_int.to_bytes(10, "big")
        return hmac.new(bdk, b"DUKPT-IPEK-V1:" + iksn_bytes, hashlib.sha256).digest()

    @staticmethod
    def _non_reversible_step(parent_key: bytes, ksn_reg_int: int) -> bytes:
        """
        One-way tree progression function: derives child intermediate key for a
        partial counter mask.
        """
        reg_bytes = ksn_reg_int.to_bytes(10, "big")
        return hmac.new(parent_key, b"DUKPT-NRKGP:" + reg_bytes, hashlib.sha256).digest()

    @classmethod
    def derive_transaction_key(cls, bdk: bytes, ksn_hex: str) -> DUKPTTransactionKey:
        if len(bdk) != 32:
            raise ValueError("BDK must be 32 bytes (256 bits)")
        clean_ksn = ksn_hex.strip().upper()
        if len(clean_ksn) != 20:
            raise ValueError(f"KSN must be 20 hex characters (80 bits), got {clean_ksn!r}")

        ksn_bytes = bytes.fromhex(clean_ksn)
        ksn_int = int.from_bytes(ksn_bytes, "big")
        iksn_int = ksn_int & ~COUNTER_MASK_21BIT
        counter = ksn_int & COUNTER_MASK_21BIT
        if counter == 0:
            raise ValueError("DUKPT transaction counter must be >= 1")

        ipek = cls.derive_ipek(bdk, ksn_bytes)
        cur_key = ipek
        reg = iksn_int
        hops = 0

        for bit_pos in range(20, -1, -1):
            mask = 1 << bit_pos
            if counter & mask:
                reg |= mask
                cur_key = cls._non_reversible_step(cur_key, reg)
                hops += 1

        tx_fpe_key = hmac.new(cur_key, b"DUKPT-VARIANT:FPE", hashlib.sha256).digest()
        tx_mac_key = hmac.new(cur_key, b"DUKPT-VARIANT:MAC", hashlib.sha256).digest()
        tx_dek_key = hmac.new(cur_key, b"DUKPT-VARIANT:DEK", hashlib.sha256).digest()

        return DUKPTTransactionKey(
            ksn=clean_ksn,
            iksn=f"{iksn_int:020X}",
            counter=counter,
            tree_depth_hops=hops,
            ipek_fingerprint=hashlib.sha256(ipek).hexdigest()[:16],
            working_key_hex=cur_key.hex(),
            tx_fpe_key=tx_fpe_key,
            tx_mac_key=tx_mac_key,
            tx_dek_key=tx_dek_key,
        )


@dataclass
class EpochKeyBundle:
    epoch: int
    hybrid_keypair: HybridKeyPair
    fpe_master_key: bytes
    bdk: bytes
    created_at: str
    status: str = "ACTIVE"  # "ACTIVE" or "RETIRED_READONLY"

    @property
    def fpe_cipher(self) -> FF1Radix10Cipher:
        return FF1Radix10Cipher(self.fpe_master_key)


@dataclass
class VaultRecord:
    record_id: str
    token: str
    legacy_tokens: List[str]
    bin_prefix: str
    last4: str
    network: str
    merchant_id: str
    epoch: int
    ksn: str
    pqc_envelope: Dict[str, str]
    tx_mac_hex: str
    created_at: str
    rotated_at: Optional[str] = None


@dataclass
class AuditLogEntry:
    seq: int
    timestamp: str
    action: str
    epoch: int
    details: Dict[str, object]
    prev_hash: str
    entry_hash: str


class QuantumSafeHSMVault:
    """
    Post-Quantum Payment Card Vault combining:
      1. Bijective Luhn-Preserving FF1-Feistel Tokenization
      2. Module-LWE + X25519 Hybrid PQC-KEM Envelope Wrapping
      3. DUKPT Per-Transaction Key Derivation
      4. Zero-Downtime Epoch Key Rotation with Hash-Chained Audit Log
    """

    def __init__(self, initial_seed: Optional[bytes] = None) -> None:
        self._seed = initial_seed or hashlib.sha256(b"PQCPAYMENT-HSM-GENESIS-SEED-2026").digest()
        self.epochs: Dict[int, EpochKeyBundle] = {}
        self.active_epoch: int = 0
        self.tx_counter: int = 0
        self.records_by_token: Dict[str, VaultRecord] = {}
        self.audit_log: List[AuditLogEntry] = []

        self._initialize_epoch(epoch_num=1, reason="HSM Genesis Provisioning")

    def _append_audit(self, action: str, epoch: int, details: Dict[str, object]) -> AuditLogEntry:
        seq = len(self.audit_log) + 1
        prev_hash = self.audit_log[-1].entry_hash if self.audit_log else "0" * 64
        timestamp = datetime.now(timezone.utc).isoformat()
        payload = json.dumps(
            {
                "seq": seq,
                "timestamp": timestamp,
                "action": action,
                "epoch": epoch,
                "details": details,
                "prev_hash": prev_hash,
            },
            sort_keys=True,
        ).encode("utf-8")
        entry_hash = hashlib.sha256(payload).hexdigest()
        entry = AuditLogEntry(
            seq=seq,
            timestamp=timestamp,
            action=action,
            epoch=epoch,
            details=details,
            prev_hash=prev_hash,
            entry_hash=entry_hash,
        )
        self.audit_log.append(entry)
        return entry

    def _initialize_epoch(self, epoch_num: int, reason: str) -> EpochKeyBundle:
        epoch_seed = hashlib.sha3_512(
            self._seed + struct.pack(">I", epoch_num) + reason.encode("utf-8")
        ).digest()
        hybrid_kp = HybridPQCKEM.keygen(seed=epoch_seed)
        fpe_key = hashlib.sha256(b"EPOCH-FPE-MASTER:" + epoch_seed).digest()
        bdk = hashlib.sha256(b"EPOCH-DUKPT-BDK:" + epoch_seed).digest()

        bundle = EpochKeyBundle(
            epoch=epoch_num,
            hybrid_keypair=hybrid_kp,
            fpe_master_key=fpe_key,
            bdk=bdk,
            created_at=datetime.now(timezone.utc).isoformat(),
            status="ACTIVE",
        )
        self.epochs[epoch_num] = bundle
        self.active_epoch = epoch_num
        self._append_audit(
            action="EPOCH_KEYGEN",
            epoch=epoch_num,
            details={
                "reason": reason,
                "pqc_pk_fingerprint": hybrid_kp.public_key.fingerprint(),
                "fpe_key_fingerprint": hashlib.sha256(fpe_key).hexdigest()[:16],
                "bdk_fingerprint": hashlib.sha256(bdk).hexdigest()[:16],
            },
        )
        return bundle

    @staticmethod
    def _build_tweak(epoch: int, merchant_id: str) -> str:
        return f"EPOCH:{epoch}|MERCH:{merchant_id}"

    @staticmethod
    def _build_aad(epoch: int, merchant_id: str, ksn: str) -> bytes:
        return f"PQCPAYMENT-AAD|EPOCH:{epoch}|MERCH:{merchant_id}|KSN:{ksn}".encode("utf-8")

    def tokenize(
        self,
        pan: str,
        merchant_id: str = "MERCH-GLOBAL-01",
        terminal_id: str = "FFFF987654",
    ) -> Dict[str, object]:
        """
        Tokenize a 16-digit Luhn-valid PAN into a 16-digit Luhn-valid format-preserving
        token, derive a unique DUKPT per-transaction key, and seal the vault envelope
        under the active Epoch's Hybrid PQC-KEM (Module-LWE + X25519) public key.
        """
        t0 = time.perf_counter()
        clean_pan = pan.replace(" ", "").replace("-", "")
        if not verify_luhn(clean_pan):
            raise ValueError(f"PAN {clean_pan!r} is not a valid 16-digit Luhn card number")

        bundle = self.epochs[self.active_epoch]
        self.tx_counter += 1
        ksn = DUKPTKeyEngine.format_ksn(terminal_id, self.tx_counter)
        dukpt_tx = DUKPTKeyEngine.derive_transaction_key(bundle.bdk, ksn)

        tweak = self._build_tweak(bundle.epoch, merchant_id)
        token = bundle.fpe_cipher.encrypt_pan(clean_pan, tweak=tweak)

        # Seal PAN + metadata inside Hybrid PQC-KEM + AES-256-GCM envelope
        aad = self._build_aad(bundle.epoch, merchant_id, ksn)
        envelope_payload = json.dumps(
            {
                "pan": clean_pan,
                "merchant_id": merchant_id,
                "ksn": ksn,
                "epoch": bundle.epoch,
            }
        ).encode("utf-8")
        pqc_envelope = HybridPQCKEM.wrap_envelope(
            bundle.hybrid_keypair.public_key, envelope_payload, aad=aad
        )

        # Authenticate token + envelope with the per-transaction DUKPT MAC key
        tx_mac = hmac.new(
            dukpt_tx.tx_mac_key,
            f"{token}|{ksn}|{pqc_envelope['pk_fingerprint']}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        record_id = f"VREC-{bundle.epoch:02d}-{self.tx_counter:06d}"
        record = VaultRecord(
            record_id=record_id,
            token=token,
            legacy_tokens=[],
            bin_prefix=clean_pan[:6],
            last4=clean_pan[-4:],
            network=detect_card_network(clean_pan),
            merchant_id=merchant_id,
            epoch=bundle.epoch,
            ksn=ksn,
            pqc_envelope=pqc_envelope,
            tx_mac_hex=tx_mac,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        self.records_by_token[token] = record
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        self._append_audit(
            action="TOKENIZE_PAN",
            epoch=bundle.epoch,
            details={
                "record_id": record_id,
                "token_masked": f"{token[:6]}******{token[-4:]}",
                "merchant_id": merchant_id,
                "ksn": ksn,
                "pqc_pk_fingerprint": pqc_envelope["pk_fingerprint"],
            },
        )

        return {
            "record_id": record_id,
            "token": token,
            "token_luhn_valid": verify_luhn(token),
            "bin_prefix": clean_pan[:6],
            "masked_pan": f"{clean_pan[:6]}******{clean_pan[-4:]}",
            "network": record.network,
            "merchant_id": merchant_id,
            "epoch": bundle.epoch,
            "dukpt": {
                "ksn": dukpt_tx.ksn,
                "iksn": dukpt_tx.iksn,
                "counter": dukpt_tx.counter,
                "tree_depth_hops": dukpt_tx.tree_depth_hops,
                "ipek_fingerprint": dukpt_tx.ipek_fingerprint,
                "tx_mac_hex": tx_mac[:32],
            },
            "pqc_envelope": {
                "pk_fingerprint": pqc_envelope["pk_fingerprint"],
                "aes_nonce_hex": pqc_envelope["aes_nonce_hex"],
                "kem_ciphertext_bytes": len(
                    HybridPQCKEM.keygen(seed=b"0" * 64).public_key.to_bytes()
                ),
            },
            "latency_ms": round(elapsed_ms, 3),
        }

    def detokenize(
        self,
        token: str,
        merchant_id: str = "MERCH-GLOBAL-01",
        epoch: Optional[int] = None,
    ) -> Dict[str, object]:
        """
        Detokenize a 16-digit Luhn-valid token back to the original 16-digit PAN.
        Supports both vault-backed dual verification (FF1 inverse + Hybrid PQC-KEM
        envelope decapsulation) and stateless FF1 detokenization.
        """
        t0 = time.perf_counter()
        clean_token = token.replace(" ", "").replace("-", "")
        if not verify_luhn(clean_token):
            raise ValueError(f"Token {clean_token!r} failed Luhn check")

        record = self.records_by_token.get(clean_token)
        target_epoch = epoch or (record.epoch if record is not None else self.active_epoch)
        if target_epoch not in self.epochs:
            raise ValueError(f"Unknown key epoch {target_epoch}")

        bundle = self.epochs[target_epoch]
        eff_merchant = record.merchant_id if record is not None else merchant_id

        # If token was issued under a prior epoch and rotated, resolve the epoch it was minted in
        if record is not None and clean_token in record.legacy_tokens:
            # Unwrap envelope from current record epoch to recover exact PAN even for legacy token
            aad = self._build_aad(record.epoch, record.merchant_id, record.ksn)
            active_bundle = self.epochs[record.epoch]
            unwrapped = json.loads(
                HybridPQCKEM.unwrap_envelope(
                    active_bundle.hybrid_keypair, record.pqc_envelope, aad=aad
                ).decode("utf-8")
            )
            recovered_pan = str(unwrapped["pan"])
            pqc_verified = True
        else:
            tweak = self._build_tweak(target_epoch, eff_merchant)
            recovered_pan = bundle.fpe_cipher.decrypt_token(clean_token, tweak=tweak)
            pqc_verified = False
            if record is not None:
                aad = self._build_aad(record.epoch, record.merchant_id, record.ksn)
                rec_bundle = self.epochs[record.epoch]
                unwrapped = json.loads(
                    HybridPQCKEM.unwrap_envelope(
                        rec_bundle.hybrid_keypair, record.pqc_envelope, aad=aad
                    ).decode("utf-8")
                )
                if unwrapped["pan"] != recovered_pan:
                    raise ValueError("Vault integrity mismatch between FF1 inverse and PQC envelope")
                pqc_verified = True

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        self._append_audit(
            action="DETOKENIZE_TOKEN",
            epoch=target_epoch,
            details={
                "token_masked": f"{clean_token[:6]}******{clean_token[-4:]}",
                "merchant_id": eff_merchant,
                "pqc_envelope_verified": pqc_verified,
            },
        )

        return {
            "token": clean_token,
            "pan": recovered_pan,
            "pan_luhn_valid": verify_luhn(recovered_pan),
            "bin_prefix": recovered_pan[:6],
            "network": detect_card_network(recovered_pan),
            "merchant_id": eff_merchant,
            "epoch": target_epoch,
            "pqc_envelope_verified": pqc_verified,
            "latency_ms": round(elapsed_ms, 3),
        }

    def rotate_epoch(self, reason: str = "Scheduled Zero-Downtime PQC Key Rotation") -> Dict[str, object]:
        """
        Perform Zero-Downtime HSM Key Rotation from Epoch E to Epoch E+1:
          1. Mark Epoch E as RETIRED_READONLY.
          2. Provision Epoch E+1 (new Module-LWE + X25519 HybridKeyPair, FF1 Master Key, BDK).
          3. Re-wrap all vault records from Epoch E to Epoch E+1 without exposing PANs
             outside the HSM boundary, while preserving legacy tokens in `records_by_token`
             so in-flight settlements on Epoch E tokens never fail.
        """
        t0 = time.perf_counter()
        old_epoch = self.active_epoch
        old_bundle = self.epochs[old_epoch]
        old_bundle.status = "RETIRED_READONLY"

        new_epoch = old_epoch + 1
        new_bundle = self._initialize_epoch(epoch_num=new_epoch, reason=reason)

        unique_records = {rec.record_id: rec for rec in self.records_by_token.values()}
        rewrapped_count = 0

        for rec in unique_records.values():
            rec_bundle = self.epochs[rec.epoch]
            old_aad = self._build_aad(rec.epoch, rec.merchant_id, rec.ksn)
            plaintext_bytes = HybridPQCKEM.unwrap_envelope(
                rec_bundle.hybrid_keypair, rec.pqc_envelope, aad=old_aad
            )
            payload_obj = json.loads(plaintext_bytes.decode("utf-8"))
            pan_str = str(payload_obj["pan"])

            # Compute new Epoch E+1 FF1 token
            new_tweak = self._build_tweak(new_epoch, rec.merchant_id)
            new_token = new_bundle.fpe_cipher.encrypt_pan(pan_str, tweak=new_tweak)

            # Re-wrap envelope under Epoch E+1 Hybrid PQC-KEM public key
            payload_obj["epoch"] = new_epoch
            new_aad = self._build_aad(new_epoch, rec.merchant_id, rec.ksn)
            new_envelope = HybridPQCKEM.wrap_envelope(
                new_bundle.hybrid_keypair.public_key,
                json.dumps(payload_obj).encode("utf-8"),
                aad=new_aad,
            )

            if rec.token not in rec.legacy_tokens and rec.token != new_token:
                rec.legacy_tokens.append(rec.token)
            rec.token = new_token
            rec.epoch = new_epoch
            rec.pqc_envelope = new_envelope
            rec.rotated_at = datetime.now(timezone.utc).isoformat()
            self.records_by_token[new_token] = rec
            rewrapped_count += 1

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        audit_entry = self._append_audit(
            action="ZERO_DOWNTIME_ROTATION",
            epoch=new_epoch,
            details={
                "from_epoch": old_epoch,
                "to_epoch": new_epoch,
                "reason": reason,
                "rewrapped_records": rewrapped_count,
                "old_pk_fingerprint": old_bundle.hybrid_keypair.public_key.fingerprint(),
                "new_pk_fingerprint": new_bundle.hybrid_keypair.public_key.fingerprint(),
            },
        )

        return {
            "previous_epoch": old_epoch,
            "active_epoch": new_epoch,
            "reason": reason,
            "rewrapped_records": rewrapped_count,
            "old_pk_fingerprint": old_bundle.hybrid_keypair.public_key.fingerprint(),
            "new_pk_fingerprint": new_bundle.hybrid_keypair.public_key.fingerprint(),
            "audit_entry_hash": audit_entry.entry_hash,
            "audit_chain_valid": self.verify_audit_log()["valid"],
            "latency_ms": round(elapsed_ms, 3),
        }

    def verify_audit_log(self) -> Dict[str, object]:
        """
        Verify the cryptographic integrity of the SHA-256 hash-chained audit log.
        """
        prev = "0" * 64
        for entry in self.audit_log:
            if entry.prev_hash != prev:
                return {"valid": False, "failed_seq": entry.seq}
            payload = json.dumps(
                {
                    "seq": entry.seq,
                    "timestamp": entry.timestamp,
                    "action": entry.action,
                    "epoch": entry.epoch,
                    "details": entry.details,
                    "prev_hash": entry.prev_hash,
                },
                sort_keys=True,
            ).encode("utf-8")
            expected_hash = hashlib.sha256(payload).hexdigest()
            if not hmac.compare_digest(expected_hash, entry.entry_hash):
                return {"valid": False, "failed_seq": entry.seq}
            prev = entry.entry_hash

        return {
            "valid": True,
            "entries_count": len(self.audit_log),
            "head_hash": prev,
        }

    def status_summary(self) -> Dict[str, object]:
        unique_records = {rec.record_id: rec for rec in self.records_by_token.values()}
        audit_status = self.verify_audit_log()
        return {
            "active_epoch": self.active_epoch,
            "total_epochs": len(self.epochs),
            "tx_counter": self.tx_counter,
            "vault_records": len(unique_records),
            "active_pk_fingerprint": self.epochs[
                self.active_epoch
            ].hybrid_keypair.public_key.fingerprint(),
            "audit_chain": audit_status,
            "epochs": [
                {
                    "epoch": b.epoch,
                    "status": b.status,
                    "pk_fingerprint": b.hybrid_keypair.public_key.fingerprint(),
                    "created_at": b.created_at,
                }
                for b in self.epochs.values()
            ],
        }
