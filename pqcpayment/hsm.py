"""
Software model of a card vault: FF1 tokens, hybrid-KEM envelopes, DUKPT-style
per-transaction keys, epoch key rotation and an HMAC-chained audit log.

Despite the class name this is not an HSM: keys are sealed at rest under a master key from
the environment, and unsealed into Python process memory to be used.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import struct
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.exc import IntegrityError

from pqcpayment import db
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
    DUKPT-style key derivation, modelled on ANSI X9.24 but not compatible with it
    (X9.24-3 AES DUKPT uses AES-based derivation; this uses HMAC-SHA256).

    Given a 32-byte Base Derivation Key (BDK) and a 10-byte (20-hex-char) Key
    Serial Number (KSN = 59-bit IKSN device prefix || 21-bit transaction counter):
      1. Derives the initial key (IPEK) from BDK and IKSN.
      2. Walks the 21-bit derivation tree, one HMAC-SHA256 step per set bit of the
         counter from bit 20 down to bit 0.
      3. Derives separate FPE, MAC and DEK subkeys from the result.
    A transaction key doesn't reveal the BDK, the IPEK or its ancestors, but it does give
    every key below it in the tree (counter 4's key derives counter 5's). Real DUKPT devices
    erase keys as they go to limit that; nothing here models the device side.
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

    @property
    def fpe_cipher(self) -> FF1Radix10Cipher:
        return FF1Radix10Cipher(self.fpe_master_key)


@dataclass
class AuditLogEntry:
    seq: int
    timestamp: str
    action: str
    epoch: int
    details: Dict[str, object]
    prev_hash: str
    entry_hash: str


class _Conflict(Exception):
    """Another replica changed a row this transaction read; run the operation again."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _audit_payload(e: Dict[str, object]) -> bytes:
    return json.dumps({k: e[k] for k in ("seq", "timestamp", "action", "epoch", "details", "prev_hash")},
                      sort_keys=True).encode("utf-8")


class QuantumSafeHSMVault:
    """
    Card vault combining:
      1. Luhn-preserving FF1 tokens (one tweak per epoch and merchant)
      2. ML-KEM-768 + X25519 envelopes holding the PAN
      3. DUKPT-style per-transaction keys (the MAC they produce is stored, not checked)
      4. Epoch key rotation that keeps earlier tokens working, with an HMAC-chained audit log

    Records, the token index, the audit log and every epoch's keys live in a database (db.py).
    Epoch keys are sealed with AES-256-GCM under the master key, so a database dump alone opens
    nothing. Each operation is one transaction under a per-process lock; replicas sharing the
    database detect each other through primary keys and counter checks and retry.
    """

    def __init__(
        self,
        engine: Optional[Engine] = None,
        master_key: Optional[bytes] = None,
        audit_key: Optional[bytes] = None,
        previous_master_keys: Tuple[bytes, ...] = (),
        previous_audit_keys: Tuple[bytes, ...] = (),
        initial_seed: Optional[bytes] = None,
    ) -> None:
        # initial_seed makes every key reproducible, for tests only. Without it each epoch
        # gets fresh random keys, so one epoch's keys say nothing about another's.
        self._seed = initial_seed
        self.db = engine or db.connect("sqlite://")
        if master_key is None:
            master_key = hashlib.sha256(b"MASTER:" + initial_seed).digest() if initial_seed else AESGCM.generate_key(bit_length=256)
        self._master = [AESGCM(k) for k in (master_key, *previous_master_keys)]  # first one seals
        # Audit entries are HMAC-chained: a plain hash chain can be rewritten and re-hashed
        # by anyone who can edit the log, a keyed one only by someone holding this key
        if audit_key is None:
            audit_key = hashlib.sha256(b"AUDIT-MAC:" + initial_seed).digest() if initial_seed else os.urandom(32)
        self._audit_keys = (audit_key, *previous_audit_keys)
        self._bundles: Dict[int, EpochKeyBundle] = {}  # unsealed keys, by epoch (they never change)
        self._lock = threading.Lock()  # ponytail: per process; replicas are caught by keys and counter checks
        self._tx(lambda c: None if self._active(c) else self._initialize_epoch(c, 1, "HSM Genesis Provisioning"))

    # --- plumbing ------------------------------------------------------------------------

    def _tx(self, fn):
        """Run fn in one transaction under the process lock; again if another replica won a race."""
        for attempt in range(3):
            try:
                with self._lock, self.db.begin() as c:
                    return fn(c)
            except Exception as e:
                self._bundles.clear()  # it may hold keys of an epoch the rollback just removed
                if attempt == 2 or not isinstance(e, (IntegrityError, _Conflict)):
                    raise
        raise AssertionError("unreachable")

    def _read(self, fn):
        with self._lock, self.db.connect() as c:
            return fn(c)

    def _seal(self, data: bytes, aad: str) -> str:
        nonce = os.urandom(12)
        return base64.b64encode(nonce + self._master[0].encrypt(nonce, data, aad.encode())).decode()

    def _unseal(self, sealed: str, aad: str) -> bytes:
        raw = base64.b64decode(sealed)
        for aead in self._master:
            try:
                return aead.decrypt(raw[:12], raw[12:], aad.encode())
            except InvalidTag:
                continue
        raise ValueError("cannot unseal epoch keys: wrong master key, or the key they were sealed with was rotated out")

    @staticmethod
    def _active(c: Connection) -> int:
        return c.execute(text("SELECT MAX(epoch) FROM epochs")).scalar() or 0

    def _bundle(self, c: Connection, epoch: int) -> EpochKeyBundle:
        if epoch not in self._bundles:
            sealed = c.execute(text("SELECT sealed_keys FROM epochs WHERE epoch = :e"), {"e": epoch}).scalar_one()
            k = json.loads(self._unseal(sealed, f"epoch|{epoch}"))
            self._bundles[epoch] = EpochKeyBundle(
                epoch=epoch,
                hybrid_keypair=HybridKeyPair.from_private_bytes(base64.b64decode(k["kem"])),
                fpe_master_key=base64.b64decode(k["fpe"]),
                bdk=base64.b64decode(k["bdk"]),
            )
        return self._bundles[epoch]

    def _append_audit(self, c: Connection, action: str, epoch: int, details: Dict[str, object]) -> AuditLogEntry:
        last = c.execute(text("SELECT seq, entry FROM audit_log ORDER BY seq DESC LIMIT 1")).first()
        entry = {"seq": last.seq + 1 if last else 1, "timestamp": _now(), "action": action, "epoch": epoch,
                 "details": details, "prev_hash": json.loads(last.entry)["entry_hash"] if last else "0" * 64}
        entry["entry_hash"] = hmac.new(self._audit_keys[0], _audit_payload(entry), hashlib.sha256).hexdigest()
        c.execute(text("INSERT INTO audit_log (seq, entry) VALUES (:s, :e)"), {"s": entry["seq"], "e": json.dumps(entry)})
        return AuditLogEntry(**entry)

    def _initialize_epoch(self, c: Connection, epoch_num: int, reason: str) -> EpochKeyBundle:
        if self._seed is None:
            epoch_seed = os.urandom(64)
        else:
            epoch_seed = hashlib.sha3_512(self._seed + struct.pack(">I", epoch_num)).digest()
        bundle = EpochKeyBundle(
            epoch=epoch_num,
            hybrid_keypair=HybridPQCKEM.keygen(seed=epoch_seed),
            fpe_master_key=hashlib.sha256(b"EPOCH-FPE-MASTER:" + epoch_seed).digest(),
            bdk=hashlib.sha256(b"EPOCH-DUKPT-BDK:" + epoch_seed).digest(),
        )
        keys = json.dumps({"kem": base64.b64encode(bundle.hybrid_keypair.private_bytes()).decode(),
                           "fpe": base64.b64encode(bundle.fpe_master_key).decode(),
                           "bdk": base64.b64encode(bundle.bdk).decode()}).encode()
        fingerprint = bundle.hybrid_keypair.public_key.fingerprint()
        c.execute(text("INSERT INTO epochs (epoch, status, created_at, pk_fingerprint, tx_counter, sealed_keys) "
                       "VALUES (:e, 'ACTIVE', :t, :f, 0, :k)"),
                  {"e": epoch_num, "t": _now(), "f": fingerprint, "k": self._seal(keys, f"epoch|{epoch_num}")})
        self._bundles[epoch_num] = bundle
        self._append_audit(c, "EPOCH_KEYGEN", epoch_num, {
            "reason": reason,
            "pqc_pk_fingerprint": fingerprint,
            "fpe_key_fingerprint": hashlib.sha256(bundle.fpe_master_key).hexdigest()[:16],
            "bdk_fingerprint": hashlib.sha256(bundle.bdk).hexdigest()[:16],
        })
        return bundle

    @staticmethod
    def _index(c: Connection, merchant_id: str, token: str, record_id: str, legacy: bool = False) -> None:
        # A new token can equal an older epoch's token for a different card. The new one wins,
        # and the stale legacy token stops resolving instead of returning the wrong card.
        c.execute(text("DELETE FROM tokens WHERE merchant_id = :m AND token = :t"), {"m": merchant_id, "t": token})
        c.execute(text("INSERT INTO tokens (merchant_id, token, record_id, legacy) VALUES (:m, :t, :r, :l)"),
                  {"m": merchant_id, "t": token, "r": record_id, "l": int(legacy)})

    @staticmethod
    def _build_tweak(epoch: int, merchant_id: str) -> str:
        return f"EPOCH:{epoch}|MERCH:{merchant_id}"

    @staticmethod
    def _build_aad(epoch: int, merchant_id: str, ksn: str) -> bytes:
        return f"PQCPAYMENT-AAD|EPOCH:{epoch}|MERCH:{merchant_id}|KSN:{ksn}".encode("utf-8")

    # --- what tests and the API read -------------------------------------------------------

    @property
    def active_epoch(self) -> int:
        return self._read(self._active)

    @property
    def epochs(self) -> Dict[int, EpochKeyBundle]:
        def run(c: Connection) -> Dict[int, EpochKeyBundle]:
            return {e: self._bundle(c, e) for (e,) in c.execute(text("SELECT epoch FROM epochs ORDER BY epoch"))}

        return self._read(run)

    @property
    def tx_counter(self) -> int:
        return self._read(lambda c: c.execute(text("SELECT tx_counter FROM epochs WHERE epoch = :e"),
                                              {"e": self._active(c)}).scalar_one())

    @tx_counter.setter
    def tx_counter(self, value: int) -> None:  # tests only
        self._tx(lambda c: c.execute(text("UPDATE epochs SET tx_counter = :n WHERE epoch = :e"),
                                     {"n": value, "e": self._active(c)}))

    def token_count(self) -> int:
        return self._read(lambda c: c.execute(text("SELECT COUNT(*) FROM tokens")).scalar())

    def audit_tail(self, n: int = 10) -> List[AuditLogEntry]:
        rows = self._read(lambda c: c.execute(text("SELECT entry FROM audit_log ORDER BY seq DESC LIMIT :n"), {"n": n}).all())
        return [AuditLogEntry(**json.loads(r.entry)) for r in reversed(rows)]

    # --- operations ------------------------------------------------------------------------

    def tokenize(
        self,
        pan: str,
        merchant_id: str = "MERCH-GLOBAL-01",
        terminal_id: str = "FFFF987654",
    ) -> Dict[str, object]:
        """
        Tokenize a 16-digit Luhn-valid PAN into a 16-digit Luhn-valid format-preserving
        token, derive a unique DUKPT per-transaction key, and seal the vault envelope
        under the active epoch's hybrid ML-KEM-768 + X25519 public key.
        """
        t0 = time.perf_counter()
        clean_pan = pan.replace(" ", "").replace("-", "")
        if not verify_luhn(clean_pan):
            raise ValueError("PAN is not a valid 16-digit Luhn card number")

        def run(c: Connection) -> Dict[str, object]:
            epoch = self._active(c)
            bundle = self._bundle(c, epoch)
            counter = c.execute(text("SELECT tx_counter FROM epochs WHERE epoch = :e"), {"e": epoch}).scalar_one()
            if counter >= COUNTER_MASK_21BIT:
                # format_ksn masks the counter to 21 bits, so going on would reuse KSNs and keys
                raise ValueError("DUKPT counter exhausted for this epoch; rotate keys")
            n = counter + 1
            if c.execute(text("UPDATE epochs SET tx_counter = :n WHERE epoch = :e AND tx_counter = :old"),
                         {"n": n, "e": epoch, "old": counter}).rowcount != 1:
                raise _Conflict
            ksn = DUKPTKeyEngine.format_ksn(terminal_id, n)
            dukpt_tx = DUKPTKeyEngine.derive_transaction_key(bundle.bdk, ksn)
            token = bundle.fpe_cipher.encrypt_pan(clean_pan, tweak=self._build_tweak(epoch, merchant_id))

            # Seal PAN + metadata inside an ML-KEM-768 + X25519 / AES-256-GCM envelope
            payload = json.dumps({"pan": clean_pan, "merchant_id": merchant_id, "ksn": ksn, "epoch": epoch}).encode()
            envelope = HybridPQCKEM.wrap_envelope(bundle.hybrid_keypair.public_key, payload,
                                                  aad=self._build_aad(epoch, merchant_id, ksn))
            # Authenticate token + envelope with the per-transaction DUKPT MAC key
            tx_mac = hmac.new(dukpt_tx.tx_mac_key, f"{token}|{ksn}|{envelope['pk_fingerprint']}".encode(),
                              hashlib.sha256).hexdigest()

            record_id = f"VREC-{epoch:02d}-{n:06d}"
            record = {"bin_prefix": clean_pan[:6], "last4": clean_pan[-4:], "network": detect_card_network(clean_pan),
                      "ksn": ksn, "pqc_envelope": envelope, "tx_mac_hex": tx_mac, "created_at": _now(), "rotated_at": None}
            c.execute(text("INSERT INTO records (record_id, merchant_id, epoch, token, doc) VALUES (:r, :m, :e, :t, :d)"),
                      {"r": record_id, "m": merchant_id, "e": epoch, "t": token, "d": json.dumps(record)})
            self._index(c, merchant_id, token, record_id)
            self._append_audit(c, "TOKENIZE_PAN", epoch, {
                "record_id": record_id,
                "token_masked": f"{token[:6]}******{token[-4:]}",
                "merchant_id": merchant_id,
                "ksn": ksn,
                "pqc_pk_fingerprint": envelope["pk_fingerprint"],
            })
            return {
                "record_id": record_id,
                "token": token,
                "token_luhn_valid": verify_luhn(token),
                "bin_prefix": clean_pan[:6],
                "masked_pan": f"{clean_pan[:6]}******{clean_pan[-4:]}",
                "network": record["network"],
                "merchant_id": merchant_id,
                "epoch": epoch,
                "dukpt": {
                    "ksn": dukpt_tx.ksn,
                    "iksn": dukpt_tx.iksn,
                    "counter": dukpt_tx.counter,
                    "tree_depth_hops": dukpt_tx.tree_depth_hops,
                    "ipek_fingerprint": dukpt_tx.ipek_fingerprint,
                    "tx_mac_hex": tx_mac[:32],
                },
                "pqc_envelope": {
                    "pk_fingerprint": envelope["pk_fingerprint"],
                    "aes_nonce_hex": envelope["aes_nonce_hex"],
                    "kem_ciphertext_bytes": len(base64.b64decode(envelope["kem_ciphertext_b64"])),
                },
            }

        out = self._tx(run)
        out["latency_ms"] = round((time.perf_counter() - t0) * 1000.0, 3)
        return out

    def detokenize(self, token: str, merchant_id: str) -> Dict[str, object]:
        """
        Return the PAN for a token this vault issued to `merchant_id` (in the current epoch,
        or an earlier one if the token predates a rotation). The PAN comes from the KEM
        envelope; for a current token it must also equal the FF1 inverse.
        """
        t0 = time.perf_counter()
        clean_token = token.replace(" ", "").replace("-", "")

        def run(c: Connection) -> Dict[str, object]:
            row = c.execute(text("SELECT r.epoch, r.doc, t.legacy FROM tokens t JOIN records r ON r.record_id = t.record_id "
                                 "WHERE t.merchant_id = :m AND t.token = :t"), {"m": merchant_id, "t": clean_token}).first()
            if row is None:
                # FF1 is a permutation, so an unissued token would still "decrypt" to a
                # plausible PAN; only answer for tokens on record for this merchant
                raise ValueError("Unknown token for this merchant")
            rec, bundle = json.loads(row.doc), self._bundle(c, row.epoch)
            unwrapped = json.loads(HybridPQCKEM.unwrap_envelope(
                bundle.hybrid_keypair, rec["pqc_envelope"], aad=self._build_aad(row.epoch, merchant_id, rec["ksn"])))
            recovered_pan = str(unwrapped["pan"])
            is_legacy = bool(row.legacy)
            if not is_legacy:
                fpe_pan = bundle.fpe_cipher.decrypt_token(clean_token, tweak=self._build_tweak(row.epoch, merchant_id))
                if not hmac.compare_digest(fpe_pan, recovered_pan):
                    raise ValueError("Vault integrity mismatch between FF1 inverse and PQC envelope")
            self._append_audit(c, "DETOKENIZE_TOKEN", row.epoch, {
                "token_masked": f"{clean_token[:6]}******{clean_token[-4:]}",
                "merchant_id": merchant_id,
                "legacy_token": is_legacy,
            })
            return {
                "token": clean_token,
                "pan": recovered_pan,
                "pan_luhn_valid": verify_luhn(recovered_pan),
                "bin_prefix": recovered_pan[:6],
                "network": detect_card_network(recovered_pan),
                "merchant_id": merchant_id,
                "epoch": row.epoch,
                "legacy_token": is_legacy,
            }

        out = self._tx(run)
        out["latency_ms"] = round((time.perf_counter() - t0) * 1000.0, 3)
        return out

    def rotate_epoch(self, reason: str = "Scheduled Zero-Downtime PQC Key Rotation") -> Dict[str, object]:
        """
        Rotate from epoch E to E+1:
          1. Mark epoch E as RETIRED_READONLY (its keys are kept, since legacy tokens need them).
          2. Create epoch E+1 keys (KEM keypair, FF1 key, BDK); its DUKPT counter starts at 0.
          3. Decrypt every record and re-wrap it under E+1 with a new token, keeping the old
             token as a legacy alias so tokens issued before the rotation still resolve.
        ponytail: one transaction over every record, so the vault is busy for the duration;
        rotate in batches if the vault grows large.
        """
        t0 = time.perf_counter()

        def run(c: Connection) -> Dict[str, object]:
            old_epoch = self._active(c)
            old_fp = self._bundle(c, old_epoch).hybrid_keypair.public_key.fingerprint()
            c.execute(text("UPDATE epochs SET status = 'RETIRED_READONLY' WHERE epoch = :e"), {"e": old_epoch})
            new_epoch = old_epoch + 1
            new_bundle = self._initialize_epoch(c, new_epoch, reason)
            rows = c.execute(text("SELECT record_id, merchant_id, epoch, doc FROM records")).all()
            moved = []
            for r in rows:
                rec = json.loads(r.doc)
                payload = json.loads(HybridPQCKEM.unwrap_envelope(
                    self._bundle(c, r.epoch).hybrid_keypair, rec["pqc_envelope"],
                    aad=self._build_aad(r.epoch, r.merchant_id, rec["ksn"])))
                new_token = new_bundle.fpe_cipher.encrypt_pan(str(payload["pan"]), tweak=self._build_tweak(new_epoch, r.merchant_id))
                payload["epoch"] = new_epoch
                rec["pqc_envelope"] = HybridPQCKEM.wrap_envelope(new_bundle.hybrid_keypair.public_key, json.dumps(payload).encode(),
                                                                 aad=self._build_aad(new_epoch, r.merchant_id, rec["ksn"]))
                rec["rotated_at"] = _now()
                c.execute(text("UPDATE records SET epoch = :e, token = :t, doc = :d WHERE record_id = :r"),
                          {"e": new_epoch, "t": new_token, "d": json.dumps(rec), "r": r.record_id})
                moved.append((r.merchant_id, new_token, r.record_id))
            # Every old token becomes a legacy alias first, then the new tokens are indexed, so a
            # new token that collides with an old one replaces it
            c.execute(text("UPDATE tokens SET legacy = 1"))
            for m, t, rid in moved:
                self._index(c, m, t, rid)
            new_fp = new_bundle.hybrid_keypair.public_key.fingerprint()
            entry = self._append_audit(c, "ZERO_DOWNTIME_ROTATION", new_epoch, {
                "from_epoch": old_epoch,
                "to_epoch": new_epoch,
                "reason": reason,
                "rewrapped_records": len(moved),
                "old_pk_fingerprint": old_fp,
                "new_pk_fingerprint": new_fp,
            })
            return {
                "previous_epoch": old_epoch,
                "active_epoch": new_epoch,
                "reason": reason,
                "rewrapped_records": len(moved),
                "old_pk_fingerprint": old_fp,
                "new_pk_fingerprint": new_fp,
                "audit_entry_hash": entry.entry_hash,
            }

        out = self._tx(run)
        out["audit_chain_valid"] = self.verify_audit_log()["valid"]
        out["latency_ms"] = round((time.perf_counter() - t0) * 1000.0, 3)
        return out

    def verify_audit_log(self) -> Dict[str, object]:
        """
        Verify the HMAC-SHA256 chain over the audit log (needs this vault's audit key, or a
        previous one for entries written before a rotation).
        ponytail: walks the whole log; keep a verified checkpoint if it gets long.
        """
        rows = self._read(lambda c: c.execute(text("SELECT seq, entry FROM audit_log ORDER BY seq")).all())
        prev = "0" * 64
        for expected_seq, r in enumerate(rows, start=1):
            e = json.loads(r.entry)
            if r.seq != expected_seq or e["seq"] != r.seq or e["prev_hash"] != prev:
                return {"valid": False, "failed_seq": r.seq}
            payload = _audit_payload(e)
            if not any(hmac.compare_digest(hmac.new(k, payload, hashlib.sha256).hexdigest(), e["entry_hash"])
                       for k in self._audit_keys):
                return {"valid": False, "failed_seq": r.seq}
            prev = e["entry_hash"]
        return {"valid": True, "entries_count": len(rows), "head_hash": prev}

    def status_summary(self) -> Dict[str, object]:
        def run(c: Connection) -> Dict[str, object]:
            epochs = c.execute(text("SELECT epoch, status, pk_fingerprint, created_at, tx_counter FROM epochs ORDER BY epoch")).all()
            return {
                "active_epoch": epochs[-1].epoch,
                "total_epochs": len(epochs),
                "tx_counter": epochs[-1].tx_counter,
                "vault_records": c.execute(text("SELECT COUNT(*) FROM records")).scalar(),
                "active_pk_fingerprint": epochs[-1].pk_fingerprint,
                "epochs": [{"epoch": e.epoch, "status": e.status, "pk_fingerprint": e.pk_fingerprint,
                            "created_at": e.created_at} for e in epochs],
            }

        out = self._read(run)
        out["audit_chain"] = self.verify_audit_log()
        return out
