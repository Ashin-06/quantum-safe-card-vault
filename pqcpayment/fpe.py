"""
Radix-10 Format-Preserving Encryption (FF1 / Balanced Feistel Network with Tweak)
& Bijective Luhn-Preserving Payment Card Tokenization.

Mathematical Bijection Guarantee:
---------------------------------
Every 16-digit Luhn-valid Primary Account Number (PAN) has the structure:
    PAN = BIN (6 digits) || AccountPayload (9 digits) || LuhnCheck (1 digit)

Because the original PAN is Luhn-valid, its 16th digit is a deterministic
function of its first 15 digits:
    PAN[15] = LuhnCheck(PAN[0:15])

Therefore, encrypting the middle 9 digits PAN[6:15] bijectively via a 10-round
Luby-Rackoff Feistel network over Z_{10^4} x Z_{10^5} (keyed by AES-256 +
HMAC-SHA256 with the 6-digit BIN and merchant/epoch tweak) and recomputing the
Luhn check digit for the 16th position of the token guarantees that:
  1. Every output token is a 100% Luhn-valid 16-digit card number with the
     exact same 6-digit issuer BIN (drop-in compatible with legacy ISO 8583 switches).
  2. Decryption strips the token's Luhn check digit, runs the inverse 10-round
     Feistel network on token[6:15], and recomputes the original PAN's Luhn
     check digit — achieving a 100% exact, collision-free bijection over all
     10^9 Luhn-valid cards per BIN.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass
from typing import Dict, List, Tuple

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

MOD_LEFT = 10_000    # 10^4 (4 digits: 0000..9999)
MOD_RIGHT = 100_000  # 10^5 (5 digits: 00000..99999)


def compute_luhn_check_digit(first_15_digits: str) -> str:
    """
    Compute the ISO/IEC 7812-1 Luhn check digit for a 15-digit prefix.
    """
    if len(first_15_digits) != 15 or not first_15_digits.isdigit():
        raise ValueError(f"Expected 15 decimal digits, got {first_15_digits!r}")

    total = 0
    # In a 16-digit PAN, indices 0, 2, 4, ..., 14 (from left, 0-based) are doubled
    for idx, ch in enumerate(first_15_digits):
        d = ord(ch) - 48
        if idx % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    check = (10 - (total % 10)) % 10
    return str(check)


def verify_luhn(pan: str) -> bool:
    """
    Verify whether a 16-digit PAN or token satisfies the Luhn checksum.
    """
    if not isinstance(pan, str) or len(pan) != 16 or not pan.isdigit():
        return False
    return compute_luhn_check_digit(pan[:15]) == pan[15]


def generate_luhn_pan(bin_prefix: str = "453201", account_seq: int = 1) -> str:
    """
    Deterministically construct a 16-digit Luhn-valid PAN given a 6-digit BIN
    and a 9-digit account sequence number (0 <= account_seq < 10^9).
    """
    if len(bin_prefix) != 6 or not bin_prefix.isdigit():
        raise ValueError(f"BIN prefix must be 6 digits, got {bin_prefix!r}")
    payload_9 = f"{account_seq % 1_000_000_000:09d}"
    first_15 = bin_prefix + payload_9
    return first_15 + compute_luhn_check_digit(first_15)


def detect_card_network(pan: str) -> str:
    """
    Identify payment network from the 6-digit BIN prefix.
    """
    if len(pan) < 6 or not pan[:6].isdigit():
        return "UNKNOWN"
    b2 = int(pan[:2])
    b4 = int(pan[:4])
    if pan.startswith("4"):
        return "VISA"
    if 51 <= b2 <= 55 or 2221 <= b4 <= 2720:
        return "MASTERCARD"
    if b2 in (60, 65, 81, 82) or pan.startswith("508"):
        return "RUPAY"
    if pan.startswith("6011") or pan.startswith("64"):
        return "DISCOVER"
    return "ISO8583_GENERIC"


@dataclass(frozen=True)
class FeistelRoundTrace:
    round_index: int
    left_4: str
    right_5: str
    prf_output: int


class FF1Radix10Cipher:
    """
    10-Round Format-Preserving Feistel Cipher over Z_{10^4} x Z_{10^5}
    with AES-256 + HMAC-SHA256 Pseudo-Random Function (PRF) and Tweak.
    """

    def __init__(self, key: bytes, rounds: int = 10) -> None:
        if len(key) != 32:
            raise ValueError("FF1Radix10Cipher requires a 32-byte (256-bit) key")
        if rounds < 8 or rounds % 2 != 0:
            raise ValueError("Feistel rounds must be an even integer >= 8")
        self._key = bytes(key)
        self.rounds = rounds
        # Derive distinct AES-256 and HMAC subkeys via SHA-256 domain separation
        self._aes_key = hashlib.sha256(b"FF1-AES-SUBKEY:" + self._key).digest()
        self._hmac_key = hashlib.sha256(b"FF1-MAC-SUBKEY:" + self._key).digest()
        self._aes_cipher = Cipher(algorithms.AES(self._aes_key), modes.ECB())

    def _round_prf(self, tweak_bytes: bytes, round_idx: int, half_val: int) -> int:
        """
        Cryptographic round function F_K(tweak, round_idx, half_val).
        Combines a single-block AES-256-ECB encryption of the round state
        with an HMAC-SHA256 digest over the arbitrary-length tweak.
        """
        tweak_digest = hashlib.sha256(tweak_bytes).digest()[:8]
        block = struct.pack(">BBHI8s", 0x01, round_idx, 10, half_val, tweak_digest)
        encryptor = self._aes_cipher.encryptor()
        aes_out = encryptor.update(block) + encryptor.finalize()
        mac = hmac.new(
            self._hmac_key,
            aes_out + struct.pack(">BI", round_idx, half_val) + tweak_bytes,
            hashlib.sha256,
        ).digest()
        return int.from_bytes(mac[:8], "big")

    def encrypt_middle_9(
        self, payload_9: str, tweak: str = "default"
    ) -> Tuple[str, List[FeistelRoundTrace]]:
        """
        Encrypt a 9-digit decimal string bijectively into a 9-digit decimal string
        using a 10-round alternating Feistel network over Z_{10^4} x Z_{10^5}.
        """
        if len(payload_9) != 9 or not payload_9.isdigit():
            raise ValueError(f"payload_9 must be 9 decimal digits, got {payload_9!r}")

        left = int(payload_9[:4])   # in Z_{10^4}
        right = int(payload_9[4:])  # in Z_{10^5}
        tweak_bytes = tweak.encode("utf-8")
        traces: List[FeistelRoundTrace] = []

        for r in range(self.rounds):
            if r % 2 == 0:
                f_val = self._round_prf(tweak_bytes, r, right)
                left = (left + f_val) % MOD_LEFT
            else:
                f_val = self._round_prf(tweak_bytes, r, left)
                right = (right + f_val) % MOD_RIGHT
            traces.append(
                FeistelRoundTrace(
                    round_index=r,
                    left_4=f"{left:04d}",
                    right_5=f"{right:05d}",
                    prf_output=f_val,
                )
            )

        return f"{left:04d}{right:05d}", traces

    def decrypt_middle_9(self, cipher_9: str, tweak: str = "default") -> str:
        """
        Invert the 10-round alternating Feistel network on a 9-digit ciphertext.
        """
        if len(cipher_9) != 9 or not cipher_9.isdigit():
            raise ValueError(f"cipher_9 must be 9 decimal digits, got {cipher_9!r}")

        left = int(cipher_9[:4])   # in Z_{10^4}
        right = int(cipher_9[4:])  # in Z_{10^5}
        tweak_bytes = tweak.encode("utf-8")

        for r in range(self.rounds - 1, -1, -1):
            if r % 2 == 1:
                f_val = self._round_prf(tweak_bytes, r, left)
                right = (right - f_val) % MOD_RIGHT
            else:
                f_val = self._round_prf(tweak_bytes, r, right)
                left = (left - f_val) % MOD_LEFT

        return f"{left:04d}{right:05d}"

    def encrypt_pan(self, pan: str, tweak: str = "default") -> str:
        """
        Encrypt a 16-digit Luhn-valid PAN into a 16-digit Luhn-valid token
        preserving the 6-digit issuer BIN prefix.
        """
        clean_pan = pan.replace(" ", "").replace("-", "")
        if not verify_luhn(clean_pan):
            raise ValueError(f"Input PAN {clean_pan!r} is not a valid 16-digit Luhn card number")

        bin_prefix = clean_pan[:6]
        payload_9 = clean_pan[6:15]
        effective_tweak = f"BIN:{bin_prefix}|TWEAK:{tweak}"

        cipher_9, _ = self.encrypt_middle_9(payload_9, effective_tweak)
        token_first_15 = bin_prefix + cipher_9
        token_check = compute_luhn_check_digit(token_first_15)
        return token_first_15 + token_check

    def decrypt_token(self, token: str, tweak: str = "default") -> str:
        """
        Decrypt a 16-digit Luhn-valid token back into the exact original
        16-digit Luhn-valid PAN.
        """
        clean_token = token.replace(" ", "").replace("-", "")
        if not verify_luhn(clean_token):
            raise ValueError(f"Input token {clean_token!r} failed Luhn integrity check")

        bin_prefix = clean_token[:6]
        cipher_9 = clean_token[6:15]
        effective_tweak = f"BIN:{bin_prefix}|TWEAK:{tweak}"

        payload_9 = self.decrypt_middle_9(cipher_9, effective_tweak)
        pan_first_15 = bin_prefix + payload_9
        orig_check = compute_luhn_check_digit(pan_first_15)
        return pan_first_15 + orig_check

    def encrypt_pan_with_trace(self, pan: str, tweak: str = "default") -> Dict[str, object]:
        """
        Encrypt a 16-digit Luhn-valid PAN and return detailed round-by-round
        Feistel diagnostics for auditing and UI inspection.
        """
        clean_pan = pan.replace(" ", "").replace("-", "")
        if not verify_luhn(clean_pan):
            raise ValueError(f"Input PAN {clean_pan!r} is not a valid 16-digit Luhn card number")

        bin_prefix = clean_pan[:6]
        payload_9 = clean_pan[6:15]
        effective_tweak = f"BIN:{bin_prefix}|TWEAK:{tweak}"

        cipher_9, traces = self.encrypt_middle_9(payload_9, effective_tweak)
        token_first_15 = bin_prefix + cipher_9
        token_check = compute_luhn_check_digit(token_first_15)
        token = token_first_15 + token_check

        return {
            "bin_prefix": bin_prefix,
            "network": detect_card_network(clean_pan),
            "original_middle_9": payload_9,
            "encrypted_middle_9": cipher_9,
            "original_luhn_digit": clean_pan[15],
            "token_luhn_digit": token_check,
            "token": token,
            "token_luhn_valid": verify_luhn(token),
            "effective_tweak": effective_tweak,
            "rounds": [
                {
                    "round": t.round_index + 1,
                    "left_4": t.left_4,
                    "right_5": t.right_5,
                    "prf_mod": t.prf_output % (MOD_LEFT if t.round_index % 2 == 0 else MOD_RIGHT),
                }
                for t in traces
            ],
        }
