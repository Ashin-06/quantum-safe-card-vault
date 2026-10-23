"""
Format-preserving card tokenization with FF1 (NIST SP 800-38G Rev. 1).

`FF1` implements Algorithms 7 and 8 of SP 800-38G Rev. 1 over AES, for radix 2-36,
and is checked against all nine NIST sample vectors in the tests. It is a reference
implementation in Python: not constant-time and not reviewed.

Card tokens:
    PAN = BIN (6 digits) || account digits (9) || Luhn check digit (1)
The 9 account digits are encrypted with FF1 (radix 10, AES-256) under the tweak
"BIN:<bin>|TWEAK:<tweak>", and the check digit is recomputed. So for a fixed BIN and
tweak, tokenization is a permutation of the 10^9 Luhn-valid PANs with that BIN: every
token is a Luhn-valid 16-digit number with the same BIN, and decryption is exact.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyz"


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
    Best-guess payment network from the leading digits. RuPay and Discover share the
    60/65 ranges, so telling them apart for sure needs a BIN table; this checks the
    Discover-specific prefixes first.
    """
    if len(pan) < 6 or not pan[:6].isdigit():
        return "UNKNOWN"
    b2 = int(pan[:2])
    b3 = int(pan[:3])
    b4 = int(pan[:4])
    if pan.startswith("4"):
        return "VISA"
    if 51 <= b2 <= 55 or 2221 <= b4 <= 2720:
        return "MASTERCARD"
    if pan.startswith("6011") or 644 <= b3 <= 649:
        return "DISCOVER"
    if b2 in (60, 65, 81, 82) or pan.startswith("508"):
        return "RUPAY"
    return "ISO8583_GENERIC"


class FF1:
    """NIST SP 800-38G Rev. 1 FF1 with AES-128/192/256, radix 2..36, alphabet 0-9a-z."""

    def __init__(self, key: bytes, radix: int = 10) -> None:
        if len(key) not in (16, 24, 32):
            raise ValueError("FF1 key must be 16, 24 or 32 bytes")
        if not 2 <= radix <= len(ALPHABET):
            raise ValueError("radix must be between 2 and 36")
        self._key = bytes(key)
        self.radix = radix

    def _ciph(self, block: bytes) -> bytes:
        enc = Cipher(algorithms.AES(self._key), modes.ECB()).encryptor()
        return enc.update(block) + enc.finalize()

    def _prf(self, data: bytes) -> bytes:
        # CBC-MAC with a zero IV: the last block of AES-CBC (data is a multiple of 16 bytes)
        enc = Cipher(algorithms.AES(self._key), modes.CBC(bytes(16))).encryptor()
        return (enc.update(data) + enc.finalize())[-16:]

    def _str(self, x: int, m: int) -> str:
        out = []
        for _ in range(m):
            x, r = divmod(x, self.radix)
            out.append(ALPHABET[r])
        return "".join(reversed(out))

    def _feistel(self, X: str, tweak: bytes, decrypt: bool) -> str:
        radix, n, t = self.radix, len(X), len(tweak)
        if n < 2 or radix**n < 1_000_000:
            raise ValueError("FF1 domain too small: need radix**len >= 1,000,000")
        if any(c not in ALPHABET[:radix] for c in X):
            raise ValueError(f"input must use the first {radix} characters of {ALPHABET!r}")

        u, v = n // 2, n - n // 2
        A, B = X[:u], X[u:]
        b = -(-(radix**v - 1).bit_length() // 8)  # ceil(ceil(v * log2(radix)) / 8)
        d = 4 * -(-b // 4) + 4
        P = (bytes([1, 2, 1]) + radix.to_bytes(3, "big") + bytes([10, u % 256])
             + n.to_bytes(4, "big") + t.to_bytes(4, "big"))

        for i in (range(9, -1, -1) if decrypt else range(10)):
            m = u if i % 2 == 0 else v
            src = A if decrypt else B
            Q = tweak + bytes((-t - b - 1) % 16) + bytes([i]) + int(src, radix).to_bytes(b, "big")
            R = self._prf(P + Q)
            S = R + b"".join(
                self._ciph((int.from_bytes(R, "big") ^ j).to_bytes(16, "big"))
                for j in range(1, -(-d // 16))
            )
            y = int.from_bytes(S[:d], "big")
            if decrypt:
                B, A = A, self._str((int(B, radix) - y) % radix**m, m)
            else:
                A, B = B, self._str((int(A, radix) + y) % radix**m, m)
        return A + B

    def encrypt(self, plaintext: str, tweak: bytes = b"") -> str:
        return self._feistel(plaintext, tweak, decrypt=False)

    def decrypt(self, ciphertext: str, tweak: bytes = b"") -> str:
        return self._feistel(ciphertext, tweak, decrypt=True)


class FF1Radix10Cipher:
    """
    Tokenizes 16-digit Luhn-valid PANs with FF1 (AES-256) over the 9 digits between the
    6-digit BIN and the check digit.
    """

    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError("FF1Radix10Cipher requires a 32-byte (256-bit) key")
        self._ff1 = FF1(key, radix=10)

    def encrypt_middle_9(self, payload_9: str, tweak: str = "default") -> str:
        """Encrypt a 9-digit decimal string to another 9-digit decimal string."""
        if len(payload_9) != 9 or not payload_9.isdigit():
            raise ValueError(f"payload_9 must be 9 decimal digits, got {payload_9!r}")
        return self._ff1.encrypt(payload_9, tweak.encode("utf-8"))

    def decrypt_middle_9(self, cipher_9: str, tweak: str = "default") -> str:
        """Invert encrypt_middle_9."""
        if len(cipher_9) != 9 or not cipher_9.isdigit():
            raise ValueError(f"cipher_9 must be 9 decimal digits, got {cipher_9!r}")
        return self._ff1.decrypt(cipher_9, tweak.encode("utf-8"))

    def encrypt_pan(self, pan: str, tweak: str = "default") -> str:
        """
        Encrypt a 16-digit Luhn-valid PAN into a 16-digit Luhn-valid token
        preserving the 6-digit issuer BIN prefix.
        """
        clean_pan = pan.replace(" ", "").replace("-", "")
        if not verify_luhn(clean_pan):
            raise ValueError("Input PAN is not a valid 16-digit Luhn card number")

        bin_prefix = clean_pan[:6]
        cipher_9 = self.encrypt_middle_9(clean_pan[6:15], f"BIN:{bin_prefix}|TWEAK:{tweak}")
        token_first_15 = bin_prefix + cipher_9
        return token_first_15 + compute_luhn_check_digit(token_first_15)

    def decrypt_token(self, token: str, tweak: str = "default") -> str:
        """
        Decrypt a 16-digit Luhn-valid token back into the exact original
        16-digit Luhn-valid PAN.
        """
        clean_token = token.replace(" ", "").replace("-", "")
        if not verify_luhn(clean_token):
            raise ValueError("Input token failed Luhn integrity check")

        bin_prefix = clean_token[:6]
        payload_9 = self.decrypt_middle_9(clean_token[6:15], f"BIN:{bin_prefix}|TWEAK:{tweak}")
        pan_first_15 = bin_prefix + payload_9
        return pan_first_15 + compute_luhn_check_digit(pan_first_15)
