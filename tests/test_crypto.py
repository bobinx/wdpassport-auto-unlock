"""Tests for cryptographic key derivation and checksum functions."""

import hashlib
import unittest
from wd_auto_unlock import compute_checksum, derive_password_key


class TestCrypto(unittest.TestCase):
    def test_compute_checksum_basic(self):
        # Construct a 512-byte buffer
        buf = bytearray(512)
        buf[0] = 0x01
        buf[1] = 0x02
        # total = sum(buf[:510]) + buf[0] = 3 + 1 = 4
        # checksum = (-4) & 0xFF = 252
        expected = (-4) & 0xFF
        self.assertEqual(compute_checksum(bytes(buf)), expected)

    def test_compute_checksum_invalid_length(self):
        with self.assertRaises(ValueError):
            compute_checksum(b"too_short")

    def test_derive_password_key(self):
        # In WD drives, salt is stored as null-spaced characters (e.g. 4 chars across 8 bytes)
        salt = b"T\x00E\x00S\x00T\x00"
        password = "secret_password"
        iteration = 10

        key = derive_password_key(password, iteration, salt)
        self.assertEqual(len(key), 32)  # SHA-256 output is 32 bytes

        # Independently verify: clean salt is "TEST"
        expected_str = "TEST" + password
        expected_bytes = expected_str.encode("utf-16le")
        for _ in range(iteration):
            expected_bytes = hashlib.sha256(expected_bytes).digest()

        self.assertEqual(key, expected_bytes)

    def test_derive_password_key_null_terminated_salt(self):
        # WD Passport salt uses null bytes as terminator if shorter than 8 bytes
        salt = b"S\x00A\x00\x00\x00\x00\x00"
        password = "pwd"
        iteration = 1

        key = derive_password_key(password, iteration, salt)
        expected_str = "SA" + password
        expected_bytes = hashlib.sha256(expected_str.encode("utf-16le")).digest()
        self.assertEqual(key, expected_bytes)


if __name__ == "__main__":
    unittest.main()
