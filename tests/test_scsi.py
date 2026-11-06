"""Tests for SCSI status parsing, HSB1 retrieval, and unlock routines."""

import struct
import unittest
from typing import List, Tuple
from wd_auto_unlock import (
    AuthError,
    ScsiError,
    ScsiTransport,
    compute_checksum,
    get_encryption_status,
    read_handy_store_block1,
    unlock_drive,
)


class MockScsiTransport(ScsiTransport):
    """In-memory mock transport for unit testing SCSI CDB interactions."""

    def __init__(self):
        self.reads: List[Tuple[bytes, int]] = []
        self.writes: List[Tuple[bytes, bytes]] = []
        self.status_responses: List[bytes] = []
        self.hsb1_response: bytes = b""

    def read(self, cdb: bytes, length: int, timeout_ms: int = 10000) -> bytes:
        self.reads.append((cdb, length))
        if cdb[0] == 0xC0:  # get_encryption_status
            if self.status_responses:
                return self.status_responses.pop(0)
            raise ScsiError("No mock status response queued")
        elif cdb[0] == 0xD8:  # read_handy_store
            return self.hsb1_response
        raise ScsiError(f"Unexpected mock read CDB: {cdb.hex()}")

    def write(self, cdb: bytes, data: bytes, timeout_ms: int = 10000) -> None:
        self.writes.append((cdb, data))


def make_status_block(
    locked_code: int = 0x01,
    cipher_code: int = 0x28,
    password_len: int = 32,
) -> bytes:
    buf = bytearray(512)
    buf[0] = 0x45
    buf[3] = locked_code
    buf[4] = cipher_code
    struct.pack_into("!H", buf, 6, password_len)
    buf[8:12] = b"\x12\x34\x56\x78"  # key reset enabler
    return bytes(buf)


def make_hsb1_block(
    iteration: int = 1000,
    salt: bytes = b"SALT1234",
    hint: bytes = b"Sample hint",
) -> bytes:
    buf = bytearray(512)
    buf[0:4] = b"\x00\x01DW"  # "01WD" signature
    struct.pack_into("<I", buf, 8, iteration)
    buf[12:20] = salt[:8].ljust(8, b"\x00")
    buf[24 : 24 + len(hint)] = hint
    # calculate checksum and place in last byte
    buf[511] = compute_checksum(bytes(buf))
    return bytes(buf)


class TestScsi(unittest.TestCase):
    def test_get_encryption_status_locked(self):
        transport = MockScsiTransport()
        transport.status_responses.append(make_status_block(0x01, 0x28, 32))

        status = get_encryption_status(transport)
        self.assertEqual(status["locked_code"], 0x01)
        self.assertEqual(status["status"], "locked")
        self.assertEqual(status["cipher"], "AES_256_XTS")
        self.assertEqual(status["password_length"], 32)
        self.assertEqual(status["key_reset_enabler"], b"\x12\x34\x56\x78")

    def test_get_encryption_status_invalid_signature(self):
        transport = MockScsiTransport()
        bad_buf = bytearray(512)
        bad_buf[0] = 0x00
        transport.status_responses.append(bytes(bad_buf))

        with self.assertRaises(ScsiError):
            get_encryption_status(transport)

    def test_read_handy_store_block1_valid(self):
        transport = MockScsiTransport()
        transport.hsb1_response = make_hsb1_block(
            iteration=500, salt=b"TESTSALT", hint=b"My clue"
        )

        hsb1 = read_handy_store_block1(transport)
        self.assertIsNotNone(hsb1)
        assert hsb1 is not None
        iteration, salt = hsb1
        self.assertEqual(iteration, 500)
        self.assertEqual(salt, b"TESTSALT")

    def test_read_handy_store_block1_checksum_error(self):
        transport = MockScsiTransport()
        bad_buf = bytearray(make_hsb1_block(iteration=100))
        bad_buf[511] = (bad_buf[511] + 1) % 256  # corrupt checksum
        transport.hsb1_response = bytes(bad_buf)

        with self.assertRaises(ScsiError):
            read_handy_store_block1(transport)

    def test_unlock_drive_already_unlocked(self):
        transport = MockScsiTransport()
        transport.status_responses.append(make_status_block(locked_code=0x02))

        res = unlock_drive(transport, "any_password")
        self.assertTrue(res["success"])
        self.assertTrue(res["already_unlocked"])
        self.assertEqual(len(transport.writes), 0)

    def test_unlock_drive_success(self):
        transport = MockScsiTransport()
        # First call: status is locked
        transport.status_responses.append(make_status_block(locked_code=0x01, password_len=32))
        transport.hsb1_response = make_hsb1_block(iteration=10, salt=b"SALT8888")
        # Post-unlock call: status is unlocked
        transport.status_responses.append(make_status_block(locked_code=0x02, password_len=32))

        res = unlock_drive(transport, "secret123")
        self.assertTrue(res["success"])
        self.assertFalse(res["already_unlocked"])
        self.assertEqual(len(transport.writes), 1)

        cdb, payload = transport.writes[0]
        self.assertEqual(cdb[0], 0xC1)
        self.assertEqual(cdb[1], 0xE1)
        self.assertEqual(cdb[8], 40)  # pwblen(32) + 8 = 40
        self.assertEqual(payload[0], 0x45)
        self.assertEqual(len(payload), 40)

    def test_unlock_drive_wrong_password(self):
        transport = MockScsiTransport()
        # Status initially locked
        transport.status_responses.append(make_status_block(locked_code=0x01, password_len=32))
        transport.hsb1_response = make_hsb1_block(iteration=10, salt=b"SALT8888")
        # Post-unlock call: drive is still locked
        transport.status_responses.append(make_status_block(locked_code=0x01, password_len=32))

        with self.assertRaises(AuthError):
            unlock_drive(transport, "wrong_password")


if __name__ == "__main__":
    unittest.main()
