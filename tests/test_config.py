"""Tests for configuration file handling, precedence, and permission checks."""

import io
import os
import tempfile
import unittest
from unittest.mock import patch
from wd_auto_unlock import DeviceNotFoundError, load_config, resolve_device


class TestConfig(unittest.TestCase):
    def test_load_config_nonexistent_default(self):
        with patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
            cfg = load_config("/etc/wdpassport.conf")
            self.assertEqual(cfg, {})
            self.assertEqual(mock_stderr.getvalue(), "")

    def test_load_config_nonexistent_explicit_warns(self):
        with patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
            cfg = load_config("/custom/missing.conf")
            self.assertEqual(cfg, {})
            self.assertIn("Warning: Configuration file not found", mock_stderr.getvalue())

    def test_load_config_loose_permissions_warns(self):
        with tempfile.NamedTemporaryFile("w+", delete=False) as f:
            f.write("[wdpassport]\npassword = test\n")
            temp_path = f.name

        try:
            os.chmod(temp_path, 0o644)  # Loose permissions
            with patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
                cfg = load_config(temp_path)
                self.assertEqual(cfg.get("password"), "test")
                self.assertIn("loose permissions", mock_stderr.getvalue())
        finally:
            os.remove(temp_path)

    def test_load_config_valid(self):
        with tempfile.NamedTemporaryFile("w+", delete=False) as f:
            f.write("""[wdpassport]
password = mysecret
uuid = 88E2-42DF
mount_point = /mnt/wd
device = /dev/sdb
timeout = 45
""")
            temp_path = f.name

        try:
            os.chmod(temp_path, 0o600)
            cfg = load_config(temp_path)
            self.assertEqual(cfg.get("password"), "mysecret")
            self.assertEqual(cfg.get("uuid"), "88E2-42DF")
            self.assertEqual(cfg.get("mount_point"), "/mnt/wd")
            self.assertEqual(cfg.get("device"), "/dev/sdb")
            self.assertEqual(cfg.get("timeout"), "45")
        finally:
            os.remove(temp_path)

    def test_resolve_device_precedence(self):
        # CLI flag takes precedence over config
        dev = resolve_device("/dev/sdc", "/dev/sdb")
        self.assertEqual(dev, "/dev/sdc")

        # Config used if CLI flag is None
        dev = resolve_device(None, "/dev/sdb")
        self.assertEqual(dev, "/dev/sdb")

    def test_resolve_device_none_raises_when_no_discovery(self):
        # Mock discovery returning empty list to isolate from host hardware
        with patch("wd_auto_unlock.find_passport_devices", return_value=[]):
            with self.assertRaises(DeviceNotFoundError):
                resolve_device(None, None)


if __name__ == "__main__":
    unittest.main()
