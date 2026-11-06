"""Tests for CLI arguments, subcommands, output formats, and system operations."""

import io
import json
import unittest
from unittest.mock import MagicMock, patch
from tests.test_scsi import MockScsiTransport, make_hsb1_block, make_status_block
from wd_auto_unlock import (
    build_parser,
    cmd_status,
    cmd_unlock,
    cmd_unmount,
    main,
    mount_device,
    rescan_kernel_device,
    unmount_path,
    wait_for_uuid,
)


class TestCli(unittest.TestCase):
    def test_parser_subcommands(self):
        parser = build_parser()

        args = parser.parse_args(["unlock", "-d", "/dev/sdb", "-p", "pass"])
        self.assertEqual(args.command, "unlock")
        self.assertEqual(args.device, "/dev/sdb")
        self.assertEqual(args.password, "pass")

        args_status = parser.parse_args(["status", "-d", "/dev/sdb", "--json"])
        self.assertEqual(args_status.command, "status")
        self.assertEqual(args_status.device, "/dev/sdb")
        self.assertTrue(args_status.json)

        args_unmount = parser.parse_args(["unmount", "-m", "/media/WD"])
        self.assertEqual(args_unmount.command, "unmount")
        self.assertEqual(args_unmount.mount_point, "/media/WD")

    def test_options_before_subcommand_not_overwritten(self):
        parser = build_parser()
        args = parser.parse_args(["-p", "mysecret", "-d", "/dev/sdb", "unlock"])
        self.assertEqual(args.password, "mysecret")
        self.assertEqual(args.device, "/dev/sdb")
        self.assertEqual(args.command, "unlock")

    def test_cmd_status_plain(self):
        transport = MockScsiTransport()
        transport.status_responses.append(make_status_block(locked_code=0x01))

        with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
            ret = cmd_status("/dev/sdb", as_json=False, transport=transport)
            output = mock_stdout.getvalue()

        self.assertEqual(ret, 0)
        self.assertIn("Security Status: locked", output)
        self.assertIn("Device:          /dev/sdb", output)

    def test_cmd_status_json(self):
        transport = MockScsiTransport()
        transport.status_responses.append(make_status_block(locked_code=0x02))

        with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
            ret = cmd_status("/dev/sdb", as_json=True, transport=transport)
            output = mock_stdout.getvalue()

        self.assertEqual(ret, 0)
        data = json.loads(output)
        self.assertTrue(data["success"])
        self.assertEqual(data["device"], "/dev/sdb")
        self.assertEqual(data["security_status"], "unlocked")
        self.assertEqual(data["locked_code"], 2)

    def test_cmd_unlock_missing_password_when_locked(self):
        transport = MockScsiTransport()
        transport.status_responses.append(make_status_block(locked_code=0x01))

        with patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
            ret = cmd_unlock(
                device_path="/dev/sdb",
                password=None,
                uuid=None,
                mount_point=None,
                timeout=30,
                as_json=False,
                transport=transport,
            )
            err = mock_stderr.getvalue()

        self.assertEqual(ret, 2)
        self.assertIn("No password provided", err)

    def test_cmd_unlock_already_unlocked_needs_no_password(self):
        transport = MockScsiTransport()
        transport.status_responses.append(make_status_block(locked_code=0x02))

        with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout, patch(
            "wd_auto_unlock.rescan_kernel_device"
        ):
            ret = cmd_unlock(
                device_path="/dev/sdb",
                password=None,
                uuid=None,
                mount_point=None,
                timeout=30,
                as_json=True,
                transport=transport,
            )
            output = mock_stdout.getvalue()

        self.assertEqual(ret, 0)
        data = json.loads(output)
        self.assertTrue(data["success"])
        self.assertTrue(data["already_unlocked"])

    def test_cmd_unlock_success_json(self):
        transport = MockScsiTransport()
        transport.status_responses.append(make_status_block(locked_code=0x01))
        transport.hsb1_response = make_hsb1_block(iteration=10)
        transport.status_responses.append(make_status_block(locked_code=0x02))

        with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout, patch(
            "wd_auto_unlock.rescan_kernel_device"
        ):
            ret = cmd_unlock(
                device_path="/dev/sdb",
                password="mypassword",
                uuid=None,
                mount_point=None,
                timeout=30,
                as_json=True,
                transport=transport,
            )
            output = mock_stdout.getvalue()

        self.assertEqual(ret, 0)
        data = json.loads(output)
        self.assertTrue(data["success"])
        self.assertEqual(data["status"], "unlocked")

    def test_cmd_unmount_missing_mountpoint(self):
        with patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
            ret = cmd_unmount(mount_point=None, as_json=False)
            err = mock_stderr.getvalue()

        self.assertEqual(ret, 2)
        self.assertIn("No mount point specified", err)

    def test_cmd_unmount_success(self):
        with patch("wd_auto_unlock.unmount_path", return_value=True), patch(
            "sys.stdout", new_callable=io.StringIO
        ) as mock_stdout:
            ret = cmd_unmount(mount_point="/mnt/wd", as_json=True)
            output = mock_stdout.getvalue()

        self.assertEqual(ret, 0)
        data = json.loads(output)
        self.assertTrue(data["success"])
        self.assertEqual(data["mount_point"], "/mnt/wd")
        self.assertFalse(data["already_unmounted"])

    def test_cmd_unmount_already_unmounted(self):
        with patch("wd_auto_unlock.unmount_path", return_value=False), patch(
            "sys.stdout", new_callable=io.StringIO
        ) as mock_stdout:
            ret = cmd_unmount(mount_point="/mnt/wd", as_json=True)
            output = mock_stdout.getvalue()

        self.assertEqual(ret, 0)
        data = json.loads(output)
        self.assertTrue(data["success"])
        self.assertTrue(data["already_unmounted"])

    def test_main_cli_device_not_found(self):
        with patch("wd_auto_unlock.find_passport_devices", return_value=[]), patch(
            "sys.stderr", new_callable=io.StringIO
        ) as mock_stderr:
            ret = main(["status", "-c", "/nonexistent.conf"])
            err = mock_stderr.getvalue()

        self.assertEqual(ret, 1)
        self.assertIn("No Western Digital My Passport device found", err)

    def test_mount_device_already_mounted(self):
        with patch("os.path.ismount", return_value=True):
            self.assertTrue(mount_device("/dev/sdb1", "/media/WD"))

    def test_mount_device_command_exec(self):
        with patch("os.path.ismount", return_value=False), patch(
            "os.makedirs"
        ), patch("subprocess.run") as mock_run:
            mock_proc = MagicMock()
            mock_proc.returncode = 0
            mock_run.return_value = mock_proc

            res = mount_device("/dev/sdb1", "/media/WD")
            self.assertTrue(res)
            mock_run.assert_called_once()

    def test_unmount_path_not_mounted(self):
        with patch("os.path.ismount", return_value=False):
            self.assertFalse(unmount_path("/media/WD"))

    def test_unmount_path_command_exec(self):
        with patch("os.path.ismount", return_value=True), patch(
            "subprocess.run"
        ) as mock_run:
            mock_proc = MagicMock()
            mock_proc.returncode = 0
            mock_run.return_value = mock_proc

            self.assertTrue(unmount_path("/media/WD"))

    def test_wait_for_uuid_found(self):
        with patch("os.path.exists", return_value=True), patch(
            "os.path.realpath", return_value="/dev/sdb1"
        ):
            path = wait_for_uuid("88E2-42DF", timeout=1)
            self.assertEqual(path, "/dev/sdb1")

    def test_wait_for_uuid_timeout(self):
        with patch("os.path.exists", return_value=False), patch("time.sleep"):
            path = wait_for_uuid("NONEXISTENT", timeout=0)
            self.assertIsNone(path)

    def test_rescan_kernel_device(self):
        with patch("subprocess.run") as mock_run, patch("os.path.isfile", return_value=False):
            mock_proc = MagicMock()
            mock_proc.returncode = 0
            mock_run.return_value = mock_proc
            rescan_kernel_device("/dev/sdb")
            mock_run.assert_called()


if __name__ == "__main__":
    unittest.main()
