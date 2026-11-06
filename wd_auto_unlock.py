#!/usr/bin/env python3
"""WD Passport Auto Unlock & Mount.

Single-purpose, zero-dependency Linux utility to unlock and mount
Western Digital My Passport hardware-encrypted drives.
"""

from __future__ import annotations

import argparse
import configparser
import ctypes
import hashlib
import json
import os
import struct
import subprocess
import sys
import time
from typing import Any, Optional

try:
    import fcntl
except ImportError:
    fcntl = None  # type: ignore[assignment]

__version__ = "1.0.0"

BLOCK_SIZE = 512
DEFAULT_CONFIG_PATH = "/etc/wdpassport.conf"

SECURITY_STATUS_MAP = {
    0x00: "no_lock",
    0x01: "locked",
    0x02: "unlocked",
    0x06: "locked_blocked",
    0x07: "no_keys",
}

CIPHER_MAP = {
    0x10: "AES_128_ECB",
    0x12: "AES_128_CBC",
    0x18: "AES_128_XTS",
    0x20: "AES_256_ECB",
    0x22: "AES_256_CBC",
    0x28: "AES_256_XTS",
    0x30: "Full Disk Encryption",
}


# --- Linux SG_IO ioctl structures ---

class SgioHdr(ctypes.Structure):
    """Linux struct sg_io_hdr from <scsi/sg.h>."""
    _fields_ = [
        ("interface_id", ctypes.c_int),
        ("dxfer_direction", ctypes.c_int),
        ("cmd_len", ctypes.c_ubyte),
        ("mx_sb_len", ctypes.c_ubyte),
        ("iovec_count", ctypes.c_ushort),
        ("dxfer_len", ctypes.c_uint),
        ("dxferp", ctypes.c_void_p),
        ("cmdp", ctypes.c_void_p),
        ("sbp", ctypes.c_void_p),
        ("timeout", ctypes.c_uint),
        ("flags", ctypes.c_uint),
        ("pack_id", ctypes.c_int),
        ("usr_ptr", ctypes.c_void_p),
        ("status", ctypes.c_ubyte),
        ("masked_status", ctypes.c_ubyte),
        ("msg_status", ctypes.c_ubyte),
        ("sb_len_wr", ctypes.c_ubyte),
        ("host_status", ctypes.c_ushort),
        ("driver_status", ctypes.c_ushort),
        ("resid", ctypes.c_int),
        ("duration", ctypes.c_uint),
        ("info", ctypes.c_uint),
    ]


SG_IO = 0x2285
SG_DXFER_TO_DEV = -2
SG_DXFER_FROM_DEV = -3


class ScsiError(RuntimeError):
    """Raised when a SCSI command or transport error occurs."""
    pass


class DeviceNotFoundError(RuntimeError):
    """Raised when target WD Passport drive cannot be found."""
    pass


class AuthError(RuntimeError):
    """Raised when drive unlock fails due to invalid password."""
    pass


# --- Transport Abstraction ---

class ScsiTransport:
    """Abstract interface for sending SCSI commands."""

    def read(self, cdb: bytes, length: int, timeout_ms: int = 10000) -> bytes:
        raise NotImplementedError

    def write(self, cdb: bytes, data: bytes, timeout_ms: int = 10000) -> None:
        raise NotImplementedError

    def close(self) -> None:
        pass

    def __enter__(self) -> ScsiTransport:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()


class LinuxSgioTransport(ScsiTransport):
    """Sends SCSI commands directly via Linux SG_IO ioctl."""

    def __init__(self, device_path: str):
        if fcntl is None:
            raise ScsiError("Linux SCSI transport requires the fcntl module")

        self.device_path = device_path
        flags = os.O_RDWR | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
        try:
            self.fd: Optional[int] = os.open(device_path, flags)
        except PermissionError:
            raise PermissionError(
                f"Permission denied accessing {device_path}. Run as root or with sudo."
            )
        except OSError as exc:
            raise ScsiError(f"Failed to open device {device_path}: {exc}") from exc

    def read(self, cdb: bytes, length: int, timeout_ms: int = 10000) -> bytes:
        if self.fd is None:
            raise ScsiError("Transport is closed")

        data_buf = (ctypes.c_ubyte * length)()
        sense_buf = (ctypes.c_ubyte * 32)()
        cdb_buf = (ctypes.c_ubyte * len(cdb)).from_buffer_copy(cdb)

        hdr = SgioHdr()
        hdr.interface_id = ord("S")
        hdr.dxfer_direction = SG_DXFER_FROM_DEV
        hdr.cmd_len = len(cdb)
        hdr.mx_sb_len = ctypes.sizeof(sense_buf)
        hdr.dxfer_len = length
        hdr.dxferp = ctypes.cast(data_buf, ctypes.c_void_p)
        hdr.cmdp = ctypes.cast(cdb_buf, ctypes.c_void_p)
        hdr.sbp = ctypes.cast(sense_buf, ctypes.c_void_p)
        hdr.timeout = timeout_ms

        try:
            fcntl.ioctl(self.fd, SG_IO, hdr)
        except OSError as exc:
            raise ScsiError(f"SCSI read ioctl failed on {self.device_path}: {exc}") from exc

        if hdr.status != 0 or hdr.host_status != 0 or hdr.driver_status != 0:
            raise ScsiError(
                f"SCSI read failed on {self.device_path}: status=0x{hdr.status:02x}, "
                f"host=0x{hdr.host_status:04x}, driver=0x{hdr.driver_status:04x}"
            )

        return bytes(data_buf)

    def write(self, cdb: bytes, data: bytes, timeout_ms: int = 10000) -> None:
        if self.fd is None:
            raise ScsiError("Transport is closed")

        data_buf = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
        sense_buf = (ctypes.c_ubyte * 32)()
        cdb_buf = (ctypes.c_ubyte * len(cdb)).from_buffer_copy(cdb)

        hdr = SgioHdr()
        hdr.interface_id = ord("S")
        hdr.dxfer_direction = SG_DXFER_TO_DEV
        hdr.cmd_len = len(cdb)
        hdr.mx_sb_len = ctypes.sizeof(sense_buf)
        hdr.dxfer_len = len(data)
        hdr.dxferp = ctypes.cast(data_buf, ctypes.c_void_p)
        hdr.cmdp = ctypes.cast(cdb_buf, ctypes.c_void_p)
        hdr.sbp = ctypes.cast(sense_buf, ctypes.c_void_p)
        hdr.timeout = timeout_ms

        try:
            fcntl.ioctl(self.fd, SG_IO, hdr)
        except OSError as exc:
            raise ScsiError(f"SCSI write ioctl failed on {self.device_path}: {exc}") from exc

        if hdr.status != 0 or hdr.host_status != 0 or hdr.driver_status != 0:
            raise ScsiError(
                f"SCSI write failed on {self.device_path}: status=0x{hdr.status:02x}, "
                f"host=0x{hdr.host_status:04x}, driver=0x{hdr.driver_status:04x}"
            )

    def close(self) -> None:
        if getattr(self, "fd", None) is not None:
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = None

    def __del__(self) -> None:
        self.close()


# --- Core Cryptographic & SCSI Logic ---

def compute_checksum(data: bytes) -> int:
    """Computes the Western Digital Handy Store Block checksum."""
    if len(data) < 510:
        raise ValueError("Data block must be at least 510 bytes")
    total = sum(data[:510]) + data[0]
    return (-total) & 0xFF


def derive_password_key(password: str, iteration: int, salt: bytes) -> bytes:
    """Derives the unlock key from passphrase, salt, and iteration count."""
    salt_padded = salt + b"\x00\x00"
    clean_chars = []
    for i in range(len(salt_padded) // 2):
        b0 = salt_padded[2 * i]
        b1 = salt_padded[2 * i + 1]
        if b0 == 0 and b1 == 0:
            break
        clean_chars.append(chr(b0))
    clean_salt = "".join(clean_chars)

    # Encode with UTF-16LE without BOM
    key = (clean_salt + password).encode("utf-16le")
    for _ in range(iteration):
        key = hashlib.sha256(key).digest()
    return key


def get_encryption_status(transport: ScsiTransport) -> dict[str, Any]:
    """Queries drive encryption and lock status."""
    cdb = bytes([0xC0, 0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x00])
    data = transport.read(cdb, BLOCK_SIZE)

    if len(data) < 12 or data[0] != 0x45:
        sig = hex(data[0]) if data else "empty"
        raise ScsiError(f"Invalid encryption status response signature: {sig}")

    locked_code = data[3]
    cipher_code = data[4]
    password_len = struct.unpack("!H", data[6:8])[0]
    key_reset_enabler = data[8:12]

    return {
        "locked_code": locked_code,
        "status": SECURITY_STATUS_MAP.get(locked_code, f"unknown (0x{locked_code:02x})"),
        "cipher_code": cipher_code,
        "cipher": CIPHER_MAP.get(cipher_code, f"unknown (0x{cipher_code:02x})"),
        "password_length": password_len,
        "key_reset_enabler": key_reset_enabler,
    }


def read_handy_store_block1(transport: ScsiTransport) -> Optional[tuple[int, bytes]]:
    """Reads Handy Store Block 1 to obtain iterations and salt."""
    cdb = bytes([0xD8, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00])
    data = transport.read(cdb, BLOCK_SIZE)
    if len(data) != BLOCK_SIZE:
        raise ScsiError(f"Unexpected HSB1 block length: {len(data)}")

    expected_checksum = compute_checksum(data)
    actual_checksum = data[511]
    if expected_checksum != actual_checksum:
        raise ScsiError(
            f"HSB1 checksum mismatch: calculated 0x{expected_checksum:02x}, "
            f"device reported 0x{actual_checksum:02x}"
        )

    # Signature must be "01WD" (0x00, 0x01, 0x44, 0x57)
    if data[0:4] != b"\x00\x01DW":
        return None

    iteration = struct.unpack_from("<I", data, 8)[0]
    salt = data[12:20]
    return iteration, salt


def unlock_drive(transport: ScsiTransport, password: str) -> dict[str, Any]:
    """Unlocks a locked WD Passport drive with the given passphrase."""
    status = get_encryption_status(transport)
    locked_code = status["locked_code"]

    if locked_code in (0x00, 0x02):
        return {
            "success": True,
            "already_unlocked": True,
            "status": status["status"],
            "cipher": status["cipher"],
        }

    if locked_code != 0x01:
        raise ScsiError(
            f"Drive cannot be unlocked in status '{status['status']}' (code 0x{locked_code:02x})"
        )

    hsb1 = read_handy_store_block1(transport)
    if not hsb1:
        raise ScsiError("Device did not return valid key derivation parameters (HSB1)")

    iteration, salt = hsb1
    derived_key = derive_password_key(password, iteration, salt)

    pw_len = status["password_length"]
    pw_block = bytearray([0x45, 0x00, 0x00, 0x00, 0x00, 0x00])
    pw_block.extend(struct.pack("!H", pw_len))
    payload = bytes(pw_block) + derived_key

    cdb = bytearray([0xC1, 0xE1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    cdb[8] = pw_len + 8

    try:
        transport.write(bytes(cdb), payload)
    except ScsiError as exc:
        raise AuthError(f"Unlock command failed: {exc}") from exc

    # Confirm the new status
    post_status = get_encryption_status(transport)
    if post_status["locked_code"] not in (0x00, 0x02):
        raise AuthError("Unlock rejected: incorrect password or drive remains locked")

    return {
        "success": True,
        "already_unlocked": False,
        "status": post_status["status"],
        "cipher": post_status["cipher"],
    }


# --- Device Discovery & System Actions ---

def find_passport_devices() -> list[dict[str, str]]:
    """Discovers connected Western Digital My Passport block devices via sysfs."""
    devices: list[dict[str, str]] = []
    sys_block = "/sys/block"
    if not os.path.isdir(sys_block):
        return devices

    for name in sorted(os.listdir(sys_block)):
        dev_dir = os.path.join(sys_block, name)
        device_sub = os.path.join(dev_dir, "device")
        if not os.path.isdir(device_sub):
            continue

        # Filter out optical / virtual unlocker devices (type 5 is CD-ROM)
        type_file = os.path.join(device_sub, "type")
        if os.path.isfile(type_file):
            try:
                with open(type_file, "r") as f:
                    if int(f.read().strip()) != 0:
                        continue
            except (ValueError, OSError):
                pass

        if name.startswith(("sr", "loop", "ram", "dm-", "md")):
            continue

        vendor_file = os.path.join(device_sub, "vendor")
        model_file = os.path.join(device_sub, "model")

        vendor = ""
        model = ""
        if os.path.isfile(vendor_file):
            with open(vendor_file, "r", errors="ignore") as f:
                vendor = f.read().strip()
        if os.path.isfile(model_file):
            with open(model_file, "r", errors="ignore") as f:
                model = f.read().strip()

        is_wd = "WD" in vendor.upper() or "WESTERN DIGITAL" in vendor.upper() or "WD" in model.upper()
        is_passport = "MY PASSPORT" in model.upper() or "PASSPORT" in model.upper() or "ELEMENTS" in model.upper()

        if not (is_wd and is_passport):
            # Check /dev/disk/by-id symlinks
            by_id = "/dev/disk/by-id"
            if os.path.isdir(by_id):
                for link in os.listdir(by_id):
                    link_upper = link.upper()
                    if ("WD" in link_upper or "WESTERN_DIGITAL" in link_upper) and "PASSPORT" in link_upper:
                        try:
                            target = os.path.realpath(os.path.join(by_id, link))
                            if target == f"/dev/{name}":
                                is_wd = True
                                is_passport = True
                                break
                        except OSError:
                            continue

        if is_wd and is_passport:
            devices.append({
                "name": name,
                "node": f"/dev/{name}",
                "vendor": vendor,
                "model": model,
            })

    return devices


def rescan_kernel_device(device_node: str, timeout: int = 15) -> None:
    """Notifies the Linux kernel to rescan the block device and partition table."""
    dev_name = os.path.basename(device_node)
    rescan_path = f"/sys/block/{dev_name}/device/rescan"
    if os.path.isfile(rescan_path):
        try:
            with open(rescan_path, "w") as f:
                f.write("1\n")
        except OSError:
            pass

    for cmd in (
        ["blockdev", "--rereadpt", device_node],
        ["partprobe", device_node],
        ["udevadm", "trigger", "--subsystem-match=block"],
    ):
        try:
            res = subprocess.run(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=timeout,
            )
            if res.returncode == 0:
                break
        except (FileNotFoundError, OSError, subprocess.SubprocessError):
            continue


def wait_for_uuid(uuid: str, timeout: int = 30) -> Optional[str]:
    """Polls until the block device for the specified UUID appears."""
    uuid_path = f"/dev/disk/by-uuid/{uuid}"
    deadline = time.time() + max(0, timeout)
    while True:
        if os.path.exists(uuid_path):
            try:
                return os.path.realpath(uuid_path)
            except OSError:
                return uuid_path
        if time.time() >= deadline:
            break
        time.sleep(0.5)
    return None


def mount_device(target: str, mount_point: str, timeout: int = 15) -> bool:
    """Mounts a device or UUID partition to the specified mount point."""
    if os.path.ismount(mount_point):
        return True

    try:
        os.makedirs(mount_point, exist_ok=True)
    except OSError as exc:
        raise RuntimeError(f"Failed to create mount directory {mount_point}: {exc}") from exc

    try:
        res = subprocess.run(
            ["mount", target, mount_point],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        raise RuntimeError("Mount utility ('mount') not found in PATH")
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError(f"Failed to execute mount command: {exc}") from exc

    if res.returncode != 0:
        raise RuntimeError(f"Mount command failed: {res.stderr.strip() or res.stdout.strip()}")

    return True


def unmount_path(mount_point: str, timeout: int = 15) -> bool:
    """Unmounts the specified mount point. Returns True if unmounted, False if already unmounted."""
    if not os.path.ismount(mount_point):
        return False

    try:
        res = subprocess.run(
            ["umount", mount_point],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        raise RuntimeError("Unmount utility ('umount') not found in PATH")
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError(f"Failed to execute unmount command: {exc}") from exc

    if res.returncode != 0:
        raise RuntimeError(f"Unmount command failed: {res.stderr.strip() or res.stdout.strip()}")

    return True


# --- Configuration & CLI ---

def load_config(config_path: str = DEFAULT_CONFIG_PATH) -> dict[str, str]:
    """Loads configuration from INI file if present."""
    config: dict[str, str] = {}
    if not os.path.isfile(config_path):
        if config_path != DEFAULT_CONFIG_PATH:
            print(f"Warning: Configuration file not found: {config_path}", file=sys.stderr)
        return config

    # Check for insecure permissions on POSIX systems
    try:
        mode = os.stat(config_path).st_mode
        if mode & 0o077:
            print(
                f"Warning: {config_path} has loose permissions (0{mode & 0o777:o}). "
                "Run 'chmod 600 /etc/wdpassport.conf' to protect your drive password.",
                file=sys.stderr,
            )
    except OSError:
        pass

    parser = configparser.ConfigParser()
    try:
        parser.read(config_path)
    except configparser.Error as exc:
        print(f"Warning: Failed to parse config file {config_path}: {exc}", file=sys.stderr)
        return config

    for section in ("wdpassport", "wd-auto-unlock"):
        if parser.has_section(section):
            for key, val in parser.items(section):
                config[key.lower()] = val
            break
    else:
        if parser.defaults():
            for key, val in parser.defaults().items():
                config[key.lower()] = val

    return config


def resolve_device(cli_device: Optional[str], config_device: Optional[str]) -> str:
    """Resolves target device path via CLI flag, config file, or auto-discovery."""
    if cli_device:
        return cli_device
    if config_device:
        return config_device

    devices = find_passport_devices()
    if not devices:
        raise DeviceNotFoundError(
            "No Western Digital My Passport device found. Specify with --device /dev/sdX."
        )
    if len(devices) > 1:
        dev_list = ", ".join(d["node"] for d in devices)
        raise DeviceNotFoundError(
            f"Multiple Western Digital Passport devices found ({dev_list}). Specify with --device."
        )

    return devices[0]["node"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wd-auto-unlock",
        description="Zero-dependency utility to unlock and mount WD Passport drives on Linux.",
    )
    parser.add_argument(
        "-V", "--version", action="version", version=f"%(prog)s {__version__}"
    )

    # Global options defined on root parser
    parser.add_argument("-d", "--device", default=None, help="Target block device (e.g. /dev/sdb)")
    parser.add_argument("-c", "--config", default=DEFAULT_CONFIG_PATH, help="Path to config file")
    parser.add_argument("--json", action="store_true", default=False, help="Output results in JSON")
    parser.add_argument("-p", "--password", default=None, help="Passphrase (or set WD_PASSWORD env var)")
    parser.add_argument("-u", "--uuid", default=None, help="Partition filesystem UUID to mount")
    parser.add_argument("-m", "--mount-point", default=None, help="Mount point directory (e.g. /media/WD)")
    parser.add_argument("-t", "--timeout", type=int, default=None, help="Device wait timeout in seconds (default: 30)")

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Command: unlock (primary action)
    p_unlock = subparsers.add_parser("unlock", help="Unlock drive and optionally mount partition")
    p_unlock.add_argument("-d", "--device", default=argparse.SUPPRESS, help="Target block device")
    p_unlock.add_argument("-c", "--config", default=argparse.SUPPRESS, help="Path to config file")
    p_unlock.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="Output results in JSON")
    p_unlock.add_argument("-p", "--password", default=argparse.SUPPRESS, help="Passphrase")
    p_unlock.add_argument("-u", "--uuid", default=argparse.SUPPRESS, help="Partition filesystem UUID")
    p_unlock.add_argument("-m", "--mount-point", default=argparse.SUPPRESS, help="Mount point directory")
    p_unlock.add_argument("-t", "--timeout", type=int, default=argparse.SUPPRESS, help="Device wait timeout")

    # Command: status
    p_status = subparsers.add_parser("status", help="Display drive lock and encryption status")
    p_status.add_argument("-d", "--device", default=argparse.SUPPRESS, help="Target block device")
    p_status.add_argument("-c", "--config", default=argparse.SUPPRESS, help="Path to config file")
    p_status.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="Output results in JSON")

    # Command: unmount (teardown)
    p_unmount = subparsers.add_parser("unmount", help="Safely unmount configured mount point")
    p_unmount.add_argument("-m", "--mount-point", default=argparse.SUPPRESS, help="Target mount directory")
    p_unmount.add_argument("-c", "--config", default=argparse.SUPPRESS, help="Path to config file")
    p_unmount.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="Output results in JSON")

    return parser


def cmd_status(
    device_path: str,
    as_json: bool,
    transport: Optional[ScsiTransport] = None,
) -> int:
    close_transport = False
    if transport is None:
        transport = LinuxSgioTransport(device_path)
        close_transport = True

    try:
        status_info = get_encryption_status(transport)
        data = {
            "success": True,
            "device": device_path,
            "security_status": status_info["status"],
            "locked_code": status_info["locked_code"],
            "cipher": status_info["cipher"],
            "password_length": status_info["password_length"],
        }
        if as_json:
            print(json.dumps(data, indent=2))
        else:
            print(f"Device:          {device_path}")
            print(f"Security Status: {status_info['status']}")
            print(f"Encryption:      {status_info['cipher']}")
            print(f"Key Length:      {status_info['password_length']} bytes")
        return 0
    finally:
        if close_transport:
            transport.close()


def cmd_unlock(
    device_path: str,
    password: Optional[str],
    uuid: Optional[str],
    mount_point: Optional[str],
    timeout: int,
    as_json: bool,
    transport: Optional[ScsiTransport] = None,
) -> int:
    close_transport = False
    if transport is None:
        transport = LinuxSgioTransport(device_path)
        close_transport = True

    try:
        current_status = get_encryption_status(transport)
        if current_status["locked_code"] in (0x00, 0x02):
            unlock_result = {
                "success": True,
                "already_unlocked": True,
                "status": current_status["status"],
                "cipher": current_status["cipher"],
            }
        else:
            if not password:
                err_msg = "No password provided. Set via --password, WD_PASSWORD env var, or config file."
                if as_json:
                    print(json.dumps({"success": False, "error": err_msg}), file=sys.stderr)
                else:
                    print(f"Error: {err_msg}", file=sys.stderr)
                return 2

            unlock_result = unlock_drive(transport, password)
    finally:
        if close_transport:
            transport.close()

    # Notify kernel to rescan partition table
    rescan_kernel_device(device_path)

    mounted = False
    resolved_partition = None

    if uuid and mount_point:
        partition_path = wait_for_uuid(uuid, timeout=timeout)
        if not partition_path:
            err_msg = f"Timed out waiting for partition UUID={uuid} ({timeout}s)"
            if as_json:
                print(
                    json.dumps({
                        "success": False,
                        "unlocked": unlock_result["success"],
                        "error": err_msg,
                    }),
                    file=sys.stderr,
                )
            else:
                print(f"Error: {err_msg}", file=sys.stderr)
            return 1

        resolved_partition = partition_path
        mount_device(partition_path, mount_point)
        mounted = True
    elif mount_point and not uuid:
        candidate_part = f"{device_path}1"
        if os.path.exists(candidate_part):
            resolved_partition = candidate_part
            mount_device(candidate_part, mount_point)
            mounted = True
        else:
            err_msg = f"Mount point specified but no partition UUID provided and {candidate_part} not found"
            if as_json:
                print(
                    json.dumps({
                        "success": False,
                        "unlocked": unlock_result["success"],
                        "error": err_msg,
                    }),
                    file=sys.stderr,
                )
            else:
                print(f"Error: {err_msg}", file=sys.stderr)
            return 1

    output_data = {
        "success": True,
        "device": device_path,
        "already_unlocked": unlock_result.get("already_unlocked", False),
        "status": unlock_result.get("status"),
        "cipher": unlock_result.get("cipher"),
        "partition": resolved_partition,
        "mount_point": mount_point if mounted else None,
        "mounted": mounted,
    }

    if as_json:
        print(json.dumps(output_data, indent=2))
    else:
        status_note = "Already unlocked" if unlock_result.get("already_unlocked") else "Unlocked successfully"
        print(f"Device: {device_path} ({status_note})")
        if mounted:
            print(f"Mounted: {resolved_partition} -> {mount_point}")

    return 0


def cmd_unmount(mount_point: Optional[str], as_json: bool) -> int:
    if not mount_point:
        err_msg = "No mount point specified. Provide --mount-point or configure it in config file."
        if as_json:
            print(json.dumps({"success": False, "error": err_msg}), file=sys.stderr)
        else:
            print(f"Error: {err_msg}", file=sys.stderr)
        return 2

    was_unmounted = unmount_path(mount_point)
    output_data = {
        "success": True,
        "mount_point": mount_point,
        "already_unmounted": not was_unmounted,
    }
    if as_json:
        print(json.dumps(output_data, indent=2))
    else:
        if was_unmounted:
            print(f"Unmounted {mount_point} successfully.")
        else:
            print(f"{mount_point} was already unmounted.")
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    command = args.command or "unlock"
    config_file = getattr(args, "config", DEFAULT_CONFIG_PATH)
    file_cfg = load_config(config_file)

    as_json = getattr(args, "json", False)

    try:
        if command == "unmount":
            mount_point = (
                getattr(args, "mount_point", None)
                or os.getenv("WD_MOUNT_POINT")
                or file_cfg.get("mount_point")
            )
            return cmd_unmount(mount_point=mount_point, as_json=as_json)

        # Device resolution
        cli_device = getattr(args, "device", None)
        cfg_device = os.getenv("WD_DEVICE") or file_cfg.get("device")
        device_path = resolve_device(cli_device, cfg_device)

        if command == "status":
            return cmd_status(device_path=device_path, as_json=as_json)

        if command == "unlock":
            password = (
                getattr(args, "password", None)
                or os.getenv("WD_PASSWORD")
                or file_cfg.get("password")
            )
            uuid = (
                getattr(args, "uuid", None)
                or os.getenv("WD_UUID")
                or file_cfg.get("uuid")
            )
            mount_point = (
                getattr(args, "mount_point", None)
                or os.getenv("WD_MOUNT_POINT")
                or file_cfg.get("mount_point")
            )

            cli_timeout = getattr(args, "timeout", None)
            if cli_timeout is not None:
                timeout = cli_timeout
            else:
                try:
                    timeout = int(file_cfg.get("timeout", 30))
                except ValueError:
                    timeout = 30

            return cmd_unlock(
                device_path=device_path,
                password=password,
                uuid=uuid,
                mount_point=mount_point,
                timeout=timeout,
                as_json=as_json,
            )

        parser.print_help(sys.stderr)
        return 2

    except (PermissionError, DeviceNotFoundError, AuthError, ScsiError, RuntimeError, OSError) as exc:
        if as_json:
            print(json.dumps({"success": False, "error": str(exc)}), file=sys.stderr)
        else:
            print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
