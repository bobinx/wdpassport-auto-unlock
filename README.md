# wd-auto-unlock

Auto-unlock and mount Western Digital My Passport drives on Linux.

## Quickstart

### Install

```bash
git clone https://github.com/bobinx/wdpassport-auto-unlock.git
cd wdpassport-auto-unlock
sudo make install
```

### Configure

Put your drive password and filesystem UUID into `/etc/wdpassport.conf`:

```ini
[wdpassport]
password = your_drive_password
uuid = 88E2-42DF
mount_point = /media/WD
```

Restrict permissions so only root can read the password:
```bash
sudo chmod 600 /etc/wdpassport.conf
```

### Run

Unlock and mount manually:
```bash
sudo wd-auto-unlock
```

Or enable the timer and udev rule to unlock automatically when plugged in or on boot:
```bash
sudo systemctl enable --now wd-unlock.timer
sudo udevadm control --reload-rules
```

## Background

Western Digital My Passport drives with hardware encryption lock themselves whenever they lose power. WD provides official unlock software for Windows and macOS, but not for Linux. When connected to a Linux machine, the drive presents a virtual CD-ROM and leaves the actual data partition locked and unreadable.

Tools like `wdpassport-utils` can send the vendor SCSI commands to unlock the drive, but they are interactive CLI utilities meant for typing a password into a terminal prompt. If the drive is attached to a home server, NAS, or desktop, you usually want it unlocked and mounted automatically on boot or when plugged in.

This utility automates that workflow:
1. A udev rule detects the drive when connected over USB.
2. A systemd service runs `wd-auto-unlock` using the settings in `/etc/wdpassport.conf`.
3. The script sends the unlock command over the Linux SCSI generic (`SG_IO`) interface.
4. The kernel rescans the partition table, and the partition is mounted to your target directory.

It uses Python standard library modules (`ctypes`, `fcntl`, `hashlib`, `struct`) so there are no extra packages or compilers needed.

## Commands

| Command | Description |
| :--- | :--- |
| `wd-auto-unlock unlock` | Unlock the drive, rescan partition table, and mount (default). |
| `wd-auto-unlock status` | Print current lock state, cipher, and key length. |
| `wd-auto-unlock unmount` | Unmount the configured mount point. |

## Options

| Option | Env variable | Description |
| :--- | :--- | :--- |
| `-d, --device PATH` | `WD_DEVICE` | Block device path (e.g. `/dev/sdb`). Auto-detected if omitted. |
| `-p, --password PASS` | `WD_PASSWORD` | Unlock password. Prefer `/etc/wdpassport.conf` so it stays out of `ps`. |
| `-u, --uuid UUID` | `WD_UUID` | Filesystem UUID to wait for and mount. |
| `-m, --mount-point PATH` | `WD_MOUNT_POINT` | Directory mount target (e.g. `/media/WD`). |
| `-c, --config PATH` | | Config file path (default: `/etc/wdpassport.conf`). |
| `-t, --timeout SEC` | | Seconds to wait for partition device to appear (default: 30). |
| `--json` | | Print output as JSON. |
| `-V, --version` | | Print version and exit. |
| `-h, --help` | | Print help and exit. |

## Configuration

Settings are resolved in order:
1. Command line flags
2. Environment variables
3. Configuration file (`/etc/wdpassport.conf`)

Example `/etc/wdpassport.conf`:

```ini
[wdpassport]
password = secret
uuid = 88E2-42DF
mount_point = /media/WD
timeout = 30
# device = /dev/sdb   # Optional: omit to auto-detect
```

## How the automation works

Installation sets up three system files:

- `/etc/udev/rules.d/99-wd-passport.rules`: Tells systemd to start `wd-unlock.service` when a My Passport drive is connected.
- `/etc/systemd/system/wd-unlock.service`: Runs `wd-auto-unlock unlock` as a oneshot task.
- `/etc/systemd/system/wd-unlock.timer`: Runs `wd-unlock.service` 30 seconds after system boot to catch drives already plugged in at startup.

View logs with journalctl:
```bash
sudo journalctl -u wd-unlock.service -f
```

## Testing

Run the test suite:
```bash
make test
make lint
```

## Uninstall

```bash
sudo make uninstall
sudo systemctl daemon-reload
sudo udevadm control --reload-rules
```

The configuration file `/etc/wdpassport.conf` stays on disk. Remove it manually if you do not plan to use it again.

## License

MIT. See [LICENSE](LICENSE).
