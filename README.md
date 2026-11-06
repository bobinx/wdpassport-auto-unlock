```
 __      __ ___    ___                                   _   
 \ \    / /|   \  | _ \__ _ ___ ___ _ __  ___  _ _ _| |_ 
  \ \/\/ / | |) | |  _/ _` (_-</ -_) '_ \/ _ \| '_|_   _|
   \_/\_/  |___/  |_| \__,_/__/\___| .__/\___/|_|   |_|  
                                   |_|                   
```

Zero-dependency auto-unlock and mount tool for Western Digital My Passport drives on Linux.

## Get started

### Installation

```bash
git clone https://github.com/bobinx/wdpassport-auto-unlock.git
cd wdpassport-auto-unlock
sudo make install
```

### 30-second quickstart

1. Put your drive password and filesystem UUID into `/etc/wdpassport.conf`:
   ```ini
   [wdpassport]
   password = your_drive_password
   uuid = 88E2-42DF
   mount_point = /media/WD
   ```

2. Restrict config file permissions:
   ```bash
   sudo chmod 600 /etc/wdpassport.conf
   ```

3. Unlock and mount:
   ```bash
   sudo wd-auto-unlock
   ```

Enable automatic unlock on boot and USB hotplug:
```bash
sudo systemctl enable --now wd-unlock.timer
sudo udevadm control --reload-rules
```

## Why I built this

I keep a headless Debian box tucked under my desk for backups. A while ago I bought a Western Digital My Passport drive because hardware-level disk encryption sounded great. Then I plugged it into Linux.

The kernel saw a useless virtual CD-ROM and locked the actual storage away. WD makes Windows and macOS unlock apps, but nothing for Linux. The scripts I found online either wanted me to compile unmaintained C extensions as root through pip, or asked for passwords interactively on stdin. If the power blinked at 3am, the machine rebooted and backup cron jobs failed until morning.

I wrote this because I wanted something that unlocks the drive, mounts it, and gets out of the way. It talks SCSI directly through Linux `SG_IO` ioctls using Python's standard library. No pip, no compiler, no background daemon eating RAM. When you plug the drive in, udev triggers the unlock script, the kernel re-reads the partition table, and the drive mounts. That is the whole job.

## Commands and options

### Commands

| Command | Action |
| :--- | :--- |
| `wd-auto-unlock unlock` | Unlock the drive, rescan partition tables, and mount if configured (default). |
| `wd-auto-unlock status` | Print current drive lock state, cipher, and key length. |
| `wd-auto-unlock unmount` | Unmount the configured mount point. |

### Options

| Option | Environment variable | Description |
| :--- | :--- | :--- |
| `-d, --device PATH` | `WD_DEVICE` | Block device path (for example, `/dev/sdb`). Auto-detected if omitted. |
| `-p, --password PASS` | `WD_PASSWORD` | Unlock passphrase. Prefer `/etc/wdpassport.conf` so passwords stay out of process lists. |
| `-u, --uuid UUID` | `WD_UUID` | Partition filesystem UUID to mount. |
| `-m, --mount-point PATH` | `WD_MOUNT_POINT` | Directory mount target (for example, `/media/WD`). |
| `-c, --config PATH` | | Path to configuration file (default: `/etc/wdpassport.conf`). |
| `-t, --timeout SEC` | | Seconds to wait for partition device to appear (default: 30). |
| `--json` | | Output structured JSON for scripts and health checks. |
| `-V, --version` | | Show version number and exit. |
| `-h, --help` | | Show help message and exit. |

## Configuration

The CLI resolves configuration in this order:
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

## System automation

The installer places three files on the system:

* `/etc/udev/rules.d/99-wd-passport.rules`. Triggers `wd-unlock.service` when the kernel detects a connected My Passport drive.
* `/etc/systemd/system/wd-unlock.service`. Runs `wd-auto-unlock unlock` as a oneshot task.
* `/etc/systemd/system/wd-unlock.timer`. Waits 30 seconds after system boot to unlock drives that were already connected when the machine started up.

Inspect service logs:
```bash
sudo journalctl -u wd-unlock.service -f
```

## Verification and testing

Run the test suite and syntax checks:

```bash
make test
make lint
```

All 35 tests run offline in milliseconds.

## Uninstallation

To remove installed binaries and systemd units:

```bash
sudo make uninstall
sudo systemctl daemon-reload
sudo udevadm control --reload-rules
```

The configuration file `/etc/wdpassport.conf` stays on disk. Remove it manually if you do not plan to use it again.

## License

MIT License. See [LICENSE](LICENSE) for details.
