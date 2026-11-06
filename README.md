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

Clone and install using the included Makefile:

```bash
git clone https://github.com/bobinx/wdpassport-auto-unlock.git
cd wdpassport-auto-unlock
sudo make install
```

### 30-second quickstart

1. Edit `/etc/wdpassport.conf` with your drive password and filesystem UUID:
   ```ini
   [wdpassport]
   password = your_drive_password
   uuid = 88E2-42DF
   mount_point = /media/WD
   ```

2. Lock down config file permissions:
   ```bash
   sudo chmod 600 /etc/wdpassport.conf
   ```

3. Run the unlock command:
   ```bash
   sudo wd-auto-unlock
   ```

Enable automatic unlocking on drive plug-in or system boot:
```bash
sudo systemctl enable --now wd-unlock.timer
sudo udevadm control --reload-rules
```

## Why I built this

I run a headless Linux server for backups and storage. I had a hardware-encrypted Western Digital My Passport drive that worked fine on Windows, but plugging it into Linux was a headache. Western Digital does not provide an official Linux unlock utility. Instead, the Linux kernel sees a dummy virtual CD-ROM and leaves the actual storage volume locked and inaccessible.

The few scripts floating around online were brittle. Most required installing Python development headers and compiling third-party C libraries from random GitHub forks with root pip privileges. None of them handled automatic hotplugging cleanly, and they asked for passwords interactively on standard input, which broke automated reboots.

I wanted a single-purpose utility that adheres to the Unix philosophy. It uses standard Linux kernel SCSI pass-through interfaces directly from Python standard library modules. You do not need a compiler, you do not need pip, and you do not need external libraries. It discovers the drive, negotiates the hardware unlock in under 100 milliseconds, prompts the kernel to rescan partition tables, and mounts the filesystem where you want it.

## Commands and options

### Commands

| Command | Action |
| :--- | :--- |
| `wd-auto-unlock unlock` | Unlocks the drive, rescans partition tables, and mounts if configured (default action). |
| `wd-auto-unlock status` | Queries and displays current drive lock state, cipher, and key length. |
| `wd-auto-unlock unmount` | Safely unmounts the configured partition mount point. |

### Options

| Option | Environment variable | Description |
| :--- | :--- | :--- |
| `-d, --device PATH` | `WD_DEVICE` | Block device path (for example, `/dev/sdb`). Auto-detected if omitted. |
| `-p, --password PASS` | `WD_PASSWORD` | Unlock passphrase. Prefer storing in `/etc/wdpassport.conf` for security. |
| `-u, --uuid UUID` | `WD_UUID` | Filesystem UUID to wait for and mount. |
| `-m, --mount-point PATH` | `WD_MOUNT_POINT` | Directory mount target (for example, `/media/WD`). |
| `-c, --config PATH` | | Path to configuration file (default: `/etc/wdpassport.conf`). |
| `-t, --timeout SEC` | | Seconds to wait for partition device to appear (default: 30). |
| `--json` | | Output responses in structured JSON format for scripts. |
| `-V, --version` | | Show version number and exit. |
| `-h, --help` | | Show help message and exit. |

## Configuration

Configuration values are resolved using this priority order:
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

The installer places systemd units and udev rules into standard system paths:

* **Udev rule (`/etc/udev/rules.d/99-wd-passport.rules`)**: Fires whenever a Western Digital My Passport drive is connected over USB, triggering `wd-unlock.service`.
* **Systemd service (`/etc/systemd/system/wd-unlock.service`)**: Runs `wd-auto-unlock unlock` once as a oneshot system task.
* **Systemd timer (`/etc/systemd/system/wd-unlock.timer`)**: Triggers 30 seconds after system boot to catch drives that were already attached while the machine powered up.

Check service status or logs with journalctl:
```bash
sudo journalctl -u wd-unlock.service -f
```

## Verification and testing

Run the offline test suite and syntax checks:

```bash
make test
make lint
```

All tests run locally in milliseconds with no external network or hardware dependencies.

## Uninstallation

To remove all installed binaries, systemd units, and udev rules:

```bash
sudo make uninstall
sudo systemctl daemon-reload
sudo udevadm control --reload-rules
```

The configuration file `/etc/wdpassport.conf` is preserved during uninstallation. Remove it manually if no longer needed.

## License

MIT License. See [LICENSE](LICENSE) for details.
