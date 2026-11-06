# wd-auto-unlock

Automatically unlock and mount Western Digital My Passport drives on Linux.

---

## Quickstart

### 1. Install

Clone the repository and install the command, systemd service, and udev rule:

```bash
git clone https://github.com/bobinx/wdpassport-auto-unlock.git
cd wdpassport-auto-unlock
sudo make install
```

### 2. Configure

Plug in your Western Digital drive and run the setup wizard:

```bash
sudo wd-auto-unlock config
```

The setup wizard will:
1. Detect your connected Western Digital drive.
2. Prompt for your unlock password.
3. Test unlocking the drive to verify the password.
4. Detect the filesystem partition UUID and ask where you want it mounted (e.g. `/media/WD`).
5. Save the configuration to `/etc/wdpassport.conf` with secure permissions (`0600`).
6. Enable the systemd service so your drive unlocks and mounts automatically whenever you plug it in or reboot.

That is it. Your drive will now unlock and mount automatically on connection.

---

## Alternative: Manual configuration

If you prefer to configure things manually without the wizard:

1. Copy the example configuration:
   ```bash
   sudo cp wdpassport.conf.example /etc/wdpassport.conf
   sudo chmod 600 /etc/wdpassport.conf
   ```

2. Open `/etc/wdpassport.conf` and set your password:
   ```ini
   [wdpassport]
   password = your_drive_password
   # Optional: specify UUID and mount point for automatic mounting
   # uuid = 88E2-42DF
   # mount_point = /media/WD
   ```

3. Enable the background service:
   ```bash
   sudo systemctl enable --now wd-unlock.timer
   sudo udevadm control --reload-rules
   ```

---

## Common tasks

### Find your connected drives

List all connected Western Digital drives, lock status, and partitions:
```bash
sudo wd-auto-unlock list
```

Example output:
```text
Western Digital Passport Devices:
  [1] /dev/sdb  Western Digital My Passport 25E1  (931.5 GB)
      Status: locked (AES_256_XTS)
      Partitions: none visible (drive is locked)
```

If your drive is an older model or enclosure not automatically detected, list all disks:
```bash
sudo wd-auto-unlock list --all
```
You can then unlock it directly by specifying the device path:
```bash
sudo wd-auto-unlock unlock --device /dev/sdX
```

### Unlock manually

Unlock with interactive password prompt:
```bash
sudo wd-auto-unlock unlock
```

Or provide the password via command flag:
```bash
sudo wd-auto-unlock unlock --password "mysecret"
```

### Run unattended unlock (`auto`)

Unattended unlock is what the systemd service runs. It requires a configured password in `/etc/wdpassport.conf`, unlocks the drive, rescans the partition table, and mounts the filesystem if configured:
```bash
sudo wd-auto-unlock auto
```

### Check drive lock status

```bash
sudo wd-auto-unlock status
```

Output:
```text
Device:          /dev/sdb
Security Status: unlocked
Encryption:      AES_256_XTS
Key Length:      32 bytes
```

### Safely unmount

```bash
sudo wd-auto-unlock unmount
```

### View service logs

```bash
sudo journalctl -u wd-unlock.service -e
```

---

## Reference

### Commands

| Command | Description |
| :--- | :--- |
| `wd-auto-unlock config` | Interactive setup wizard (finds drive, verifies password, configures auto-mount and systemd). |
| `wd-auto-unlock list` | Scan and display connected Western Digital drives, lock status, and partitions. |
| `wd-auto-unlock unlock` | Unlock the drive interactively or with flags, rescan partitions, and mount. |
| `wd-auto-unlock auto` | Unattended unlock and mount reading credentials from `/etc/wdpassport.conf` (used by systemd). |
| `wd-auto-unlock status` | Print current security lock state, cipher, and key length. |
| `wd-auto-unlock unmount` | Unmount the configured mount point. |

### Options

| Option | Env variable | Description |
| :--- | :--- | :--- |
| `-d, --device PATH` | `WD_DEVICE` | Block device path (e.g. `/dev/sdb`). Auto-detected if omitted. |
| `-p, --password PASS` | `WD_PASSWORD` | Unlock password. |
| `-u, --uuid UUID` | `WD_UUID` | Filesystem UUID to wait for and mount. |
| `-m, --mount-point PATH` | `WD_MOUNT_POINT` | Directory mount target (e.g. `/media/WD`). |
| `-c, --config PATH` | | Config file path (default: `/etc/wdpassport.conf`). |
| `-t, --timeout SEC` | | Seconds to wait for partition device to appear (default: 30). |
| `-a, --all` | | In `list` command, display all connected block devices. |
| `-y, --enable-service` | | In `config` command, automatically enable systemd service and reload udev. |
| `--json` | | Print output in JSON format for scripting and automation. |
| `-V, --version` | | Print version and exit. |
| `-h, --help` | | Print help and exit. |

### Configuration priority

Settings are resolved in order:
1. Command line flags
2. Environment variables
3. Configuration file (`/etc/wdpassport.conf`)

---

## How it works

Western Digital My Passport drives contain a hardware AES engine in their USB-SATA bridge chip. When plugged into Linux, the drive locks its storage sectors and exposes a virtual CD-ROM.

`wd-auto-unlock` communicates directly with the bridge chip via Linux `SG_IO` ioctl SCSI commands (`0xC0`, `0xD8`, `0xC1`), performs the SHA-256 key derivation, unlocks the drive, triggers a kernel partition table rescan, and mounts your filesystem.

For an in-depth breakdown of the SCSI opcodes, HSB1 checksum formula, key derivation function, and distribution analysis (standalone binary vs. Python library), see [HOW_IT_WORKS.md](HOW_IT_WORKS.md).

---

## Uninstall

```bash
sudo make uninstall
sudo systemctl daemon-reload
sudo udevadm control --reload-rules
```

The configuration file `/etc/wdpassport.conf` is preserved during uninstall. Delete it manually if you do not plan to use it again:
```bash
sudo rm -f /etc/wdpassport.conf
```

---

## Credits and references

The SCSI unlock sequence, Handy Store checksum algorithm, and password key derivation are based on the reverse engineering work and implementations in:

- [wdpassport-utils](https://github.com/0-duke/wdpassport-utils) by 0-duke, DanLukes, KenMacD, crypto-universe, and JoshData.
- [bobinx/wdpassport-utils](https://github.com/bobinx/wdpassport-utils).

## License

MIT. See [LICENSE](LICENSE).
