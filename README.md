# wd-auto-unlock

Automatically unlock and mount Western Digital My Passport drives on Linux.

## Quickstart

### 1. Install

```bash
git clone https://github.com/bobinx/wdpassport-auto-unlock.git
cd wdpassport-auto-unlock
sudo make install
```

### 2. Add your password

Open the configuration file:
```bash
sudo nano /etc/wdpassport.conf
```

Set your unlock password:
```ini
[wdpassport]
password = your_drive_password
```

Restrict permissions so only root can read your password:
```bash
sudo chmod 600 /etc/wdpassport.conf
```

### 3. Test and enable

Plug in your drive and test unlocking:
```bash
sudo wd-auto-unlock
```

Enable the service so it unlocks automatically on boot and whenever you plug the drive in:
```bash
sudo systemctl enable --now wd-unlock.timer
sudo udevadm control --reload-rules
```

That is it. Your drive will now unlock automatically whenever it is connected.

---

## Automatic mounting (optional)

By default, `wd-auto-unlock` unlocks the drive and tells the Linux kernel to load its partition table. If you want this tool to mount the filesystem for you as well:

1. Unlock the drive once with `sudo wd-auto-unlock`.
2. Find your partition's filesystem UUID:
   ```bash
   lsblk -f
   ```
   Look for your drive (for example, `sdb1`) and copy its `UUID` string:
   ```text
   NAME   FSTYPE LABEL UUID                                 MOUNTPOINTS
   sdb
   └─sdb1 ext4   Data  88E2-42DF-ABCD                       
   ```

3. Add the `uuid` and your target `mount_point` to `/etc/wdpassport.conf`:
   ```ini
   [wdpassport]
   password = your_drive_password
   uuid = 88E2-42DF-ABCD
   mount_point = /media/WD
   ```

Now whenever the drive is plugged in, the tool will unlock it, wait for the partition to appear, and mount it to `/media/WD`.

---

## Checking status and logs

Check whether your drive is currently locked or unlocked:
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

View system service logs:
```bash
sudo journalctl -u wd-unlock.service -e
```

Safely unmount:
```bash
sudo wd-auto-unlock unmount
```

---

## How it works

Western Digital My Passport drives have built-in hardware encryption. When they lose power or get unplugged, they lock themselves. Western Digital only provides unlock software for Windows and macOS. When plugged into Linux, the drive shows up as a virtual CD-ROM, and the real storage partition stays locked and invisible.

This tool solves that:
1. When you plug in the drive, a udev rule notices it and triggers `wd-unlock.service`.
2. The script reads the password from `/etc/wdpassport.conf`.
3. It sends the vendor SCSI unlock commands directly through the Linux kernel.
4. The kernel re-reads the partition table, making your partitions accessible.
5. If configured, it mounts the partition to your chosen folder.

It uses Python's standard library modules (`ctypes`, `fcntl`, `hashlib`, `struct`). You do not need pip, third-party libraries, or a C compiler.

---

## Reference

### Commands

| Command | Description |
| :--- | :--- |
| `wd-auto-unlock unlock` | Unlock the drive, rescan partition table, and mount if configured (default). |
| `wd-auto-unlock status` | Print current lock state, cipher, and key length. |
| `wd-auto-unlock unmount` | Unmount the configured mount point. |

### Options

| Option | Env variable | Description |
| :--- | :--- | :--- |
| `-d, --device PATH` | `WD_DEVICE` | Block device path (e.g. `/dev/sdb`). Auto-detected if omitted. |
| `-p, --password PASS` | `WD_PASSWORD` | Unlock password. Prefer `/etc/wdpassport.conf` so it stays out of `ps`. |
| `-u, --uuid UUID` | `WD_UUID` | Filesystem UUID to wait for and mount. |
| `-m, --mount-point PATH` | `WD_MOUNT_POINT` | Directory mount target (e.g. `/media/WD`). |
| `-c, --config PATH` | | Config file path (default: `/etc/wdpassport.conf`). |
| `-t, --timeout SEC` | | Seconds to wait for partition device to appear (default: 30). |
| `--json` | | Print output in JSON format for scripts. |
| `-V, --version` | | Print version and exit. |
| `-h, --help` | | Print help and exit. |

### Configuration priority

Settings are resolved in order:
1. Command line flags
2. Environment variables
3. Configuration file (`/etc/wdpassport.conf`)

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
