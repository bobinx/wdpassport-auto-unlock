package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/term"

	"github.com/bobinx/wdpassport-auto-unlock/internal/config"
	"github.com/bobinx/wdpassport-auto-unlock/internal/device"
	"github.com/bobinx/wdpassport-auto-unlock/internal/scsi"
)

const Version = "1.0.0"

func printUsage() {
	fmt.Print(`wd-auto-unlock - Automatically unlock and mount Western Digital My Passport drives on Linux

Usage:
  wd-auto-unlock <command> [options]

Commands:
  config      Interactive setup wizard to configure auto-unlock and auto-mount
  list        List connected Western Digital drives, lock status, and partitions
  unlock      Unlock drive interactively or via flags, rescan partitions, and mount
  auto        Unattended unlock and mount reading credentials from /etc/wdpassport.conf
  status      Print current security lock state, cipher, and key length
  unmount     Safely unmount the configured mount point

Options:
  -d, --device PATH        Block device path (e.g. /dev/sdb). Auto-detected if omitted
  -p, --password PASS      Unlock password
  -u, --uuid UUID          Filesystem UUID to wait for and mount
  -m, --mount-point PATH   Directory mount target (e.g. /media/WD)
  -c, --config PATH        Config file path (default: /etc/wdpassport.conf)
  -t, --timeout SEC        Seconds to wait for partition device to appear (default: 30)
  -a, --all                In list command, display all connected block devices
  -y, --enable-service     In config command, enable systemd service and reload udev
      --json               Print output in JSON format for scripting
  -V, --version            Print version and exit
  -h, --help               Print help and exit
`)
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	var (
		flagDevice     string
		flagPassword   string
		flagUUID       string
		flagMountPoint string
		flagConfig     string
		flagTimeout    int
		flagAll        bool
		flagEnableSvc  bool
		flagJSON       bool
		flagVersion    bool
		flagHelp       bool
	)

	fs := flag.NewFlagSet("wd-auto-unlock", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	fs.StringVar(&flagDevice, "device", "", "Block device path")
	fs.StringVar(&flagDevice, "d", "", "Block device path (shorthand)")

	fs.StringVar(&flagPassword, "password", "", "Unlock password")
	fs.StringVar(&flagPassword, "p", "", "Unlock password (shorthand)")

	fs.StringVar(&flagUUID, "uuid", "", "Filesystem UUID")
	fs.StringVar(&flagUUID, "u", "", "Filesystem UUID (shorthand)")

	fs.StringVar(&flagMountPoint, "mount-point", "", "Mount point path")
	fs.StringVar(&flagMountPoint, "m", "", "Mount point path (shorthand)")

	fs.StringVar(&flagConfig, "config", config.DefaultConfigPath, "Config file path")
	fs.StringVar(&flagConfig, "c", config.DefaultConfigPath, "Config file path (shorthand)")

	fs.IntVar(&flagTimeout, "timeout", 0, "Timeout in seconds")
	fs.IntVar(&flagTimeout, "t", 0, "Timeout in seconds (shorthand)")

	fs.BoolVar(&flagAll, "all", false, "Show all block devices")
	fs.BoolVar(&flagAll, "a", false, "Show all block devices (shorthand)")

	fs.BoolVar(&flagEnableSvc, "enable-service", false, "Enable systemd services")
	fs.BoolVar(&flagEnableSvc, "y", false, "Enable systemd services (shorthand)")

	fs.BoolVar(&flagJSON, "json", false, "Output in JSON format")

	fs.BoolVar(&flagVersion, "version", false, "Print version")
	fs.BoolVar(&flagVersion, "V", false, "Print version (shorthand)")

	fs.BoolVar(&flagHelp, "help", false, "Print help")
	fs.BoolVar(&flagHelp, "h", false, "Print help (shorthand)")

	// Parse flags and command
	var command string
	var nonFlagArgs []string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "-h" || arg == "--help" {
			printUsage()
			return 0
		}
		if arg == "-V" || arg == "--version" {
			fmt.Printf("wd-auto-unlock %s\n", Version)
			return 0
		}
		if !strings.HasPrefix(arg, "-") && command == "" {
			command = arg
		} else {
			nonFlagArgs = append(nonFlagArgs, arg)
		}
	}

	if err := fs.Parse(nonFlagArgs); err != nil {
		return 2
	}

	if flagHelp {
		printUsage()
		return 0
	}
	if flagVersion {
		fmt.Printf("wd-auto-unlock %s\n", Version)
		return 0
	}

	// Default command dispatch
	if command == "" {
		if term.IsTerminal(int(os.Stdin.Fd())) {
			command = "unlock"
		} else {
			command = "auto"
		}
	}

	fileCfg, _ := config.Load(flagConfig)
	if fileCfg == nil {
		fileCfg = &config.Config{Timeout: 30}
	}

	switch command {
	case "list":
		return cmdList(flagJSON, flagAll)

	case "config", "setup":
		return cmdConfig(flagDevice, flagPassword, flagUUID, flagMountPoint, flagTimeout, flagConfig, flagEnableSvc, flagJSON)

	case "auto":
		return cmdAuto(flagConfig, flagJSON)

	case "status":
		devPath, err := resolveDeviceTarget(flagDevice, fileCfg.Device)
		if err != nil {
			outputError(err.Error(), flagJSON)
			return 1
		}
		return cmdStatus(devPath, flagJSON)

	case "unlock":
		devPath, err := resolveDeviceTarget(flagDevice, fileCfg.Device)
		if err != nil {
			outputError(err.Error(), flagJSON)
			return 1
		}

		pwd := flagPassword
		if pwd == "" {
			pwd = os.Getenv("WD_PASSWORD")
		}
		if pwd == "" {
			pwd = fileCfg.Password
		}

		uid := flagUUID
		if uid == "" {
			uid = os.Getenv("WD_UUID")
		}
		if uid == "" {
			uid = fileCfg.UUID
		}

		mnt := flagMountPoint
		if mnt == "" {
			mnt = os.Getenv("WD_MOUNT_POINT")
		}
		if mnt == "" {
			mnt = fileCfg.MountPoint
		}

		t := flagTimeout
		if t <= 0 {
			t = fileCfg.Timeout
		}
		if t <= 0 {
			t = 30
		}

		return cmdUnlock(devPath, pwd, uid, mnt, t, flagJSON)

	case "unmount":
		mnt := flagMountPoint
		if mnt == "" {
			mnt = os.Getenv("WD_MOUNT_POINT")
		}
		if mnt == "" {
			mnt = fileCfg.MountPoint
		}
		return cmdUnmount(mnt, flagJSON)

	default:
		outputError(fmt.Sprintf("Unknown command: %s. Run 'wd-auto-unlock --help' for usage.", command), flagJSON)
		return 2
	}
}

func resolveDeviceTarget(cliDevice, cfgDevice string) (string, error) {
	return device.ResolveDevice(cliDevice, cfgDevice)
}

func outputError(msg string, asJSON bool) {
	if asJSON {
		out, _ := json.Marshal(map[string]any{"success": false, "error": msg})
		fmt.Fprintln(os.Stderr, string(out))
	} else {
		fmt.Fprintf(os.Stderr, "Error: %s\n", msg)
	}
}

func cmdList(asJSON, showAll bool) int {
	wdDevices, otherDevices, err := device.ScanAllDisks()
	if err != nil {
		outputError(fmt.Sprintf("failed to scan disks: %v", err), asJSON)
		return 1
	}

	if asJSON {
		res := map[string]any{
			"success":    true,
			"wd_devices": wdDevices,
		}
		if showAll {
			res["other_devices"] = otherDevices
		}
		out, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(out))
		return 0
	}

	if len(wdDevices) > 0 {
		fmt.Println("Western Digital Passport Devices:")
		for i, dev := range wdDevices {
			statusLine := dev.SecurityStatus
			if dev.Cipher != "" && dev.Cipher != "unknown" {
				statusLine = fmt.Sprintf("%s (%s)", dev.SecurityStatus, dev.Cipher)
			}
			fmt.Printf("  [%d] %s  %s %s  (%s)\n", i+1, dev.Node, dev.Vendor, dev.Model, dev.SizeHuman)
			fmt.Printf("      Status: %s\n", statusLine)
			if len(dev.Partitions) > 0 {
				fmt.Println("      Partitions:")
				for _, p := range dev.Partitions {
					uuidStr := "No UUID"
					if p.UUID != "" {
						uuidStr = "UUID: " + p.UUID
					}
					fmt.Printf("        - %s  (%s, %s)\n", p.Node, uuidStr, p.SizeHuman)
				}
			} else {
				if dev.SecurityStatus == "locked" {
					fmt.Println("      Partitions: none visible (drive is locked)")
				} else {
					fmt.Println("      Partitions: none detected")
				}
			}
		}
		fmt.Println()
	}

	if showAll || len(wdDevices) == 0 {
		if len(otherDevices) > 0 {
			if showAll {
				fmt.Println("All Connected Disk Block Devices:")
			} else {
				fmt.Println("No Western Digital Passport devices found. Connected disks:")
			}
			for _, dev := range otherDevices {
				fmt.Printf("  - %s  %s %s  (%s)\n", dev.Node, dev.Vendor, dev.Model, dev.SizeHuman)
				if len(dev.Partitions) > 0 {
					for _, p := range dev.Partitions {
						uuidStr := "No UUID"
						if p.UUID != "" {
							uuidStr = "UUID: " + p.UUID
						}
						fmt.Printf("      └─ %s  (%s, %s)\n", p.Node, uuidStr, p.SizeHuman)
					}
				}
			}
			fmt.Println()
			if len(wdDevices) == 0 {
				fmt.Println("If your drive is listed above, target it manually:")
				fmt.Println("  sudo wd-auto-unlock unlock --device /dev/sdX")
			}
		} else {
			fmt.Println("No disk block devices found.")
		}
	}

	return 0
}

func cmdStatus(devicePath string, asJSON bool) int {
	transport, err := scsi.OpenTransport(devicePath)
	if err != nil {
		outputError(err.Error(), asJSON)
		return 1
	}
	defer transport.Close()

	status, err := scsi.GetEncryptionStatus(transport)
	if err != nil {
		outputError(err.Error(), asJSON)
		return 1
	}

	if asJSON {
		res := map[string]any{
			"success":          true,
			"device":           devicePath,
			"security_status":  status.Status,
			"locked_code":      status.LockedCode,
			"cipher":           status.Cipher,
			"key_length_bytes": status.KeyLengthBytes,
		}
		out, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(out))
		return 0
	}

	fmt.Printf("Device:          %s\n", devicePath)
	fmt.Printf("Security Status: %s\n", status.Status)
	fmt.Printf("Encryption:      %s\n", status.Cipher)
	fmt.Printf("Key Length:      %d bytes\n", status.KeyLengthBytes)
	return 0
}

func cmdUnlock(devicePath, password, uuid, mountPoint string, timeout int, asJSON bool) int {
	transport, err := scsi.OpenTransport(devicePath)
	if err != nil {
		outputError(err.Error(), asJSON)
		return 1
	}
	defer transport.Close()

	currentStatus, err := scsi.GetEncryptionStatus(transport)
	if err != nil {
		outputError(err.Error(), asJSON)
		return 1
	}

	var unlockRes *scsi.UnlockResult

	if currentStatus.LockedCode == 0x00 || currentStatus.LockedCode == 0x02 {
		unlockRes = &scsi.UnlockResult{
			Success:         true,
			AlreadyUnlocked: true,
			Status:          currentStatus.Status,
			Cipher:          currentStatus.Cipher,
		}
	} else {
		if password == "" && term.IsTerminal(int(os.Stdin.Fd())) {
			fmt.Printf("Password for %s: ", devicePath)
			passBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Println()
			if err != nil {
				outputError("failed to read password", asJSON)
				return 130
			}
			password = string(passBytes)
		}

		if password == "" {
			outputError("No password provided. Set via --password, WD_PASSWORD env var, or config file.", asJSON)
			return 2
		}

		unlockRes, err = scsi.UnlockDrive(transport, password)
		if err != nil {
			if errors.Is(err, scsi.ErrWrongPassword) {
				outputError("Drive unlock failed: incorrect password.", asJSON)
			} else {
				outputError(fmt.Sprintf("Drive unlock failed: %v", err), asJSON)
			}
			return 1
		}
	}

	// Rescan partition table
	device.RescanKernelDevice(devicePath, 15)

	var mountNode string
	var mountError string

	if uuid != "" && mountPoint != "" {
		resolvedNode, err := device.WaitForUUID(uuid, timeout)
		if err != nil {
			mountError = err.Error()
		} else {
			mountNode = resolvedNode
			if err := device.MountDevice(resolvedNode, mountPoint); err != nil {
				mountError = err.Error()
			}
		}
	}

	if asJSON {
		res := map[string]any{
			"success":          true,
			"device":           devicePath,
			"already_unlocked": unlockRes.AlreadyUnlocked,
			"status":           unlockRes.Status,
			"cipher":           unlockRes.Cipher,
		}
		if uuid != "" && mountPoint != "" {
			res["uuid"] = uuid
			res["mount_point"] = mountPoint
			res["partition_node"] = mountNode
			res["mounted"] = (mountError == "")
			if mountError != "" {
				res["mount_error"] = mountError
			}
		}
		out, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(out))
		if mountError != "" {
			return 1
		}
		return 0
	}

	if unlockRes.AlreadyUnlocked {
		fmt.Printf("Drive %s is already unlocked (%s).\n", devicePath, unlockRes.Cipher)
	} else {
		fmt.Printf("Successfully unlocked %s (%s).\n", devicePath, unlockRes.Cipher)
	}
	fmt.Println("Partition table rescanned.")

	if uuid != "" && mountPoint != "" {
		if mountError != "" {
			fmt.Fprintf(os.Stderr, "Mount error: %s\n", mountError)
			return 1
		}
		fmt.Printf("Mounted %s (%s) to %s.\n", mountNode, uuid, mountPoint)
	}

	return 0
}

func cmdAuto(configFile string, asJSON bool) int {
	cfg, err := config.Load(configFile)
	if err != nil || cfg.Password == "" {
		outputError(fmt.Sprintf("No password configured in %s. Run 'sudo wd-auto-unlock config' first.", configFile), asJSON)
		return 2
	}

	devPath, err := resolveDeviceTarget(cfg.Device, "")
	if err != nil {
		outputError(err.Error(), asJSON)
		return 1
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 30
	}

	return cmdUnlock(devPath, cfg.Password, cfg.UUID, cfg.MountPoint, timeout, asJSON)
}

func cmdConfig(devicePath, password, uuid, mountPoint string, timeout int, configFile string, enableService, asJSON bool) int {
	isInteractive := term.IsTerminal(int(os.Stdin.Fd()))

	if isInteractive {
		fmt.Println("=== Western Digital Auto-Unlock Setup Wizard ===")
		fmt.Println()

		if devicePath == "" {
			devices, _ := device.FindPassportDevices()
			if len(devices) == 1 {
				devicePath = devices[0].Node
				fmt.Printf("Detected Western Digital drive: %s (%s %s)\n", devicePath, devices[0].Vendor, devices[0].Model)
			} else if len(devices) > 1 {
				fmt.Println("Found multiple Western Digital drives:")
				for i, d := range devices {
					fmt.Printf("  [%d] %s (%s %s)\n", i+1, d.Node, d.Vendor, d.Model)
				}
				fmt.Print("Select drive number [1]: ")
				var choice string
				fmt.Scanln(&choice)
				idx := 0
				if choice != "" {
					fmt.Sscanf(choice, "%d", &idx)
					idx--
				}
				if idx >= 0 && idx < len(devices) {
					devicePath = devices[idx].Node
				}
			}
		}

		if devicePath == "" {
			fmt.Print("Enter drive device path (e.g. /dev/sdb): ")
			fmt.Scanln(&devicePath)
		}

		if password == "" {
			fmt.Print("Enter drive unlock password: ")
			passBytes, _ := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Println()
			password = string(passBytes)
		}

		if devicePath != "" && password != "" {
			fmt.Printf("Testing password against %s...\n", devicePath)
			if t, err := scsi.OpenTransport(devicePath); err == nil {
				if _, err := scsi.UnlockDrive(t, password); err != nil {
					fmt.Printf("Warning: Test unlock returned: %v\n", err)
				} else {
					fmt.Println("Password verified successfully!")
					device.RescanKernelDevice(devicePath, 5)
				}
				t.Close()
			}
		}

		if uuid == "" && devicePath != "" {
			devName := strings.TrimPrefix(devicePath, "/dev/")
			parts := device.GetBlockDevicePartitions(devName)
			if len(parts) > 0 {
				for _, p := range parts {
					if p.UUID != "" {
						uuid = p.UUID
						fmt.Printf("Detected partition %s with UUID: %s\n", p.Node, uuid)
						break
					}
				}
			}
		}

		if uuid != "" && mountPoint == "" {
			fmt.Print("Enter mount point directory [/media/WD]: ")
			var mntInput string
			fmt.Scanln(&mntInput)
			if strings.TrimSpace(mntInput) != "" {
				mountPoint = strings.TrimSpace(mntInput)
			} else {
				mountPoint = "/media/WD"
			}
		}

		if !enableService {
			fmt.Print("Enable background systemd service for auto-unlock on boot and plug-in? [Y/n]: ")
			var svcInput string
			fmt.Scanln(&svcInput)
			if strings.ToLower(strings.TrimSpace(svcInput)) != "n" {
				enableService = true
			}
		}
	}

	if password == "" {
		outputError("Password is required for configuration. Provide via --password.", asJSON)
		return 2
	}

	if timeout <= 0 {
		timeout = 30
	}

	cfg := &config.Config{
		Password:   password,
		Device:     devicePath,
		UUID:       uuid,
		MountPoint: mountPoint,
		Timeout:    timeout,
	}

	if err := config.Save(configFile, cfg); err != nil {
		outputError(fmt.Sprintf("Failed to write configuration file %s: %v", configFile, err), asJSON)
		return 1
	}

	servicesEnabled := false
	if enableService {
		_ = exec.Command("systemctl", "enable", "--now", "wd-unlock.timer").Run()
		_ = exec.Command("udevadm", "control", "--reload-rules").Run()
		servicesEnabled = true
	}

	if asJSON {
		res := map[string]any{
			"success":          true,
			"config_file":      configFile,
			"device":           devicePath,
			"uuid":             uuid,
			"mount_point":      mountPoint,
			"timeout":          timeout,
			"services_enabled": servicesEnabled,
		}
		out, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(out))
		return 0
	}

	fmt.Printf("Saved configuration to %s (mode 0600).\n", configFile)
	if servicesEnabled {
		fmt.Println("Enabled wd-unlock.timer and reloaded udev rules.")
	}
	fmt.Println("Setup complete.")
	return 0
}

func cmdUnmount(mountPoint string, asJSON bool) int {
	if mountPoint == "" {
		outputError("No mount point specified. Provide via -m/--mount-point or config file.", asJSON)
		return 2
	}

	alreadyUnmounted, err := device.UnmountPath(mountPoint)
	if err != nil {
		outputError(fmt.Sprintf("Failed to unmount %s: %v", mountPoint, err), asJSON)
		return 1
	}

	if asJSON {
		res := map[string]any{
			"success":           true,
			"mount_point":       mountPoint,
			"already_unmounted": alreadyUnmounted,
		}
		out, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(out))
		return 0
	}

	if alreadyUnmounted {
		fmt.Printf("%s was not mounted.\n", mountPoint)
	} else {
		fmt.Printf("Successfully unmounted %s.\n", mountPoint)
	}
	return 0
}
