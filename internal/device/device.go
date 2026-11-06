package device

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/bobinx/wdpassport-auto-unlock/internal/scsi"
)

// PartitionInfo describes a block device partition.
type PartitionInfo struct {
	Name      string `json:"name"`
	Node      string `json:"node"`
	UUID      string `json:"uuid,omitempty"`
	SizeBytes int64  `json:"size_bytes"`
	SizeHuman string `json:"size_human"`
}

// DeviceInfo describes a discovered disk block device.
type DeviceInfo struct {
	Name           string          `json:"name"`
	Node           string          `json:"node"`
	Vendor         string          `json:"vendor"`
	Model          string          `json:"model"`
	SizeBytes      int64           `json:"size_bytes"`
	SizeHuman      string          `json:"size_human"`
	IsWD           bool            `json:"is_wd"`
	Partitions     []PartitionInfo `json:"partitions"`
	SecurityStatus string          `json:"security_status,omitempty"`
	Cipher         string          `json:"cipher,omitempty"`
}

// FormatBytes formats byte count into human-readable unit.
func FormatBytes(sizeBytes int64) string {
	val := float64(sizeBytes)
	units := []string{"B", "KB", "MB", "GB", "TB", "PB"}
	for i, unit := range units {
		if val < 1024.0 || i == len(units)-1 {
			if unit == "GB" || unit == "TB" || unit == "PB" {
				return fmt.Sprintf("%.1f %s", val, unit)
			}
			return fmt.Sprintf("%d %s", int64(val), unit)
		}
		val /= 1024.0
	}
	return fmt.Sprintf("%d B", sizeBytes)
}

// GetPartitionUUID resolves filesystem UUID for a partition from /dev/disk/by-uuid.
func GetPartitionUUID(partitionNode string) string {
	byUUID := "/dev/disk/by-uuid"
	entries, err := os.ReadDir(byUUID)
	if err != nil {
		return ""
	}

	targetReal, err := filepath.EvalSymlinks(partitionNode)
	if err != nil {
		targetReal = partitionNode
	}

	for _, entry := range entries {
		linkPath := filepath.Join(byUUID, entry.Name())
		realPath, err := filepath.EvalSymlinks(linkPath)
		if err == nil && realPath == targetReal {
			return entry.Name()
		}
	}
	return ""
}

// GetBlockDevicePartitions scans visible partitions for a given block device.
func GetBlockDevicePartitions(devName string) []PartitionInfo {
	var partitions []PartitionInfo
	sysDev := filepath.Join("/sys/block", devName)

	entries, err := os.ReadDir(sysDev)
	if err != nil {
		return partitions
	}

	for _, entry := range entries {
		partDir := filepath.Join(sysDev, entry.Name())
		if _, err := os.Stat(filepath.Join(partDir, "partition")); err == nil {
			var sizeBytes int64
			sizeData, err := os.ReadFile(filepath.Join(partDir, "size"))
			if err == nil {
				if sectors, err := strconv.ParseInt(strings.TrimSpace(string(sizeData)), 10, 64); err == nil {
					sizeBytes = sectors * 512
				}
			}

			node := filepath.Join("/dev", entry.Name())
			uuid := GetPartitionUUID(node)

			partitions = append(partitions, PartitionInfo{
				Name:      entry.Name(),
				Node:      node,
				UUID:      uuid,
				SizeBytes: sizeBytes,
				SizeHuman: FormatBytes(sizeBytes),
			})
		}
	}
	return partitions
}

// ScanAllDisks inspects /sys/block and returns detected WD Passport and other disks.
func ScanAllDisks() ([]DeviceInfo, []DeviceInfo, error) {
	var wdDevices []DeviceInfo
	var otherDevices []DeviceInfo

	sysBlock := "/sys/block"
	entries, err := os.ReadDir(sysBlock)
	if err != nil {
		return nil, nil, err
	}

	for _, entry := range entries {
		name := entry.Name()
		devDir := filepath.Join(sysBlock, name)
		deviceSub := filepath.Join(devDir, "device")

		if _, err := os.Stat(deviceSub); err != nil {
			continue
		}

		// Skip optical devices (type 5 is CD-ROM)
		typeData, err := os.ReadFile(filepath.Join(deviceSub, "type"))
		if err == nil {
			if strings.TrimSpace(string(typeData)) == "5" {
				continue
			}
		}

		vendorData, _ := os.ReadFile(filepath.Join(deviceSub, "vendor"))
		modelData, _ := os.ReadFile(filepath.Join(deviceSub, "model"))
		sizeData, _ := os.ReadFile(filepath.Join(devDir, "size"))

		vendor := strings.TrimSpace(string(vendorData))
		model := strings.TrimSpace(string(modelData))

		var sizeBytes int64
		if sectors, err := strconv.ParseInt(strings.TrimSpace(string(sizeData)), 10, 64); err == nil {
			sizeBytes = sectors * 512
		}

		vendorUpper := strings.ToUpper(vendor)
		modelUpper := strings.ToUpper(model)

		isWD := strings.Contains(vendorUpper, "WD") || strings.Contains(vendorUpper, "WESTERN DIGITAL") || strings.Contains(modelUpper, "WD")
		isPassport := strings.Contains(modelUpper, "PASSPORT") || strings.Contains(modelUpper, "ELEMENTS")

		if !(isWD && isPassport) {
			// Check /dev/disk/by-id
			byID := "/dev/disk/by-id"
			if idEntries, err := os.ReadDir(byID); err == nil {
				for _, idEntry := range idEntries {
					idUpper := strings.ToUpper(idEntry.Name())
					if (strings.Contains(idUpper, "WD") || strings.Contains(idUpper, "WESTERN_DIGITAL")) && strings.Contains(idUpper, "PASSPORT") {
						target, err := filepath.EvalSymlinks(filepath.Join(byID, idEntry.Name()))
						if err == nil && target == filepath.Join("/dev", name) {
							isWD = true
							isPassport = true
							break
						}
					}
				}
			}
		}

		partitions := GetBlockDevicePartitions(name)
		node := filepath.Join("/dev", name)

		info := DeviceInfo{
			Name:       name,
			Node:       node,
			Vendor:     vendor,
			Model:      model,
			SizeBytes:  sizeBytes,
			SizeHuman:  FormatBytes(sizeBytes),
			Partitions: partitions,
			IsWD:       isWD && isPassport,
		}

		if info.IsWD {
			info.SecurityStatus = "unknown"
			info.Cipher = "unknown"

			if transport, err := scsi.OpenTransport(node); err == nil {
				if encStatus, err := scsi.GetEncryptionStatus(transport); err == nil {
					info.SecurityStatus = encStatus.Status
					info.Cipher = encStatus.Cipher
				}
				transport.Close()
			}
			wdDevices = append(wdDevices, info)
		} else {
			otherDevices = append(otherDevices, info)
		}
	}

	return wdDevices, otherDevices, nil
}

// FindPassportDevices returns list of detected WD Passport block devices.
func FindPassportDevices() ([]DeviceInfo, error) {
	wdDevices, _, err := ScanAllDisks()
	return wdDevices, err
}

// ResolveDevice finds target block device from flag, env, config, or sysfs auto-discovery.
func ResolveDevice(cliDevice, cfgDevice string) (string, error) {
	if cliDevice != "" {
		return cliDevice, nil
	}
	if envDevice := os.Getenv("WD_DEVICE"); envDevice != "" {
		return envDevice, nil
	}
	if cfgDevice != "" {
		return cfgDevice, nil
	}

	devices, err := FindPassportDevices()
	if err != nil || len(devices) == 0 {
		return "", errors.New("no Western Digital My Passport device found. Specify via --device or WD_DEVICE env var")
	}

	return devices[0].Node, nil
}

// RescanKernelDevice instructs the kernel to re-read block device partition table.
func RescanKernelDevice(deviceNode string, timeoutSec int) {
	devName := filepath.Base(deviceNode)
	rescanPath := fmt.Sprintf("/sys/block/%s/device/rescan", devName)

	_ = os.WriteFile(rescanPath, []byte("1\n"), 0644)

	commands := [][]string{
		{"blockdev", "--rereadpt", deviceNode},
		{"partprobe", deviceNode},
		{"udevadm", "trigger", "--subsystem-match=block"},
	}

	for _, cmdArgs := range commands {
		cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
		_ = cmd.Run()
	}
}

// WaitForUUID polls for /dev/disk/by-uuid/<UUID> until timeout.
func WaitForUUID(uuid string, timeoutSec int) (string, error) {
	uuidPath := filepath.Join("/dev/disk/by-uuid", uuid)
	deadline := time.Now().Add(time.Duration(timeoutSec) * time.Second)

	for {
		if _, err := os.Stat(uuidPath); err == nil {
			realPath, err := filepath.EvalSymlinks(uuidPath)
			if err == nil {
				return realPath, nil
			}
			return uuidPath, nil
		}

		if time.Now().After(deadline) {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	return "", fmt.Errorf("timeout waiting for partition with UUID %s", uuid)
}

// IsMounted checks if a mount path is currently active.
func IsMounted(mountPoint string) bool {
	mountData, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return false
	}
	cleanTarget := filepath.Clean(mountPoint)
	for _, line := range strings.Split(string(mountData), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && filepath.Clean(fields[1]) == cleanTarget {
			return true
		}
	}
	return false
}

// MountDevice mounts a partition to target mount point.
func MountDevice(devNode, mountPoint string) error {
	if IsMounted(mountPoint) {
		return nil
	}

	if err := os.MkdirAll(mountPoint, 0755); err != nil {
		return fmt.Errorf("failed to create mount point directory: %w", err)
	}

	cmd := exec.Command("mount", devNode, mountPoint)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("mount failed: %s (%w)", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// UnmountPath unmounts the directory target cleanly.
func UnmountPath(mountPoint string) (bool, error) {
	if !IsMounted(mountPoint) {
		return true, nil
	}

	cmd := exec.Command("umount", mountPoint)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("umount failed: %s (%w)", strings.TrimSpace(string(out)), err)
	}
	return false, nil
}
