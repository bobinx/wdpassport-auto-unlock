//go:build !linux

package scsi

import (
	"fmt"
	"runtime"
)

// OpenTransport is a stub on non-Linux platforms.
func OpenTransport(devicePath string) (Transport, error) {
	return nil, fmt.Errorf("SCSI SG_IO pass-through is only supported on Linux (running on %s)", runtime.GOOS)
}
