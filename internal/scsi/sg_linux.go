//go:build linux

package scsi

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const (
	SgIo           = 0x2285
	SgDxferToDev   = -2
	SgDxferFromDev = -3
	SgDxferNone    = -1
)

// SgIoHdr represents Linux struct sg_io_hdr.
type SgIoHdr struct {
	InterfaceID    int32
	DxferDirection int32
	CmdLen         uint8
	MxSbLen        uint8
	IovecCount     uint16
	DxferLen       uint32
	Dxferp         uintptr
	Cmdp           uintptr
	Sbp            uintptr
	Timeout        uint32
	Flags          uint32
	PackID         int32
	UsrPtr         uintptr
	Status         uint8
	MaskedStatus   uint8
	MsgStatus      uint8
	SbLenWr        uint8
	HostStatus     uint16
	DriverStatus   uint16
	Resid          int32
	Duration       uint32
	Info           uint32
}

// LinuxSgioTransport implements Transport via Linux SG_IO ioctl.
type LinuxSgioTransport struct {
	file *os.File
}

// OpenTransport opens the block device for SG_IO pass-through.
func OpenTransport(devicePath string) (Transport, error) {
	f, err := os.OpenFile(devicePath, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open device %s: %w", devicePath, err)
	}
	return &LinuxSgioTransport{file: f}, nil
}

// Read executes a SCSI read command.
func (t *LinuxSgioTransport) Read(cdb []byte, dataLen int) ([]byte, error) {
	buf := make([]byte, dataLen)
	sense := make([]byte, 32)

	hdr := SgIoHdr{
		InterfaceID:    'S',
		DxferDirection: SgDxferFromDev,
		CmdLen:         uint8(len(cdb)),
		MxSbLen:        uint8(len(sense)),
		DxferLen:       uint32(dataLen),
		Dxferp:         uintptr(unsafe.Pointer(&buf[0])),
		Cmdp:           uintptr(unsafe.Pointer(&cdb[0])),
		Sbp:            uintptr(unsafe.Pointer(&sense[0])),
		Timeout:        10000,
	}

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, t.file.Fd(), uintptr(SgIo), uintptr(unsafe.Pointer(&hdr)))
	if errno != 0 {
		return nil, fmt.Errorf("SG_IO ioctl error: %w", errno)
	}
	if hdr.Status != 0 || hdr.HostStatus != 0 || hdr.DriverStatus != 0 {
		return nil, fmt.Errorf("SCSI command failed: status=0x%02X, host=0x%04X, driver=0x%04X", hdr.Status, hdr.HostStatus, hdr.DriverStatus)
	}

	return buf, nil
}

// Write executes a SCSI write command.
func (t *LinuxSgioTransport) Write(cdb []byte, data []byte) error {
	sense := make([]byte, 32)

	var dataPtr uintptr
	if len(data) > 0 {
		dataPtr = uintptr(unsafe.Pointer(&data[0]))
	}

	hdr := SgIoHdr{
		InterfaceID:    'S',
		DxferDirection: SgDxferToDev,
		CmdLen:         uint8(len(cdb)),
		MxSbLen:        uint8(len(sense)),
		DxferLen:       uint32(len(data)),
		Dxferp:         dataPtr,
		Cmdp:           uintptr(unsafe.Pointer(&cdb[0])),
		Sbp:            uintptr(unsafe.Pointer(&sense[0])),
		Timeout:        10000,
	}

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, t.file.Fd(), uintptr(SgIo), uintptr(unsafe.Pointer(&hdr)))
	if errno != 0 {
		return fmt.Errorf("SG_IO ioctl error: %w", errno)
	}
	if hdr.Status != 0 || hdr.HostStatus != 0 || hdr.DriverStatus != 0 {
		return fmt.Errorf("SCSI command failed: status=0x%02X, host=0x%04X, driver=0x%04X", hdr.Status, hdr.HostStatus, hdr.DriverStatus)
	}

	return nil
}

// Close closes the file handle.
func (t *LinuxSgioTransport) Close() error {
	return t.file.Close()
}
