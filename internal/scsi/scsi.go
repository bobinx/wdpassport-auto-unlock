package scsi

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/bobinx/wdpassport-auto-unlock/internal/crypto"
)

const (
	BlockSize = 512
)

var (
	ErrDeviceLocked   = errors.New("device is locked")
	ErrInvalidStatus  = errors.New("invalid status response")
	ErrWrongPassword  = errors.New("incorrect password")
	ErrHSB1Checksum   = errors.New("HSB1 checksum mismatch")
)

var SecurityStatusMap = map[uint8]string{
	0x00: "unencrypted",
	0x01: "locked",
	0x02: "unlocked",
}

var CipherMap = map[uint8]string{
	0x00: "None",
	0x01: "AES_128_CBC",
	0x02: "AES_256_CBC",
	0x03: "AES_128_XTS",
	0x04: "AES_256_XTS",
}

// Transport abstracts raw SCSI command execution.
type Transport interface {
	Read(cdb []byte, dataLen int) ([]byte, error)
	Write(cdb []byte, data []byte) error
	Close() error
}

// EncryptionStatus holds hardware encryption parameters from CDB 0xC0.
type EncryptionStatus struct {
	LockedCode     uint8  `json:"locked_code"`
	Status         string `json:"status"`
	CipherCode     uint8  `json:"cipher_code"`
	Cipher         string `json:"cipher"`
	KeyLengthBytes uint16 `json:"key_length_bytes"`
}

// UnlockResult holds outcome of an unlock operation.
type UnlockResult struct {
	Success         bool   `json:"success"`
	AlreadyUnlocked bool   `json:"already_unlocked,omitempty"`
	Status          string `json:"status"`
	Cipher          string `json:"cipher"`
}

// GetEncryptionStatus queries the drive's security state via CDB 0xC0 0x45.
func GetEncryptionStatus(t Transport) (*EncryptionStatus, error) {
	cdb := []byte{0xC0, 0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x00}
	data, err := t.Read(cdb, BlockSize)
	if err != nil {
		return nil, fmt.Errorf("SCSI 0xC0 query failed: %w", err)
	}

	if len(data) < 12 || data[0] != 0x45 {
		return nil, fmt.Errorf("%w: invalid signature 0x%02X", ErrInvalidStatus, data[0])
	}

	lockedCode := data[3]
	cipherCode := data[4]
	keyLen := binary.BigEndian.Uint16(data[6:8])

	statusDesc := SecurityStatusMap[lockedCode]
	if statusDesc == "" {
		statusDesc = fmt.Sprintf("unknown (0x%02X)", lockedCode)
	}

	cipherDesc := CipherMap[cipherCode]
	if cipherDesc == "" {
		cipherDesc = fmt.Sprintf("unknown (0x%02X)", cipherCode)
	}

	return &EncryptionStatus{
		LockedCode:     lockedCode,
		Status:         statusDesc,
		CipherCode:     cipherCode,
		Cipher:         cipherDesc,
		KeyLengthBytes: keyLen,
	}, nil
}

// ReadHandyStoreBlock1 reads HSB1 (CDB 0xD8) to extract KDF iterations and salt.
func ReadHandyStoreBlock1(t Transport) (int, []byte, error) {
	cdb := []byte{0xD8, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00}
	data, err := t.Read(cdb, BlockSize)
	if err != nil {
		return 0, nil, fmt.Errorf("SCSI 0xD8 query failed: %w", err)
	}

	if len(data) != BlockSize {
		return 0, nil, fmt.Errorf("unexpected HSB1 length: %d bytes", len(data))
	}

	expectedChecksum, err := crypto.ComputeChecksum(data)
	if err != nil {
		return 0, nil, err
	}

	actualChecksum := data[511]
	if expectedChecksum != actualChecksum {
		return 0, nil, fmt.Errorf("%w: calculated 0x%02X, device returned 0x%02X", ErrHSB1Checksum, expectedChecksum, actualChecksum)
	}

	// Signature must be "\x00\x01DW" (0x00, 0x01, 0x44, 0x57)
	if !bytes.Equal(data[0:4], []byte{0x00, 0x01, 'D', 'W'}) {
		return 0, nil, errors.New("invalid HSB1 signature")
	}

	iteration := int(binary.LittleEndian.Uint32(data[8:12]))
	salt := make([]byte, 8)
	copy(salt, data[12:20])

	return iteration, salt, nil
}

// UnlockDrive executes the unlock sequence against the device.
func UnlockDrive(t Transport, passphrase string) (*UnlockResult, error) {
	status, err := GetEncryptionStatus(t)
	if err != nil {
		return nil, err
	}

	if status.LockedCode == 0x00 || status.LockedCode == 0x02 {
		return &UnlockResult{
			Success:         true,
			AlreadyUnlocked: true,
			Status:          status.Status,
			Cipher:          status.Cipher,
		}, nil
	}

	if status.LockedCode != 0x01 {
		return nil, fmt.Errorf("drive cannot be unlocked in status '%s' (code 0x%02X)", status.Status, status.LockedCode)
	}

	iteration, salt, err := ReadHandyStoreBlock1(t)
	if err != nil {
		return nil, err
	}

	derivedKey := crypto.DeriveKey(passphrase, iteration, salt)

	pwLen := status.KeyLengthBytes
	if pwLen == 0 {
		pwLen = 32
	}

	pwBlock := make([]byte, 8)
	pwBlock[0] = 0x45
	binary.BigEndian.PutUint16(pwBlock[6:8], pwLen)

	payload := append(pwBlock, derivedKey...)

	cdb := make([]byte, 10)
	cdb[0] = 0xC1
	cdb[1] = 0xE1
	cdb[8] = byte(pwLen + 8)

	if err := t.Write(cdb, payload); err != nil {
		return nil, fmt.Errorf("SCSI 0xC1 unlock payload failed: %w", err)
	}

	// Verify status after unlock
	newStatus, err := GetEncryptionStatus(t)
	if err != nil {
		return nil, fmt.Errorf("failed to verify unlock status: %w", err)
	}

	if newStatus.LockedCode != 0x02 {
		return nil, ErrWrongPassword
	}

	return &UnlockResult{
		Success:         true,
		AlreadyUnlocked: false,
		Status:          newStatus.Status,
		Cipher:          newStatus.Cipher,
	}, nil
}
