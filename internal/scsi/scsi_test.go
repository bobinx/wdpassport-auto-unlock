package scsi

import (
	"encoding/binary"
	"testing"

	"github.com/bobinx/wdpassport-auto-unlock/internal/crypto"
)

type MockTransport struct {
	StatusResponses [][]byte
	HSB1Response    []byte
	WriteErrors     []error
	WrittenCDBs     [][]byte
	WrittenPayloads [][]byte
}

func (m *MockTransport) Read(cdb []byte, dataLen int) ([]byte, error) {
	if cdb[0] == 0xC0 {
		if len(m.StatusResponses) > 0 {
			resp := m.StatusResponses[0]
			m.StatusResponses = m.StatusResponses[1:]
			return resp, nil
		}
	}
	if cdb[0] == 0xD8 {
		if m.HSB1Response != nil {
			return m.HSB1Response, nil
		}
	}
	buf := make([]byte, dataLen)
	return buf, nil
}

func (m *MockTransport) Write(cdb []byte, data []byte) error {
	m.WrittenCDBs = append(m.WrittenCDBs, cdb)
	m.WrittenPayloads = append(m.WrittenPayloads, data)
	if len(m.WriteErrors) > 0 {
		err := m.WriteErrors[0]
		m.WriteErrors = m.WriteErrors[1:]
		return err
	}
	return nil
}

func (m *MockTransport) Close() error {
	return nil
}

func makeStatusBlock(lockedCode uint8) []byte {
	block := make([]byte, BlockSize)
	block[0] = 0x45
	block[3] = lockedCode
	block[4] = 0x04 // AES_256_XTS
	binary.BigEndian.PutUint16(block[6:8], 32)
	return block
}

func makeHSB1Block(iteration int) []byte {
	block := make([]byte, BlockSize)
	block[0] = 0x00
	block[1] = 0x01
	block[2] = 'D'
	block[3] = 'W'
	binary.LittleEndian.PutUint32(block[8:12], uint32(iteration))
	copy(block[12:20], []byte("T\x00E\x00S\x00T\x00"))

	ck, _ := crypto.ComputeChecksum(block)
	block[511] = ck
	return block
}

func TestGetEncryptionStatus(t *testing.T) {
	mock := &MockTransport{
		StatusResponses: [][]byte{makeStatusBlock(0x01)},
	}

	status, err := GetEncryptionStatus(mock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if status.Status != "locked" {
		t.Errorf("expected locked, got %s", status.Status)
	}
	if status.Cipher != "AES_256_XTS" {
		t.Errorf("expected AES_256_XTS, got %s", status.Cipher)
	}
}

func TestUnlockDriveSuccess(t *testing.T) {
	mock := &MockTransport{
		StatusResponses: [][]byte{
			makeStatusBlock(0x01), // Initial query: locked
			makeStatusBlock(0x02), // Verification query: unlocked
		},
		HSB1Response: makeHSB1Block(10),
	}

	res, err := UnlockDrive(mock, "mypassword")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !res.Success {
		t.Errorf("expected success=true")
	}
	if res.Status != "unlocked" {
		t.Errorf("expected unlocked, got %s", res.Status)
	}
}
