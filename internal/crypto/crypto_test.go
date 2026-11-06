package crypto

import (
	"bytes"
	"testing"
)

func TestComputeChecksum(t *testing.T) {
	block := make([]byte, 512)
	block[0] = 0x01
	block[1] = 0x02

	ck, err := ComputeChecksum(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// sum(data[:510]) = 3; total = 3 + 1 = 4; (-4) & 0xFF = 252 (0xFC)
	if ck != 0xFC {
		t.Fatalf("expected 0xFC, got 0x%02X", ck)
	}

	_, errShort := ComputeChecksum(block[:100])
	if errShort == nil {
		t.Fatal("expected error for short block")
	}
}

func TestDeriveKey(t *testing.T) {
	// Salt stored as 2-byte spaced "TEST"
	salt := []byte("T\x00E\x00S\x00T\x00")
	passphrase := "mypassword"

	key1 := DeriveKey(passphrase, 10, salt)
	if len(key1) != 32 {
		t.Fatalf("expected 32 bytes key, got %d", len(key1))
	}

	key2 := DeriveKey(passphrase, 10, salt)
	if !bytes.Equal(key1, key2) {
		t.Fatal("expected deterministic key derivation")
	}

	keyDifferentPass := DeriveKey("otherpassword", 10, salt)
	if bytes.Equal(key1, keyDifferentPass) {
		t.Fatal("expected different key for different password")
	}
}
