package crypto

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"unicode/utf16"
)

// ComputeChecksum computes the Western Digital Handy Store Block checksum.
func ComputeChecksum(data []byte) (uint8, error) {
	if len(data) < 510 {
		return 0, errors.New("data block must be at least 510 bytes")
	}
	var total int
	for _, b := range data[:510] {
		total += int(b)
	}
	total += int(data[0])
	return uint8((-total) & 0xFF), nil
}

// EncodeUTF16LE encodes a string to UTF-16LE without a Byte Order Mark (BOM).
func EncodeUTF16LE(s string) []byte {
	runes := []rune(s)
	u16 := utf16.Encode(runes)
	buf := make([]byte, len(u16)*2)
	for i, r := range u16 {
		binary.LittleEndian.PutUint16(buf[i*2:], r)
	}
	return buf
}

// DeriveKey derives the Western Digital password key from salt and passphrase.
func DeriveKey(passphrase string, iteration int, salt []byte) []byte {
	var cleanChars []byte
	saltPadded := make([]byte, len(salt)+2)
	copy(saltPadded, salt)

	for i := 0; i < len(saltPadded)/2; i++ {
		b0 := saltPadded[2*i]
		b1 := saltPadded[2*i+1]
		if b0 == 0 && b1 == 0 {
			break
		}
		cleanChars = append(cleanChars, b0)
	}

	cleanSalt := string(cleanChars)
	key := EncodeUTF16LE(cleanSalt + passphrase)

	for i := 0; i < iteration; i++ {
		h := sha256.Sum256(key)
		key = h[:]
	}
	return key
}
