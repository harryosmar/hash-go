package signature_go

import (
	"crypto/rand"
)

// GenerateAESKey generates a random AES key of the given size (16, 24, or 32 bytes)
func GenerateAESKey(size int) ([]byte, error) {
	key := make([]byte, size)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}
