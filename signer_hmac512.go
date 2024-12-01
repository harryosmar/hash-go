package signature_go

import (
	"context"
	"crypto/hmac"
	"crypto/sha512"
)

type (
	SignerHMAC512 struct {
		key []byte
	}
)

func NewSignerHMAC512(key string) *SignerHMAC512 {
	return &SignerHMAC512{key: []byte(key)}
}

func (r SignerHMAC512) Sign(ctx context.Context, data []byte) ([]byte, error) {
	mac := hmac.New(sha512.New, r.key)
	_, err := mac.Write(data)
	if err != nil {
		return nil, err
	}
	
	return mac.Sum(nil), nil
}
