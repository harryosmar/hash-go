package signature_go

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	_ "crypto/sha512"
)

type (
	SignerSha1 struct {
		key []byte
	}
)

func NewSignerSha1(key string) *SignerSha1 {
	return &SignerSha1{key: []byte(key)}
}

func (r SignerSha1) Sign(ctx context.Context, data []byte) ([]byte, error) {
	mac := hmac.New(sha1.New, r.key)
	_, err := mac.Write(data)
	if err != nil {
		return nil, err
	}

	return mac.Sum(nil), nil
}
