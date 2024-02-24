package signature_go

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
)

type (
	SignerMD5 struct {
		key []byte
	}
)

func NewSignerMD5(key string) *SignerMD5 {
	return &SignerMD5{key: []byte(key)}
}

func (r SignerMD5) Sign(ctx context.Context, data []byte) ([]byte, error) {
	mac := hmac.New(md5.New, r.key)
	_, err := mac.Write(data)
	if err != nil {
		return nil, err
	}

	return mac.Sum(nil), nil
}
