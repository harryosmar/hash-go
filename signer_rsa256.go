package signature_go

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	_ "crypto/sha512"
)

type (
	rsa256Signer struct {
		*rsa.PrivateKey
	}
)

func NewRsa256Signer(privateKey *rsa.PrivateKey) *rsa256Signer {
	return &rsa256Signer{PrivateKey: privateKey}
}

func (r *rsa256Signer) Sign(ctx context.Context, data []byte) ([]byte, error) {
	hashed := sha256.Sum256(data)
	return rsa.SignPKCS1v15(rand.Reader, r.PrivateKey, crypto.SHA256, hashed[:])
}
