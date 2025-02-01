package signature_go

import (
	"context"
	"crypto/rsa"
	_ "crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

//go:generate mockgen -destination=mocks/mock_Signer.go -package=mocks . Signer
type (
	Signer interface {
		Sign(ctx context.Context, data []byte) ([]byte, error)
	}
)

func SignOutputBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func SignOutputHex(data []byte) string {
	return hex.EncodeToString(data[:])
}

func LoadPrivateKeyFromBase64Encoded(base64EncodedKey string) (*rsa.PrivateKey, error) {
	keyBytes, err := DecodeBase64(base64EncodedKey)
	if err != nil {
		return nil, err
	}

	return GetPrivateKeyFromBytes(keyBytes)
}

func DecodeBase64(input string) ([]byte, error) {
	// Add padding back
	padding := len(input) % 4
	if padding != 0 {
		input += strings.Repeat("=", 4-padding)
	}

	return base64.StdEncoding.DecodeString(input)
}

func LoadPublicKeyFromBase64Encoded(base64EncodedKey string) (*rsa.PublicKey, error) {
	keyBytes, err := DecodeBase64(base64EncodedKey)
	if err != nil {
		return nil, err
	}

	return GetPublicKeyFromBytes(keyBytes)
}

func GetPublicKeyFromBytes(publicKeyPem []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(publicKeyPem)
	if block == nil {
		err := errors.New("ssh: no publicKey found")
		return nil, err
	}

	var rawKey interface{}

	switch block.Type {
	case "RSA PUBLIC KEY":
		rsaPrivate, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rawKey = rsaPrivate
	case "PUBLIC KEY":
		rsaPrivate, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rawKey = rsaPrivate
	default:
		err := fmt.Errorf("ssh: unsupported publicKey type %q", block.Type)
		return nil, err
	}

	switch t := rawKey.(type) {
	case *rsa.PublicKey:
		return t, nil
	default:
		err := fmt.Errorf("ssh: unsupported publickey type %T", rawKey)
		return nil, err
	}
}

func GetPrivateKeyFromBytes(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		err := errors.New("ssh: no privateKey found")
		return nil, err
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		rsaPrivate, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}

		return rsaPrivate, nil
	case "PRIVATE KEY":
		rsaPrivate, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}

		key, ok := rsaPrivate.(*rsa.PrivateKey)
		if ok {
			return key, nil
		}

		return nil, fmt.Errorf("ssh: unsupported privateKey type %T", rsaPrivate)
	default:
		err := fmt.Errorf("ssh: unsupported privateKey type %q", block.Type)
		return nil, err
	}
}
