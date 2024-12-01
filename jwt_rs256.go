package signature_go

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"io"
)

type JwtSignRS256Hmac struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

func NewJwtSignRS256Hmac(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey) *JwtSignRS256Hmac {
	return &JwtSignRS256Hmac{privateKey: privateKey, publicKey: publicKey}
}

func (j JwtSignRS256Hmac) Sign(ctx context.Context, payload *jwt.MapClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, payload)
	return token.SignedString(j.privateKey)
}

func (j JwtSignRS256Hmac) Validate(ctx context.Context, tokenStr string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("JwtSignRS256Hmac.Validate unexpected signing method: %v", token.Header["alg"])
		}

		return j.publicKey, nil
	})

	if token == nil || err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, err
}

func (j JwtSignRS256Hmac) ValidateReturnBytes(ctx context.Context, token string) ([]byte, error) {
	claims, err := j.Validate(ctx, token)
	if err != nil {
		return nil, err
	}

	return json.Marshal(claims)
}

func (j JwtSignRS256Hmac) ValidateReturnReader(ctx context.Context, token string) (io.Reader, error) {
	b, err := j.ValidateReturnBytes(ctx, token)
	if err != nil {
		return nil, err
	}

	return bytes.NewReader(b), err
}
