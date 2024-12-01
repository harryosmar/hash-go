package signature_go

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"io"
)

type JwtSignSHA256Hmac struct {
	secret []byte
}

func NewJwtSignSHA256Hmac(secret string) *JwtSignSHA256Hmac {
	return &JwtSignSHA256Hmac{secret: []byte(secret)}
}

func (j JwtSignSHA256Hmac) Sign(ctx context.Context, payload *jwt.MapClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, payload)
	return token.SignedString(j.secret)
}

func (j JwtSignSHA256Hmac) Validate(ctx context.Context, tokenStr string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return j.secret, nil
	})

	if token == nil || err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, err
}

func (j JwtSignSHA256Hmac) ValidateReturnBytes(ctx context.Context, token string) ([]byte, error) {
	claims, err := j.Validate(ctx, token)
	if err != nil {
		return nil, err
	}

	return json.Marshal(claims)
}

func (j JwtSignSHA256Hmac) ValidateReturnReader(ctx context.Context, token string) (io.Reader, error) {
	b, err := j.ValidateReturnBytes(ctx, token)
	if err != nil {
		return nil, err
	}

	return bytes.NewReader(b), err
}
