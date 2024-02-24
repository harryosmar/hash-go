package signature_go

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"io"
)

type JwtSignHS512Hmac struct {
	key []byte
}

func NewJwtSignHS512Hmac(key []byte) *JwtSignHS512Hmac {
	return &JwtSignHS512Hmac{key: key}
}

func (j JwtSignHS512Hmac) Sign(ctx context.Context, payload jwt.MapClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, payload)
	return token.SignedString(j.key)
}

func (j JwtSignHS512Hmac) ValidateReturnBytes(ctx context.Context, token string) ([]byte, error) {
	claims, err := j.Validate(ctx, token)
	if err != nil {
		return nil, err
	}

	return json.Marshal(claims)
}

func (j JwtSignHS512Hmac) ValidateReturnReader(ctx context.Context, token string) (io.Reader, error) {
	b, err := j.ValidateReturnBytes(ctx, token)
	if err != nil {
		return nil, err
	}

	return bytes.NewReader(b), err
}

func (j JwtSignHS512Hmac) Validate(ctx context.Context, tokenStr string) (*jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("JwtSignHS512Hmac.Validate unexpected signing method: %v", token.Header["alg"])
		}

		return j.key, nil
	})

	if token == nil || err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		err = claims.Valid()
		if err != nil {
			return nil, err
		}

		return &claims, nil
	}

	return nil, err
}
