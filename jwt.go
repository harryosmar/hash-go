package signature_go

import (
	"context"
	"encoding/json"
	"github.com/dgrijalva/jwt-go"
	"io"
)

//go:generate mockgen -destination=mocks/mock_JwtSign.go -package=mocks . JwtSign
type JwtSign interface {
	Sign(ctx context.Context, payload *jwt.MapClaims) (string, error)
	Validate(ctx context.Context, token string) (jwt.MapClaims, error)
	ValidateReturnBytes(ctx context.Context, token string) ([]byte, error)
	ValidateReturnReader(ctx context.Context, token string) (io.Reader, error)
}

func PayloadToJwtClaims(payload []byte) (*jwt.MapClaims, error) {
	var claims jwt.MapClaims
	err := json.Unmarshal(payload, &claims)
	if err != nil {
		return nil, err
	}
	return &claims, err
}
