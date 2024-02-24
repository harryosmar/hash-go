package signature_go

import "golang.org/x/crypto/bcrypt"

//go:generate mockgen -destination=mocks/mock_PasswordEncrypt.go -package=mocks . PasswordEncrypt
type PasswordEncrypt interface {
	Validate(actual string, expected string) error
	Encrypt(plainPassword string) (string, error)
}

type BcryptPasswordEncrypt struct {
	cost int
}

func NewBcryptPasswordEncrypt(cost int) *BcryptPasswordEncrypt {
	return &BcryptPasswordEncrypt{cost: cost}
}

func (b BcryptPasswordEncrypt) Encrypt(plainPassword string) (string, error) {
	password, err := bcrypt.GenerateFromPassword([]byte(plainPassword), b.cost)
	if err != nil {
		return "", err
	}
	return string(password), nil
}

func (b BcryptPasswordEncrypt) Validate(hashed string, plain string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashed), []byte(plain))
}
