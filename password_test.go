package signature_go_test

import (
	signature_go "github.com/harryosmar/hash-go"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"testing"
)

func TestEncrypt(t *testing.T) {
	type args struct {
		plainPassword string
	}

	var testData = []struct {
		name string
		args args
	}{
		{
			name: "#testcase 1",
			args: args{
				plainPassword: "makcik",
			},
		},
	}
	for _, tt := range testData {
		t.Run(tt.name, func(t *testing.T) {
			encrypt := signature_go.NewBcryptPasswordEncrypt(bcrypt.MinCost)
			s, err := encrypt.Encrypt(tt.args.plainPassword)
			if err != nil {
				t.Error(err)
				return
			}
			log.Infof("encypted password %s", s)

			err = encrypt.Validate("$2a$04$KkEewy/XI4amB6EkZ78ku.J4hyQcpHQO7.XBBII6ujYZ8FzKoJpKq", "makcik")
			if err != nil {
				t.Error(err)
			}
		})
	}
}
