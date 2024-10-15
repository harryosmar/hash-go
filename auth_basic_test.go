package signature_go_test

import (
	signature_go "github.com/harryosmar/hash-go"
	"testing"
)

func TestGenerateBasicAuthorization(t *testing.T) {
	type args struct {
		clientId     string
		clientSecret string
	}

	var testData = []struct {
		name     string
		args     args
		expected string
	}{
		{
			name: "#testcase 1",
			args: args{
				clientId:     "Client_ID",
				clientSecret: "Client_Secret",
			},
			expected: "Q2xpZW50X0lEOkNsaWVudF9TZWNyZXQ=",
		},
	}
	for _, tt := range testData {
		t.Run(tt.name, func(t *testing.T) {
			actual := signature_go.GenerateBasicAuthorization(tt.args.clientId, tt.args.clientSecret)
			if actual != tt.expected {
				t.Errorf("expect %s got %s", tt.expected, actual)
				return
			}
		})
	}
}
