package signature_go_test

import (
	"context"
	_ "crypto/sha512"
	hash "github.com/harryosmar/hash-go"
	"github.com/stretchr/testify/assert"
	"log"
	"net/url"
	"testing"
)

const privateKeyStr = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCdyzv2c2+/eSBR
GdD/YGG4Ag1bgEMTNhViLTPcdOJqEwsG1NL2qx3R3T9FbqgAXGLJLuihbE3SlAXh
Ez+GlTg6RTVDLajLcawsDQdFd+9TWDcxjht363a53mw4FlJLXQkcFuUXcBxbeSlW
bmil90+tv+R91lliLsZS6i5jKGdMa/GfHVCAwsIg+PeQC+NU4bUmQI8HCQuiHxEM
qo71podspAfaFltTKZotCI2ZwWyb3r7BDEIkGSv3iKrsE6PLChoyNcdYPfdO4LA2
VbpMdgzljxFE/ypLc67bz6kX1ulzjD2ZHrXMRZZrbeitEAgfZaz5ygdr2VFQl5oS
s+ePAuLnAgMBAAECggEAThMgMTo+4aOiLN60PZfH4g8J4utcxOWuwOwSzBL9cHTJ
sPCfDbPvRkbNpqIw+DS+IENYkX6QJxBctFgcx4+Pya0yxHGUIk21Xfp4TZQhU8DD
Vn608qoMDb2TGFFbGLUI6+AcLHOpZE1X+c8Zcn0i7JqVCPqFMYJpWN9MYn28VuAP
Nk0yOUI3tYcdby5BheK/xZzpPqo2x3njgVrKx2EhzVn0AdqEQ5h8Nb6aFxWUDRzF
PUWO6XnGNQ7AMkTCPVl32LxgURxhxrl3bpSOXpYPcjaKzslBUpiV/9a/MLGuDx4v
LPv5Eq29XhIPAkGSAO3jtRYiPghYdzGO4aNtPwauKQKBgQDNS5G20ES/E72voNHw
1Jl4vXe8s0aivznYJxhFCoXBDglApHGfPbUoqFyuL1ZdYcH03L+OpszcuFjCEmem
njegQkLtBKrMW1th8hwRK/Zj76fi7Ml2JJOyPMpQXNmd4hH1etUqtICC5M/EwND6
as4vmnn/ccJO4/hJYDauv8GyEwKBgQDExD8Go9Vn8IMfZqa44Hv68agXaqqEWKul
jIqC7qxl+NQhR/yNzfBsMggXbECb3WYmoUaMu/vvwyWKuN6xPExKD//KsPKFM73o
v66UtdKb4IAv68CkElVyWc95JnnoCLd0gDAPFhsEYqmABv0jleHkT5h6UmEKp3gJ
6YU2U7xGXQKBgGJ3npp65p5nj5HPpyLGNh5tciL2MikZY1tD1SY4V9MzMkjpFv50
EJJBvsJlPh1oKCmUP+TiKFytpxTe0wxd0vxxC7y3glymbPxbrg6mcXWZm4MCY9bg
0F6rPbax8kcCCe8eTWRAU2t06BrNCO8zj1XR2DYnkDVartoy5ceHfhY1AoGBAJwk
+7riMky8QOGfTTiy88/tCy4h+FT0JKpH//btPiPhtTz/6jwBrAPAJEmqHw9RP2ny
W5D88G2Q1+7gy9+r8QJo9dy8VIg9yju0OO9L5mjKXA8rL4FEB0iqWolSbjUjDapG
u1yNdz0gqk+tvB4MJ+lM/Lw9OUMCKLD8/jhhdKwFAoGBAL9rS1POEDoa8ak++tSc
AthfMatN5F0N5lS6TkzHRRIunzUf2XO9ttHYYoaHR+8osjoJeKEH0YRFFkJ7Wxvo
2I5rfzhZ+njlQnTQbMVTD2VubXx0suUKGjNoGrJ5VbJil8D1ekTT1cYrWdi7UqNn
NoosM1ra0AQCianf3TItnIzV
-----END PRIVATE KEY-----`

func TestGetPrivateKey(t *testing.T) {

	type args struct {
	}
	testData := []struct {
		name           string
		args           args
		expectedResult string
	}{
		{
			name:           "Should be valid",
			args:           args{},
			expectedResult: "",
		},
	}

	for _, tt := range testData {
		t.Run(tt.name, func(t *testing.T) {
			key, err := hash.GetPrivateKeyFromBytes([]byte(privateKeyStr))
			log.Printf("private key %v", key)
			if err != nil {
				t.Errorf("%v", err)
				return
			}
		})
	}
}

func TestSha256PrivateKeySigner(t *testing.T) {

	type args struct {
		data string
	}
	testData := []struct {
		name           string
		args           args
		expectedResult string
	}{
		{
			name: "Should be valid",
			args: args{
				data: `POST /api/v1/zoloz/authentication/test
2188487325442931.2022-05-27T11:53:28+0000.{"title":"hello","description":"just for demonstration."}`,
			},
			expectedResult: "gDkciFcBUMJYSsIqwnaBMg2ydAjLirQU7%2FChr0eH5tHzvVq7wcf8rstwhS%2BfKNSsKB%2BM5T56T3VmZRtwDIuXWb8oTfUHpUyrnkxzfF%2FwCamoS1CiE1ciW8z3cc%2F71%2FKeX4oStBsXUnOeFhUoh1RiN7X39PZaHw5WoMH2Y2SSjaZ0jkPBTaydBIC%2BHhhd2MY0o6q7fqrgxyDkUUIn36LMaLAu4mWr1fIcZ4bMc0m65Plv%2B0MAkHJGGpsOD2EKf15H5PKZUreFkd4SlPtLoQvIPFZtToTUZ3tgN1FZ5Ts0DAy49RvJ2n3YICbQM17ziOoCuH2iepVddxOaCDjHmAlTsg%3D%3D",
		},
	}

	for _, tt := range testData {
		t.Run(tt.name, func(t *testing.T) {
			privateKey, err := hash.GetPrivateKeyFromBytes([]byte(privateKeyStr))
			if err != nil {
				t.Errorf("hash_go.GetPrivateKeyFromBytes err %v", err)
				return
			}

			signer := hash.NewRsa256Signer(privateKey)
			signBytes, err := signer.Sign(context.TODO(), []byte(tt.args.data))
			if err != nil {
				t.Errorf("signer.Sign err %v", err)
				return
			}
			sign := hash.SignOutputBase64(signBytes)
			sign = url.QueryEscape(sign)
			if sign != tt.expectedResult {
				t.Errorf("expect %s got %s", tt.expectedResult, sign)
				return
			}
		})
	}
}

func TestGetPublicKeyFromBytesV2(t *testing.T) {

	type args struct {
	}
	testData := []struct {
		name           string
		args           args
		expectedResult string
		publicKeyBytes []byte
		checksum       string
	}{
		{
			name:           "Should be valid",
			args:           args{},
			expectedResult: "",
			publicKeyBytes: []byte(`-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAyZ8o/B2NPV1/fcITOihi
1GBNbidZmGn74opJYGPWpssd/mtj729MEYhI3XGMDsyK34LGNd5egiYNu86NiBqU
8mQyfQyo2ihsqHONs+oovWwSBk1nWOqBCWWOlxeKJfy4Kmu063TsJD1B7gOpv2bo
DWPw9MF2LG5Ce+nOlztonsnN/yYlUF9+Ble4zlknNLCi/kmd+TcglQN/ax1cORdc
oDkAq8o6DNiDSlXmWdg3Qd9nY/EKHy/kc35kR5PheaL3RC51JNwcNX7A49ZTayT9
VaaqQ1RKNHJTqjjaoE15ch8PCzfqWMCyFLjBt3GdG7zLqENN3O+qLg2QWyu4Ech9
yCcshgrODZfD1And8qSvgV9EBsWLQ0J+OyCcglsxJtKsi7t7TuKc1HDNqPjLru2o
TlWXPnOezW+xx0S0bgK6uQMXmKRCN4tTYKPcIceEC/MChVjvuz0hky3w5OsUzNeJ
AIdY7na5iF7jmVPChKicK3a3cxnse4RFjaz6HjDYWuaINx48LHo82Q6sYd9RVxgs
MJ/dP4tEAm4bYCv7UjIub9pVqyPixqp/A8KEpBRzTosfA3ituDT1KbvYiyTcdfJW
0+AOUOSkp7JqRwHNVRC4ldgTS19zLDC1g6WOxjsol9TbefLpX/QxCknCV26LHFEe
P5ch3JGYvGb8qIHwVzD+FEkCAwEAAQ==
-----END PUBLIC KEY-----
`),
			checksum: "4ab797e367d2aecd46cfbd125537472f5b98f39d",
		},
	}

	for _, tt := range testData {
		t.Run(tt.name, func(t *testing.T) {
			key, keyBytes, err := hash.GetPublicKeyFromBytesV2(tt.publicKeyBytes)
			log.Printf("public key %v\n", key)

			signerSha1 := hash.NewSignerSha1("")
			checksumBytes, err := signerSha1.Sign(context.TODO(), keyBytes)
			checksum := hash.SignOutputHex(checksumBytes)
			assert.NoError(t, err)
			log.Printf("public bytes %v\n", checksum)
			assert.NoError(t, err)
			assert.Equal(t, tt.checksum, checksum)
		})
	}
}
