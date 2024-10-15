package signature_go

import (
	"encoding/base64"
	"fmt"
)

func GenerateBasicAuthorization(clientId string, clientSecret string) string {
	str := fmt.Sprintf("%s:%s", clientId, clientSecret)
	return base64.StdEncoding.EncodeToString([]byte(str))
}
