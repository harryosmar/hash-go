package signature_go_test

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	hash "github.com/harryosmar/hash-go"
	"testing"
	"time"
)

const (
	privateKeyBase64 = `LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUV2d0lCQURBTkJna3Foa2lHOXcwQkFRRUZBQVNDQktrd2dnU2xBZ0VBQW9JQkFRQzdWSlRVdDlVczhjS2oKTXpFZll5amlXQTRSNC9NMmJTMUdCNHQ3TlhwOThDM1NDNmRWTXZEdWljdEdldXJUOGpOYnZKWkh0Q1N1WUV2dQpOTW9TZm03Nm9xRnZBcDhHeTBpejVzeGpabVNuWHlDZFBFb3ZHaExhMFZ6TWFROHMrQ0xPeVM1Nll5Q0ZHZUpaCnFndHpKNkdSM2Vxb1lTVzliOVVNdmtCcFpPRFNjdFdTTkdqM1A3alJGRE81Vm9Ud0NRQVdiRm5PakRmSDVVbGcKcDJQS1NRblNKUDNBSkxRTkZOZTdicjFYYnJoVi8vZU8rdDUxbUlwR1NEQ1V2M0UwRERGY1dEVEg5Y1hEVFRsUgpaVkVpUjJCd3BaT09rRS9aMC9CVm5oWllMNzFvWlYzNGJLZldqUUl0NlYvaXNTTWFoZHNBQVNBQ3A0WlRHdHdpClZ1TmQ5dHliQWdNQkFBRUNnZ0VCQUtUbWphUzZ0a0s4QmxQWENsVFEydnB6L042dXhEZVMzNW1YcHFhc3Fza1YKbGFBaWRnZy9zV3FwalhEYlhyOTNvdElNTGxXc00rWDBDcU1EZ1NYS2VqTFMyang0R0RqSTFaVFhnKyswQU1KOApzSjc0cFd6VkRPZm1DRVEvN3dYczMrY2JuWGhLcmlPOFowMzZxOTJRYzErTjg3U0kzOG5rR2EwQUJIOUNOODNICm1RcXQ0ZkI3VWRIenVJUmUvbWUyUEdoSXE1WkJ6ajZoM0Jwb1BHekVQK3gzbDlZbUs4dC8xY04wcHFJK2RRd1kKZGdmR2phY2tMdS8ycUg4ME1DRjdJeVFhc2VaVU9KeUtyQ0x0U0QvSWl4di9oekRFVVBmT0NqRkRnVHB6ZjNjdwp0YTgrb0U0d0hDbzFpSTEvNFRsUGt3bVh4NHFTWHRtdzRhUVB6N0lEUXZFQ2dZRUE4S05UaENPMmdzQzJJOVBRCkRNLzhDdzBPOTgzV0NEWStvaSs3SlBpTkFKd3Y1RFlCcUVaQjFRWWRqMDZZRDE2WGxDL0hBWk1zTWt1MW5hMlQKTjBkcml3ZW5RUVd6b2V2M2cyUzdnUkRvUy9GQ0pTSTNqSitramd0YUE3UW16bGdrMVR4T0ROK0cxSDkxSFc3dAowbDdWbkwyN0lXeVlvMnFSUkszanp4cVVpUFVDZ1lFQXgwb1FzMnJlQlFHTVZabkFwRDFqZXE3bjRNdk5MY1B2CnQ4Yi9lVTlpVXY2WTRNajBTdW8vQVU4bFlaWG04dWJicUFsd3oyVlNWdW5EMnRPcGxIeU1VcnRDdE9iQWZWRFUKQWhDbmRLYUE5Z0FwZ2ZiM3h3MUlLYnVRMXU0SUYxRkpsM1Z0dW1mUW4vL0xpSDFCM3JYaGNkeW8zL3ZJdHRFawo0OFJha1VLQ2xVOENnWUVBelY3VzNDT09sRERjUWQ5MzVEZHRLQkZSQVBSUEFsc3BRVW56TWk1ZVNITUQvSVNMCkRZNUlpUUhiSUg4M0Q0YnZYcTBYN3FRb1NCU05QN0R2djNIWXVxTWhmMERhZWdybEJ1SmxsRlZWcTlxUFZSbksKeHQxSWwySGd4T0J2YmhPVCs5aW4xQnpBK1lKOTlVekM4NU8wUXowNkErQ210SEV5NGFaMmtqNWhIakVDZ1lFQQptTlM0K0E4RmtzczhKczFSaWVLMkxuaUJ4TWdtWW1sM3BmVkxLR256bW5nN0gyK2N3UExoUEl6SXV3eXRYeXdoCjJiemJzWUVmWXgzRW9FVmdNRXBQaG9hclFuWVB1a3JKTzRnd0UybzVUZTZUNW1KU1pHbFFKUWo5cTRaQjJEZnoKZXQ2SU5zSzBvRzhYVkdYU3BRdlFoM1JVWWVrQ1pRa0JCRmNwcVdwYklFc0NnWUFuTTNEUWYzRkpvU25YYU1ocgpWQklvdmljNWwweEZrRUhza0FqRlRldk84NkZzejFDMmFTZVJLU3FHRm9PUTB0bUp6QkVzMVI2S3FuSEluaWNEClRRcktoQXJnTFhYNHYzQ2RkamZUUkprRldEYkUvQ2t2S1pOT3JjZjFuaGFHQ1BzcFJKajJLVWtqMUZobDlDbmMKZG4vUnNZRU9OYndRU2pJZk1Qa3Z4Ris4SFE9PQotLS0tLUVORCBQUklWQVRFIEtFWS0tLS0t`
	publicKeyBase64  = `LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF1MVNVMUxmVkxQSENvek14SDJNbwo0bGdPRWVQek5tMHRSZ2VMZXpWNmZmQXQwZ3VuVlRMdzdvbkxSbnJxMC9Jelc3eVdSN1Frcm1CTDdqVEtFbjV1CitxS2hid0tmQnN0SXMrYk1ZMlprcDE4Z25UeEtMeG9TMnRGY3pHa1BMUGdpenNrdWVtTWdoUm5pV2FvTGN5ZWgKa2QzcXFHRWx2Vy9WREw1QWFXVGcwbkxWa2pSbzl6KzQwUlF6dVZhRThBa0FGbXhaem93M3grVkpZS2RqeWtrSgowaVQ5d0NTMERSVFh1MjY5VjI2NFZmLzNqdnJlZFppS1JrZ3dsTDl4TkF3eFhGZzB4L1hGdzAwNVVXVlJJa2RnCmNLV1RqcEJQMmRQd1ZaNFdXQys5YUdWZCtHeW4xbzBDTGVsZjRyRWpHb1hiQUFFZ0FxZUdVeHJjSWxialhmYmMKbXdJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t`
)

func TestValidateJwtSignHS512Hmac(t *testing.T) {
	type args struct {
		secret string
		token  string
	}
	testData := []struct {
		name           string
		args           args
		expectedResult string
		isExpectErr    bool
		expectedErr    error
	}{
		{
			name: "1. Should be valid",
			args: args{
				secret: "thisisasecretkeyverysecret",
				token:  "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJhbW91bnQiOjIwMDAwLCJjb3Vyc2VfY29kZSI6Im1lbWJ1MHVtenBmeDhqMyIsImNvdXJzZV9pZCI6NTU4MiwiY3JlYXRlZF9hdCI6MTY2MjAyNjQ5MSwiaW52b2ljZV9jb2RlIjoiaW52b2ljZS10cmFuc2FjdGlvbi10ZXN0MTExMDAyMiIsImludm9pY2VfdXJsIjoiaHR0cDovL3BsYXRmb3JtLmNvbS9pbnZvaWNlL0lOVjAwMDEiLCJwbGF0Zm9ybV9pZCI6Mywic2NoZWR1bGVfaWQiOjExLCJzdGF0dXMiOjAsInVzZXJfdWQiOjI1N30.twL4lZMBwkudun5k16JBFUkeC3REvbmiUWjR0paV6Al8SrSkLTw2ZoqUCxO96xjBsQOjmokk620PMGXgi2yDzQ",
			},
			expectedResult: `{"amount":20000,"course_code":"membu0umzpfx8j3","course_id":5582,"created_at":1662026491,"invoice_code":"invoice-transaction-test1110022","invoice_url":"http://platform.com/invoice/INV0001","platform_id":3,"schedule_id":11,"status":0,"user_ud":257}`,
		},
		{
			name: "2. Given wrong secret Then Should be invalid",
			args: args{
				secret: "wrongsecret",
				token:  "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJhbW91bnQiOjIwMDAwLCJjb3Vyc2VfY29kZSI6Im1lbWJ1MHVtenBmeDhqMyIsImNvdXJzZV9pZCI6NTU4MiwiY3JlYXRlZF9hdCI6MTY2MjAyNjQ5MSwiaW52b2ljZV9jb2RlIjoiaW52b2ljZS10cmFuc2FjdGlvbi10ZXN0MTExMDAyMiIsImludm9pY2VfdXJsIjoiaHR0cDovL3BsYXRmb3JtLmNvbS9pbnZvaWNlL0lOVjAwMDEiLCJwbGF0Zm9ybV9pZCI6Mywic2NoZWR1bGVfaWQiOjExLCJzdGF0dXMiOjAsInVzZXJfdWQiOjI1N30.twL4lZMBwkudun5k16JBFUkeC3REvbmiUWjR0paV6Al8SrSkLTw2ZoqUCxO96xjBsQOjmokk620PMGXgi2yDzQ",
			},
			isExpectErr: true,
			expectedErr: errors.New("signature is invalid"),
		},
		{
			name: "3. Given valid secret but token payload contained `exp` field with value expired Then Should be invalid",
			args: args{
				secret: "thisisasecretkeyverysecret",
				token:  "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJhbW91bnQiOjIwMDAwLCJjb3Vyc2VfY29kZSI6Im1lbWJ1MHVtenBmeDhqMyIsImNvdXJzZV9pZCI6NTU4MiwiY3JlYXRlZF9hdCI6MTY2MjAyNjQ5MSwiaW52b2ljZV9jb2RlIjoiaW52b2ljZS10cmFuc2FjdGlvbi10ZXN0MTExMDAyMiIsImludm9pY2VfdXJsIjoiaHR0cDovL3BsYXRmb3JtLmNvbS9pbnZvaWNlL0lOVjAwMDEiLCJwbGF0Zm9ybV9pZCI6Mywic2NoZWR1bGVfaWQiOjExLCJzdGF0dXMiOjAsInVzZXJfdWQiOjI1NywiZXhwIjoxNTE2MjM5MDIyfQ.-wV2w0OIJNVeRlCYJkjKK6_92DPLFDVZSc2_-OYVLRtV4_Kwt5zo0HmhazO53jtN1m_t5uJbicZv6wSleHMVSA",
			},
			isExpectErr: true,
			expectedErr: errors.New("Token is expired"),
		},
		{
			name: "4. Given valid secret and token payload contained `exp` field with value  not expired Then Should be valid",
			args: args{
				secret: "thisisasecretkeyverysecret",
				token:  "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJhbW91bnQiOjIwMDAwLCJjb3Vyc2VfY29kZSI6Im1lbWJ1MHVtenBmeDhqMyIsImNvdXJzZV9pZCI6NTU4MiwiY3JlYXRlZF9hdCI6MTY2MjAyNjQ5MSwiaW52b2ljZV9jb2RlIjoiaW52b2ljZS10cmFuc2FjdGlvbi10ZXN0MTExMDAyMiIsImludm9pY2VfdXJsIjoiaHR0cDovL3BsYXRmb3JtLmNvbS9pbnZvaWNlL0lOVjAwMDEiLCJwbGF0Zm9ybV9pZCI6Mywic2NoZWR1bGVfaWQiOjExLCJzdGF0dXMiOjAsInVzZXJfdWQiOjI1NywiZXhwIjoxMTUxNjIzOTAyMn0.rxHNMuXa2Hq7q6hMKgfheRdkil99AlE40PPNdFsUlsy98wX80jWCaBCqaBdAXg_iyWJV_SdtfCFtulmzzd_VKA",
			},
			expectedResult: `{"amount":20000,"course_code":"membu0umzpfx8j3","course_id":5582,"created_at":1662026491,"exp":11516239022,"invoice_code":"invoice-transaction-test1110022","invoice_url":"http://platform.com/invoice/INV0001","platform_id":3,"schedule_id":11,"status":0,"user_ud":257}`,
		},
		{
			name: "5. valid jwt",
			args: args{
				secret: "k4RTU_pr4KERJA",
				token:  "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJhbW91bnQiOjIwMDAwLCJjb3Vyc2VfY29kZSI6InRla25pbTQ3bW8zYXNsdSIsImNvdXJzZV9pZCI6MzA2LCJjcmVhdGVkX2F0IjoxNjYyNzA0ODA3LCJpbnZvaWNlX2NvZGUiOiJpbnZvaWNlLXRyYW5zYWN0aW9uLXRlc3QxMjM0NSIsInBsYXRmb3JtX2lkIjo1LCJzY2hlZHVsZV9pZCI6MjksInN0YXR1cyI6MCwidXJsX2ZpbGUiOiJodHRwOi8vcGxhdGZvcm0uY29tL2ludm9pY2UvSU5WMDAwMSIsInVzZXJfaWQiOjI1NX0.ZDzejHDRho46CyxC-LAU__g8c3lcDUOEjoWAZfVDE4et6U1V3ywmpHwtTkhaytJSlFPB-xTcPcyeto4QtAc4Gw",
			},
			expectedResult: `{"amount":20000,"course_code":"teknim47mo3aslu","course_id":306,"created_at":1662704807,"invoice_code":"invoice-transaction-test12345","platform_id":5,"schedule_id":29,"status":0,"url_file":"http://platform.com/invoice/INV0001","user_id":255}`,
		},
	}

	for _, tt := range testData {
		t.Run(tt.name, func(t *testing.T) {
			hmac := hash.NewJwtSignHS512Hmac([]byte(tt.args.secret))
			actual, err := hmac.Validate(context.TODO(), tt.args.token)

			if !tt.isExpectErr {
				if err != nil {
					t.Error(err)
					return
				}

				b, _ := json.Marshal(actual)
				actualStr := string(b)
				if tt.expectedResult != actualStr {
					t.Errorf("expected %s got %s", tt.expectedResult, actualStr)
					return
				}
			} else {
				if err == nil {
					t.Error("expect err got nil")
					return
				}

				if tt.expectedErr.Error() != err.Error() {
					t.Errorf("expected %s got %s", tt.expectedErr.Error(), err.Error())
					return
				}
			}
		})
	}
}

func TestValidateJwtSignRS256Hmac(t *testing.T) {
	type args struct {
		privateKey *rsa.PrivateKey
		publicKey  *rsa.PublicKey
		token      string
	}
	testData := []struct {
		name           string
		args           args
		expectedResult string
		isExpectErr    bool
		expectedErr    error
	}{
		{
			name: "1. Should be valid",
			args: args{
				privateKey: func() *rsa.PrivateKey {
					key, _ := hash.LoadPrivateKeyFromBase64Encoded(privateKeyBase64)
					return key
				}(),
				publicKey: func() *rsa.PublicKey {
					key, _ := hash.LoadPublicKeyFromBase64Encoded(publicKeyBase64)
					return key
				}(),
				token: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbiI6dHJ1ZSwiaWF0IjoxNTE2MjM5MDIyLCJuYW1lIjoiSm9obiBEb2UiLCJzdWIiOiIxMjM0NTY3ODkwIn0.LTP39t13r4FAMKnZd1kgVR4389oNwYtBy-NBwwkFkCmpr8bwG7rFWkZMDBMJPvgyp1aHCeIEiyJWxb0lPM0Kq6o8JAdfFcORT0pkZ0OCuIfvpK92s88XPLuLbf0F2vgzrjMMnKj3DZRVf08YGpPlRBamRuJfL8Y4Y47j-IhqyJ2M_mWqiSrHLoS7AJwjLh3y229ooBWYcthuDAAHXT312hzjgp7ShE10HK1rRTLFKNTM6V9jlWFGa8NUb2WJsC7Fx3haKauwtYGH3qmfyHQsSTWmpARaEPaG4XumvfRlhaAzwMFGZAr0vXPRdMqPkPRX0-dPnLEC0in0YxocXYRKsw",
			},
			expectedResult: `{"admin":true,"iat":1516239022,"name":"John Doe","sub":"1234567890"}`,
		},
	}

	for _, tt := range testData {
		t.Run(tt.name, func(t *testing.T) {
			hmac := hash.NewJwtSignRS256Hmac(tt.args.privateKey, tt.args.publicKey)
			actual, err := hmac.Validate(context.TODO(), tt.args.token)

			if !tt.isExpectErr {
				if err != nil {
					t.Error(err)
					return
				}

				b, _ := json.Marshal(actual)
				actualStr := string(b)
				if tt.expectedResult != actualStr {
					t.Errorf("expected %s got %s", tt.expectedResult, actualStr)
					return
				}
			} else {
				if err == nil {
					t.Error("expect err got nil")
					return
				}

				if tt.expectedErr.Error() != err.Error() {
					t.Errorf("expected %s got %s", tt.expectedErr.Error(), err.Error())
					return
				}
			}
		})
	}
}

func TestGenerateJwtSignRS256Hmac(t *testing.T) {
	type args struct {
		payload []byte
	}
	testData := []struct {
		name           string
		args           args
		expectedResult string
	}{
		{
			name: "1. Should be valid",
			args: args{
				payload: []byte(`{"admin":true,"iat":1516239022,"name":"John Doe","sub":"1234567890"}`),
			},
			expectedResult: `eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbiI6dHJ1ZSwiaWF0IjoxNTE2MjM5MDIyLCJuYW1lIjoiSm9obiBEb2UiLCJzdWIiOiIxMjM0NTY3ODkwIn0.LTP39t13r4FAMKnZd1kgVR4389oNwYtBy-NBwwkFkCmpr8bwG7rFWkZMDBMJPvgyp1aHCeIEiyJWxb0lPM0Kq6o8JAdfFcORT0pkZ0OCuIfvpK92s88XPLuLbf0F2vgzrjMMnKj3DZRVf08YGpPlRBamRuJfL8Y4Y47j-IhqyJ2M_mWqiSrHLoS7AJwjLh3y229ooBWYcthuDAAHXT312hzjgp7ShE10HK1rRTLFKNTM6V9jlWFGa8NUb2WJsC7Fx3haKauwtYGH3qmfyHQsSTWmpARaEPaG4XumvfRlhaAzwMFGZAr0vXPRdMqPkPRX0-dPnLEC0in0YxocXYRKsw`,
		},
	}

	for _, tt := range testData {
		t.Run(tt.name, func(t *testing.T) {
			privateKey, err := hash.LoadPrivateKeyFromBase64Encoded(privateKeyBase64)
			if err != nil {
				t.Error(err)
				return
			}

			publicKey, err := hash.LoadPublicKeyFromBase64Encoded(publicKeyBase64)
			if err != nil {
				t.Error(err)
				return
			}

			hmac := hash.NewJwtSignRS256Hmac(privateKey, publicKey)

			claims, err := hash.PayloadToJwtClaims(tt.args.payload)
			if err != nil {
				t.Error(err)
				return
			}

			actualStr, err := hmac.Sign(context.TODO(), claims)
			if err != nil {
				t.Error(err)
				return
			}

			if tt.expectedResult != actualStr {
				t.Errorf("expected %s got %s", tt.expectedResult, actualStr)
				return
			}
		})
	}
}

func TestGenerateJwtSignSHA256Hmac(t *testing.T) {
	type args struct {
		payload []byte
		secret  string
	}
	testData := []struct {
		name           string
		args           args
		expectedResult string
	}{
		{
			name: "1. Should be valid",
			args: args{
				payload: func() []byte {
					now := time.Unix(1516239022, 0)
					m := map[string]any{
						"appKey":   "appId",
						"mn":       "00000",
						"role":     0,
						"iat":      now.Unix(),
						"exp":      now.Add(time.Duration(48) * time.Hour).Unix(),
						"tokenExp": now.Add(time.Duration(48) * time.Hour).Unix(),
					}
					bytes, _ := json.Marshal(m)
					return bytes
				}(),
				secret: "appSecret",
			},
			expectedResult: `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhcHBLZXkiOiJhcHBJZCIsImV4cCI6MTUxNjQxMTgyMiwiaWF0IjoxNTE2MjM5MDIyLCJtbiI6IjAwMDAwIiwicm9sZSI6MCwidG9rZW5FeHAiOjE1MTY0MTE4MjJ9.QPK9GTS3qTd5FedeLZ94izH-XAysjjVMh8pWL8FLjuM`,
		},
	}

	for _, tt := range testData {
		t.Run(tt.name, func(t *testing.T) {
			hmac := hash.NewJwtSignSHA256Hmac(tt.args.secret)

			claims, err := hash.PayloadToJwtClaims(tt.args.payload)
			if err != nil {
				t.Error(err)
				return
			}

			actualStr, err := hmac.Sign(context.TODO(), claims)
			if err != nil {
				t.Error(err)
				return
			}

			if tt.expectedResult != actualStr {
				t.Errorf("expected %s got %s", tt.expectedResult, actualStr)
				return
			}
		})
	}
}
