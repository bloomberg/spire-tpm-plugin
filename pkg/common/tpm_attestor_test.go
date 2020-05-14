package common

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestEncodeDecode(t *testing.T) {
	testCases := []struct {
		name     string
		hasCert  bool
		pemBytes []byte
		pubHash  string
	}{
		{
			name:    "certificate",
			hasCert: true,
			pemBytes: []byte(`-----BEGIN CERTIFICATE-----
MIIDATCCAekCAQEwDQYJKoZIhvcNAQELBQAwQzELMAkGA1UEBhMCVVMxCzAJBgNV
BAgMAk5DMQwwCgYDVQQHDANSVFAxDDAKBgNVBAoMA2FwcDELMAkGA1UEAwwCY2Ew
HhcNMjAwNTE0MjAxODEzWhcNMzAwNTEyMjAxODEzWjBKMQswCQYDVQQGEwJVUzEL
MAkGA1UECAwCTkMxDDAKBgNVBAcMA1JUUDEMMAoGA1UECgwDYXBwMRIwEAYDVQQD
DAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDYthYW
M3GRdRFfPDSr7b8/wHMegcZYxRvVjN//NlqZoUsEF4ZUNUBmJkj40y0TtdZ5/iNe
gce2b8kuSTDrP36149PdbJCztM3ChNu1XnwPe02+b8pts/d39lZIVASGVPSBXWyo
QFBA+b3ihm3rL3FfIGPc9iY/42MlTrNzYmQgbo0VkyXyWdc3DlDwzfBYpmPP18pC
+is7424aBfIKAXT0/+kX0C8e4fB4l6IG04xYAnP2XL+3C1b40x6NFUSZJfQrZQlW
Urm9aY/JYmCy19aX4cF0DboF07ieISrBJS1q3iiBtB0DCh71P/yIlij9E7tbxEL6
wFswPuOpbLUdEtojAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAJSJKKjo+KbrTdUs
oqkXoE96UL0GDIy7lPXLZOi/ayUKCj4Zthpt5HDpFfi0Uu8hwA1jN3jkCY28xE/2
WdPc5ya2wSqdXT5fM1gl3LfbBwAVOP/2yUKBRpFn6KVCjTA/QbqmZUQ55Z4L2jTb
q9pDohFRADNYagEs/Vhf+b3PnL/Nzx4+1BOp3KGtUdGSDX5O0BB8+slBMC4YmNB8
ASWkXRbZ0wBbY1TWmDEuSBVSRyfS3v/BmjMfAEjzZ/+BshnWQSBh2+W78kNRfcvS
09/II3+mWolAcYX7Z0O5gqTAl6vKuWKekuaF1cQR5kNy9nZqdSWywLaXFPryqrjS
fcSRqGI=
-----END CERTIFICATE-----`),
			pubHash: "e56864680c748f0318e1c7cbc24aeb2259f59c4bf11c2ed3b778e0329db209d0",
		},
		{
			name: "ec public key",
			pemBytes: []byte(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7mnx2ikpijr+7wbh/S67NKPeU7yE
6IDPKOOrt7W15Xs+O2aW2xMNKCCaC2QAMnDuXKogKnOr7Ri0firFrSlGIg==
-----END PUBLIC KEY-----`),
			pubHash: "d6c53c09ab792f1ea72d2ed52d7c9e587b1934489f7cde87d716e03f9fbda770",
		},
		{
			name: "rsa public key",
			pemBytes: []byte(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0SizQMxTx/8xN1IW2Nld
r5CcQVo9nk6p3fkkCIgzC1HsNX953LAKU5Xz1aSGxFQGtO7+hhMH++3qEtxgpntA
97pDfum4Rd1OUTGy+rHFrKNehBn/M9vfXeToDS5UuOr93tBR7KRJ7sW724GGAJAK
AGSfS3GLIpvcJ+gvzQoD76ox1d4bnLBXCAxAfuj3qYaeaNr4M5OKVOYNWk4dU+8U
ULm2HTqoNWSLkKqTaOn4VpQ2isFpDRpiBNq5N5mafaPWHeZixz2HAkajN94kAuk3
zopyzROwOXvNxRe6ttycHP34Hh7cRZAelyyJH5qrTQe/p+W1G5ssuWLd3Z1/qbbO
ZQIDAQAB
-----END PUBLIC KEY-----`),
			pubHash: "4d529cb0f819fd7d6fe8cd7d3fbc1a67178ae1e86c44cdc73e651646bc1517c9",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			require := require.New(t)

			pemBytes := testCase.pemBytes

			for i := 0; i < 3; i++ {
				ek, err := DecodeEK(pemBytes)
				require.NoError(err)
				if testCase.hasCert {
					require.NotNil(ek.Certificate)
				}

				pubHash, err := GetPubHash(ek)
				require.NoError(err)
				require.Equal(testCase.pubHash, pubHash)

				pemBytes, err = EncodeEK(ek)
				require.NoError(err)
			}
		})
	}
}
