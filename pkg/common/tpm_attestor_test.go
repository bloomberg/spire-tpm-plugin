package common

import (
	"github.com/stretchr/testify/require"
	"testing"
)

// TestEncodeDecode tests multiple iterations of encoding/decoding
// certificates, EC public keys, and RSA public keys
// test data generated using OpenSSL 1.1.1f on Ubuntu 20.04
func TestEncodeDecode(t *testing.T) {
	testCases := []struct {
		name     string
		hasCert  bool
		pemBytes []byte
		pubHash  string
	}{
		{
			// openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
			//   -keyout key.pem -out cert.pem -subj "/CN=test.local" \
			// && openssl x509 -pubkey -noout -in cert.pem  > pub.pem \
			// && openssl rsa -inform PEM -in pub.pem -pubin -outform DER -out pub.crt \
			// && echo "RSA Cert" \
			// && cat cert.pem \
			// && echo "RSA Cert Public Key Hash" \
			// && sha256sum pub.crt | cut -d' ' -f1
			name:    "certificate",
			hasCert: true,
			pemBytes: []byte(`-----BEGIN CERTIFICATE-----
MIIDCzCCAfOgAwIBAgIUXCtKOpyneubNfS21IabW5vFf+zAwDQYJKoZIhvcNAQEL
BQAwFTETMBEGA1UEAwwKdGVzdC5sb2NhbDAeFw0yMDA1MjIxODUyNTlaFw0zMDA1
MjAxODUyNTlaMBUxEzARBgNVBAMMCnRlc3QubG9jYWwwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQCiqLKDAlhpwC/10Ud3BloWYTA1sJnTXdZJpTj/LmTc
mQpsFk+3OJETpk65fYEpmOw8aKL7AKOEwWx1K2T6OhoCdeKtsYNOlUzXfOOqyLGo
JH+PL9G/M+Oyarbqt0kvM/I+KG8TBEwBN3jnU3X5qPsifhAjWN/M0ISC/Bnhqkex
mf9wZOawekJu71P8zeHd71b2uXHBJqLlVezrKe9Hy2wV6MopFdzBiPTTBUAnDo4i
V1KL/rjDk5sR4AJqBUtcSWGfMH6PiwHhD4f6yLI6x+CBCc9JjCaSyP5vOs3bWYww
16R8jVZutNYINKJRUXo02N9iWh9MHLJksE3vCt2RsOtbAgMBAAGjUzBRMB0GA1Ud
DgQWBBRuIHGzo1hCDH+gsy9GHxiYCz37uDAfBgNVHSMEGDAWgBRuIHGzo1hCDH+g
sy9GHxiYCz37uDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCh
fbQOvfAAktclolIzASSKVv+9RebepmLas3zNxQugDDmzGHolgRdhPxEdqzq8Jne1
7RQEu8WXoC8thtFzuDkf6F8/Y5FlGJ9s9obSO/6XRYE5tiMpmaza096FWg6h6c3d
5CyX1cIB/JXjr+3WvJ6eU9/QZMxbmoYZkYJlNFFq73N1DcmCPykOjb/F+JGtTQ2E
vcszWkx/sCo1X929yCjQIxJteoevyc7/q68UQgjUIJXnn53DU4N9gGa+OcC7EBnx
8cxCo2SEjmjqAavUPTmvyAffAPjuIMB+Hhs6N8FFhCSvkMxvh+/HvgPPHUEZ7Z0t
sKhVipBdORVGNLHWEhFM
-----END CERTIFICATE-----`),
			pubHash: "6607c38c4be632bf69050ac042850d265962460937ed11aaf68a850409e3b512",
		},
		{
			// openssl ecparam -name prime256v1 -genkey -noout -out key.pem \
			// && openssl ec -in key.pem -pubout  > pub.pem \
			// && openssl ec -inform PEM -in pub.pem -pubin -outform DER -out pub.crt \
			// && echo "EC Public Key" \
			// && cat pub.pem \
			// && echo "EC Public Key Hash" \
			// && sha256sum pub.crt | cut -d' ' -f1
			name: "ec public key",
			pemBytes: []byte(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEJxAs7EUiM56NXQH2wcMn20UJk/n
EEj0/TcVn7PJ3S/Yij56M5LpPDcILIeb3wc/JU4oHnPPuqm3Epz/2kEh2w==
-----END PUBLIC KEY-----`),
			pubHash: "5f923ceaaa7fa4fff96cdad0e31ea315b702f871aa31eb7fe9b2bfa3934a38d4",
		},
		{
			// openssl genrsa -out key.pem 2048 \
			// && openssl rsa -in key.pem -pubout  > pub.pem \
			// && openssl rsa -inform PEM -in pub.pem -pubin -outform DER -out pub.crt \
			// && echo "RSA Public Key" \
			// && cat pub.pem \
			// && echo "RSA Public Key Hash" \
			// && sha256sum pub.crt | cut -d' ' -f1
			name: "rsa public key",
			pemBytes: []byte(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuAINS/5JILujVnQHq0xx
hl3X7fepS+D6CtTa2ONl+UkJVpQTFUQXC6HXwMgCBmJHpcR125Rhroz77bgJy+Rx
QUmLsu0uOvh8KxaWWt7XKO7CqkWWJyHFydMKrfc84aTabI/QLHIqyRxCqYV67OPT
sLZWz8E3YGiZdim0DsNg43pR5FON1tDTFfWxen7XcY64W4iR/4T3xNe+i7SvkJGL
plkG4ujs7qzCtmB6JM+SnlZ0ONMTu7pqX6vYuV38UpQeb3KusDLwagdf5w7/I1Jf
1mFUYPmMRKBZazmlnREWXs4yWFpKroqaUoz9w6+juunASqFM0XKZwE5EjbupsJfc
VQIDAQAB
-----END PUBLIC KEY-----`),
			pubHash: "64e3462d87b1c6dfe127e43568f8298b8053c2488f4e46780f4c9778760f5506",
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
