/*
 ** Copyright 2019 Bloomberg Finance L.P.
 **
 ** Licensed under the Apache License, Version 2.0 (the "License");
 ** you may not use this file except in compliance with the License.
 ** You may obtain a copy of the License at
 **
 **     http://www.apache.org/licenses/LICENSE-2.0
 **
 ** Unless required by applicable law or agreed to in writing, software
 ** distributed under the License is distributed on an "AS IS" BASIS,
 ** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 ** See the License for the specific language governing permissions and
 ** limitations under the License.
 */

package common

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/go-attestation/attest"
)

const (
	PluginName = "tpm"
)

type AttestationData struct {
	EK []byte
	AK *attest.AttestationParameters
}

type Challenge struct {
	EC *attest.EncryptedCredential
}

type KeyData struct {
	Keys []string `json:"keys"`
}

type ChallengeResponse struct {
	Secret []byte
}

func CalculateResponse(ec *attest.EncryptedCredential, aikBytes []byte) (*ChallengeResponse, error) {
	tpm, err := attest.OpenTPM(&attest.OpenConfig{
		TPMVersion: attest.TPMVersion20,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to tpm: %v", err)
	}
	defer tpm.Close()

	aik, err := tpm.LoadAK(aikBytes)
	if err != nil {
		return nil, err
	}
	defer aik.Close(tpm)

	secret, err := aik.ActivateCredential(tpm, *ec)
	if err != nil {
		return nil, fmt.Errorf("failed to activate credential: %v", err)
	}
	return &ChallengeResponse{
		Secret: secret,
	}, nil
}

func GenerateAttestationData() (*AttestationData, []byte, error) {
	tpm, err := attest.OpenTPM(&attest.OpenConfig{
		TPMVersion: attest.TPMVersion20,
	})
	if err != nil {
		return nil, nil, err
	}
	defer tpm.Close()
	eks, err := tpm.EKs()
	if err != nil {
		return nil, nil, err
	}
	ak, err := tpm.NewAK(nil)
	if err != nil {
		return nil, nil, err
	}
	defer ak.Close(tpm)
	params := ak.AttestationParameters()

	var ekCert *x509.Certificate
	for _, ek := range eks {
		if ek.Certificate != nil && ek.Certificate.PublicKeyAlgorithm == x509.RSA {
			ekCert = ek.Certificate
			break
		}
	}

	if ekCert == nil {
		return nil, nil, errors.New("no EK available")
	}

	aikBytes, err := ak.Marshal()
	if err != nil {
		return nil, nil, err
	}

	return &AttestationData{
		EK: ekCert.Raw,
		AK: &params,
	}, aikBytes, nil
}

func AgentID(trustDomain string, pubHash string) string {
	u := url.URL{
		Scheme: "spiffe",
		Host:   trustDomain,
		Path:   strings.Join([]string{"spire", "agent", "tpm", pubHash}, "/"),
	}
	return u.String()
}

func GetPubHash(cert *x509.Certificate) (string, error) {
	if cert.PublicKeyAlgorithm != x509.RSA {
		return "", fmt.Errorf("expected rsa public key but got %s", cert.PublicKeyAlgorithm.String())
	}
	pubKey := cert.PublicKey.(*rsa.PublicKey)
	pubBytes := x509.MarshalPKCS1PublicKey(pubKey)
	pubHash := sha256.Sum256(pubBytes)
	hashEncoded := base64.StdEncoding.EncodeToString(pubHash[:])
	return hashEncoded, nil
}
