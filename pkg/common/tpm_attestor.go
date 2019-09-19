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
	"errors"
	"fmt"
	"net/url"
	"path"

	"github.com/google/certificate-transparency-go/x509"

	"github.com/google/go-attestation/attest"
)

const (
	PluginName = "tpm"
)

type AttestationData struct {
	EK  []byte
	AIK *attest.AttestationParameters
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

	aik, err := tpm.LoadAIK(aikBytes)
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
	aik, err := tpm.MintAIK(nil)
	if err != nil {
		return nil, nil, err
	}
	defer aik.Close(tpm)
	params := aik.AttestationParameters()

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

	aikBytes, err := aik.Marshal()
	if err != nil {
		return nil, nil, err
	}

	return &AttestationData{
		EK:  ekCert.Raw,
		AIK: &params,
	}, aikBytes, nil
}

func AgentID(trustDomain string, pubHash string) string {
	u := url.URL{
		Scheme: "spiffe",
		Host:   trustDomain,
		Path:   path.Join("spire", "agent", "tpm", pubHash),
	}
	return u.String()
}
