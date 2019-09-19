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

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"

	"github.com/google/certificate-transparency-go/x509"

	"github.com/bloomberg/spire-tpm-plugin/pkg/common"
	"github.com/google/go-attestation/attest"
	"github.com/google/go-attestation/verifier"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire/pkg/common/catalog"
	spc "github.com/spiffe/spire/proto/spire/common"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	"github.com/spiffe/spire/proto/spire/server/nodeattestor"
)

// TPMAttestorPlugin implements the nodeattestor Plugin interface
type TPMAttestorPlugin struct {
	config *TPMAttestorPluginConfig
}

type TPMAttestorPluginConfig struct {
	trustDomain string
	CaPath      []string `hcl:"ca_path"`
}

func New() *TPMAttestorPlugin {
	return &TPMAttestorPlugin{}
}

func (p *TPMAttestorPlugin) GetPluginInfo(context.Context, *spi.GetPluginInfoRequest) (*spi.GetPluginInfoResponse, error) {
	return &spi.GetPluginInfoResponse{}, nil
}

func (p *TPMAttestorPlugin) Configure(ctx context.Context, req *spi.ConfigureRequest) (*spi.ConfigureResponse, error) {
	config := &TPMAttestorPluginConfig{}
	if err := hcl.Decode(config, req.Configuration); err != nil {
		return nil, fmt.Errorf("failed to decode configuration file: %v", err)
	}

	if req.GlobalConfig == nil {
		return nil, errors.New("global configuration is required")
	}
	if req.GlobalConfig.TrustDomain == "" {
		return nil, errors.New("trust_domain is required")
	}
	if config.CaPath == nil {
		config.CaPath = []string{"/opt/spire/.data/certs"}
	}

	config.trustDomain = req.GlobalConfig.TrustDomain
	p.config = config

	return &spi.ConfigureResponse{}, nil
}

func (p *TPMAttestorPlugin) Attest(stream nodeattestor.NodeAttestor_AttestServer) error {
	if p.config == nil {
		return errors.New("plugin not configured")
	}

	req, err := stream.Recv()
	if err != nil {
		return err
	}

	if dataType := req.AttestationData.Type; dataType != common.PluginName {
		return fmt.Errorf("tpm: unexpected attestation data type %q", dataType)
	}

	attestationData := new(common.AttestationData)
	if err := json.Unmarshal(req.AttestationData.Data, attestationData); err != nil {
		return fmt.Errorf("tpm: failed to unmarshal attestation data: %v", err)
	}

	leaf, _ := x509.ParseCertificate(attestationData.EK)

	verif, err := verifier.NewEKVerifier(p.config.CaPath)
	if err != nil {
		return fmt.Errorf("tpm: could not read in certs: %v", err)
	}

	_, err = verif.VerifyEKCert(attestationData.EK)
	if err != nil {
		return fmt.Errorf("tpm: could not find valid CA for EK Cert: %v", err)
	}

	ap := attest.ActivationParameters{
		TPMVersion: attest.TPMVersion20,
		EK:         leaf.PublicKey,
		AIK:        *attestationData.AIK,
	}

	secret, ec, err := ap.Generate()
	if err != nil {
		return fmt.Errorf("tpm: could not generate credential challenge: %v", err)
	}

	challenge := &common.Challenge{
		EC: ec,
	}

	challengeBytes, err := json.Marshal(challenge)
	if err != nil {
		return fmt.Errorf("tpm: unable to marshal challenge: %v", err)
	}

	if err := stream.Send(&nodeattestor.AttestResponse{
		Challenge: challengeBytes,
	}); err != nil {
		return fmt.Errorf("tpm: unable to send challenge: %v", err)
	}

	challengeResp, err := stream.Recv()
	if err != nil {
		return fmt.Errorf("tpm: unable to receive challenge response: %v", err)
	}

	response := new(common.ChallengeResponse)
	if err := json.Unmarshal(challengeResp.Response, response); err != nil {
		return fmt.Errorf("tpm: unable to unmarshal challenge response: %v", err)
	}

	if !bytes.Equal(secret, response.Secret) {
		return fmt.Errorf("tpm: incorrect secret from attestor")
	}

	pubBytes, err := asn1.Marshal(leaf)
	pubHash := sha256.Sum256(pubBytes)
	hashEncoded := base64.StdEncoding.EncodeToString(pubHash[:])

	return stream.Send(&nodeattestor.AttestResponse{
		AgentId:   common.AgentID(p.config.trustDomain, hashEncoded),
		Selectors: buildSelectors(hashEncoded),
	})
}

func buildSelectors(pubHash string) []*spc.Selector {
	selectors := []*spc.Selector{}
	selectors = append(selectors, &spc.Selector{
		Type: "tpm", Value: "pub_hash:" + pubHash,
	})
	log.Println(selectors)
	return selectors
}

func containsKey(keys []string, key string) bool {
	for _, item := range keys {
		if item == key {
			return true
		}
	}
	return false
}

func main() {
	p := New()
	catalog.PluginMain(
		catalog.MakePlugin(common.PluginName, nodeattestor.PluginServer(p)),
	)
}
