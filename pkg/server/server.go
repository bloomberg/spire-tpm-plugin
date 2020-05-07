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

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/go-attestation/attest"
	"io/ioutil"
	"path/filepath"

	"github.com/bloomberg/spire-tpm-plugin/pkg/common"
	gx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/hashicorp/hcl"
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
	CaPath      string `hcl:"ca_path"`
}

func New() *TPMAttestorPlugin {
	return &TPMAttestorPlugin{}
}

func NewFromConfig(config *TPMAttestorPluginConfig) *TPMAttestorPlugin {
	return &TPMAttestorPlugin{config: config}
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
	if config.CaPath == "" {
		config.CaPath = "/opt/spire/.data/certs"
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

	leaf, _ := gx509.ParseCertificate(attestationData.EK)

	files, err := ioutil.ReadDir(p.config.CaPath)
	if err != nil {
		return fmt.Errorf("tpm: could not open ca directory: %v", err)
	}

	roots := gx509.NewCertPool()
	for _, file := range files {
		filename := filepath.Join(p.config.CaPath, file.Name())
		certData, err := ioutil.ReadFile(filename)
		if err != nil {
			return fmt.Errorf("tpm: could not read cert data for '%s': %v", filename, err)
		}

		ok := roots.AppendCertsFromPEM(certData)
		if ok {
			continue
		}

		root, err := gx509.ParseCertificate(certData)
		if err == nil {
			roots.AddCert(root)
			continue
		}

		return fmt.Errorf("tpm: could not parse cert data for '%s': %v", filename, err)
	}

	opts := gx509.VerifyOptions{
		Roots: roots,
	}
	_, err = leaf.Verify(opts)
	if err != nil {
		return fmt.Errorf("tpm: could not verify cert: %v", err)
	}

	ap := attest.ActivationParameters{
		TPMVersion: attest.TPMVersion20,
		EK:         leaf.PublicKey,
		AK:         *attestationData.AK,
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

	hashEncoded, err := common.GetPubHash(leaf)
	if err != nil {
		return fmt.Errorf("tpm: could not get public key hash: %v", err)
	}

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
