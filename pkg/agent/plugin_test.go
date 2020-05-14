// this file has been adapted from the following spire node attestation test file:
// https://github.com/spiffe/spire/blob/62e723fafafe322cb68e4d494d96cb29695a7b37/pkg/agent/attestor/node/node_test.go

package agent

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/bloomberg/spire-tpm-plugin/pkg/common_test"
	"github.com/bloomberg/spire-tpm-plugin/pkg/server"
	"github.com/google/go-attestation/attest"
	sim "github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm-tools/tpm2tools"
	"github.com/sirupsen/logrus/hooks/test"
	attestor "github.com/spiffe/spire/pkg/agent/attestor/node"
	"github.com/spiffe/spire/pkg/agent/plugin/keymanager/memory"
	"github.com/spiffe/spire/pkg/common/catalog"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/proto/spire/agent/keymanager"
	agentnodeattestor "github.com/spiffe/spire/proto/spire/agent/nodeattestor"
	spi "github.com/spiffe/spire/proto/spire/common/plugin"
	servernodeattestor "github.com/spiffe/spire/proto/spire/server/nodeattestor"
	"github.com/spiffe/spire/test/fakes/fakeagentcatalog"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"io/ioutil"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var (
	hashExpected = "1b5bbe2e96054f7bc34ebe7ba9a4a9eac5611c6879285ceff6094fa556af485c"
	svidExpected = "spiffe://domain.test/spire/agent/tpm/" + hashExpected
	invalidHash  = "0000000000000000000000000000000000000000000000000000000000000000"
	testKey, _   = pemutil.ParseSigner([]byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgy8ps3oQaBaSUFpfd
XM13o+VSA0tcZteyTvbOdIQNVnKhRANCAAT4dPIORBjghpL5O4h+9kyzZZUAFV9F
qNV3lKIL59N7G2B4ojbhfSNneSIIpP448uPxUnaunaQZ+/m7+x9oobIp
-----END PRIVATE KEY-----
`))
	invalidCA, _ = pemutil.ParseCertificate([]byte(`-----BEGIN CERTIFICATE-----
MIIDjDCCAnSgAwIBAgIUWe6uPQG5Z+xnccBoXH9ui6dORgMwDQYJKoZIhvcNAQEL
BQAwYTEZMBcGA1UECgwQVFBNIE1hbnVmYWN0dXJlcjEhMB8GA1UECwwYVFBNIE1h
bnVmYWN0dXJlciBSb290IENBMSEwHwYDVQQDDBhUUE0gTWFudWZhY3R1cmVyIFJv
b3QgQ0EwHhcNMjAwNTA3MjA0NDQ3WhcNMzAwNTA3MjA0NDQ3WjBhMRkwFwYDVQQK
DBBUUE0gTWFudWZhY3R1cmVyMSEwHwYDVQQLDBhUUE0gTWFudWZhY3R1cmVyIFJv
b3QgQ0ExITAfBgNVBAMMGFRQTSBNYW51ZmFjdHVyZXIgUm9vdCBDQTCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBAK7xKAhZMXr4gd+KqdAks+fqJOUIS5td
D1wuc7lTFv9oXUg+3adkM0c2X4u8zmqu01DE1JuSrbDPsnuDNtm0gX5YPwod5jgT
+nnWFs5uipRk0+Wbakw3+rnFP5VuI7rO+ZDQEgN/F+xxvawOJOwPDhR0CO+ENqLM
WVSclBBqOESezecZDqq+LaDMxMe2+3dhRuomhcL1x9jygWoZx4xpRhLdMS2O+O9k
0AFR06CVoCxPPt7ErjXKJycXNucWpPxVK1Kxrq+PFuBZm7PtOBg/+uaFg5FzbBox
5ftpGp/oFZhEs5Z2JZ7DGYH865vKbud0/lP5QSCM7Vk8dbvZu1LoWs8CAwEAAaM8
MDowHQYDVR0OBBYEFGNVc7Gbhb2fwimbEj6cUfcKCrclMAwGA1UdEwQFMAMBAf8w
CwYDVR0PBAQDAgEGMA0GCSqGSIb3DQEBCwUAA4IBAQBmXwOZ+HUUaZ7xib3FsNg/
1M8W+R1sIl3X/cBorwh2XGsYSzHlrlFO62LyGzM6VCawBVC2HsEmYi/o7Bi8RTph
lRAN6NWwQ2FaYw6sKzlXFeEGPkamIPbOFwP02OP2mYNlMDoYvgFpZjuVbZTtQH8F
litUyWe49TAfNcIRz9DVW72U0KL7kaqP5T4elje65L6oRE3PUlbrNLynxbOvBlr0
yiDzSj4A2Iqxbhkp2MLGuPR6e5MkLLfeHIdos4uVGgzmcyVU6+wss0QPqNMrfANn
80Ur8/Y9v//wSdaU+AsDfrBNiXgmp7sJ4jsvt+P8xTLTTCNmN2Pewh9N8Q3RwMZV
-----END CERTIFICATE-----
`))
)

func TestAttestor(t *testing.T) {
	s, err := sim.GetWithFixedSeedInsecure(0)
	if err != nil {
		t.Fatal(err)
	}
	defer tpm2tools.CheckedClose(t, s)

	tpm, err := attest.OpenTPM(&attest.OpenConfig{
		TPMVersion:     attest.TPMVersion20,
		CommandChannel: &common_test.TPMCmdChannel{ReadWriteCloser: s},
	})
	if err != nil {
		t.Fatal(err)
	}

	tpmCACert, log, err := common_test.LoadEKCert(s)
	if err != nil {
		if log != nil {
			t.Error(log)
		}
		t.Fatal(err)
	}

	// create CA and server certificates
	caCert := createCACertificate(t)
	serverCert := createServerCertificate(t, caCert)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{serverCert.Raw},
				PrivateKey:  testKey,
			},
		},
	}

	testCases := []struct {
		name            string
		bootstrapBundle *x509.Certificate
		emptyCA         bool
		err             string
		hcl             string
		pemEncodeCAs    bool
		validateCAs     []*x509.Certificate
		validateHashes  []string
	}{
		{
			name:            "valid CA certificate PEM format",
			bootstrapBundle: caCert,
			validateCAs:     []*x509.Certificate{tpmCACert},
			pemEncodeCAs:    true,
		},
		{
			name:            "valid CA certificate DER format",
			bootstrapBundle: caCert,
			validateCAs:     []*x509.Certificate{tpmCACert},
		},
		{
			name:            "valid multiple CAs",
			bootstrapBundle: caCert,
			validateCAs:     []*x509.Certificate{tpmCACert, invalidCA},
		},
		{
			name:            "valid hash",
			bootstrapBundle: caCert,
			validateHashes:  []string{hashExpected},
		},
		{
			name:            "valid hash",
			bootstrapBundle: caCert,
			validateHashes:  []string{hashExpected},
		},
		{
			name:            "valid CA, invalid hash",
			bootstrapBundle: caCert,
			validateCAs:     []*x509.Certificate{tpmCACert},
			validateHashes:  []string{invalidHash},
		},
		{
			name:            "valid hash, invalid CA",
			bootstrapBundle: caCert,
			validateCAs:     []*x509.Certificate{invalidCA},
			validateHashes:  []string{hashExpected},
		},
		{
			name:            "error empty CA",
			bootstrapBundle: caCert,
			emptyCA:         true,
			err:             "could not verify cert",
		},
		{
			name:            "error invalid CA",
			bootstrapBundle: caCert,
			validateCAs:     []*x509.Certificate{invalidCA},
			err:             "could not verify cert",
		},
		{
			name:            "error invalid hash",
			bootstrapBundle: caCert,
			validateHashes:  []string{invalidHash},
			err:             "could not validate EK",
		},
		{
			name:            "error invalid hash, invalid CA",
			bootstrapBundle: caCert,
			validateCAs:     []*x509.Certificate{invalidCA},
			validateHashes:  []string{invalidHash},
			err:             "could not verify cert",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			require := require.New(t)

			// prepare the temp directory
			hcl, removeDir := prepareTestDir(t, testCase.validateCAs, testCase.pemEncodeCAs,
				testCase.emptyCA, testCase.validateHashes)
			defer removeDir()
			if testCase.hcl != "" {
				hcl = testCase.hcl
			}

			// load up the fake agent-side node attestor
			agentPlugin := New()
			agentPlugin.Configure(nil, &spi.ConfigureRequest{
				GlobalConfig: &spi.ConfigureRequest_GlobalConfig{
					TrustDomain: "domain.test",
				},
			})
			agentPlugin.tpm = tpm
			agentNA, agentNADone := prepareAgentNA(t, agentPlugin)
			defer agentNADone()

			// load up the fake server-side node attestor
			serverPlugin := server.New()
			serverPlugin.Configure(nil, &spi.ConfigureRequest{
				Configuration: hcl,
				GlobalConfig: &spi.ConfigureRequest_GlobalConfig{
					TrustDomain: "domain.test",
				},
			})
			serverNA, serverNADone := prepareServerNA(t, serverPlugin)
			defer serverNADone()

			// load up an in-memory key manager
			km, kmDone := prepareKeyManager(t)
			defer kmDone()

			// initialize the catalog
			catalog := fakeagentcatalog.New()
			catalog.SetNodeAttestor(fakeagentcatalog.NodeAttestor("test", agentNA))
			catalog.SetKeyManager(fakeagentcatalog.KeyManager(km))

			// kick off the gRPC server serving the node API
			serverAddr, serverDone := startNodeServer(t, tlsConfig, fakeNodeAPIConfig{
				CACert:   caCert,
				Attestor: serverNA,
			})
			defer serverDone()

			// create the attestor
			log, _ := test.NewNullLogger()
			att := attestor.New(&attestor.Config{
				Catalog: catalog,
				Metrics: telemetry.Blackhole{},
				Log:     log,
				TrustDomain: url.URL{
					Scheme: "spiffe",
					Host:   "domain.test",
				},
				TrustBundle:   makeTrustBundle(testCase.bootstrapBundle),
				ServerAddress: serverAddr,
			})

			// perform attestation
			result, err := att.Attest(context.Background())
			if testCase.err != "" {
				spiretest.RequireErrorContains(t, err, testCase.err)
				return
			}

			require.NoError(err)
			require.NotNil(result)
			require.Len(result.SVID, 1)
			require.Len(result.SVID[0].URIs, 1)
			require.Equal(result.SVID[0].URIs[0].String(), svidExpected)
			require.NotNil(result.Key)
			require.NotNil(result.Bundle)

			rootCAs := result.Bundle.RootCAs()
			require.Len(rootCAs, 1)
			require.Equal(rootCAs[0].Raw, caCert.Raw)
		})
	}
}

func prepareTestDir(t *testing.T, caCerts []*x509.Certificate,
	pemEncodeCA bool, emptyCA bool, hashes []string) (string, func()) {
	dir, err := ioutil.TempDir("", "spire-tpm-plugin-")
	require.NoError(t, err)

	ok := false
	defer func() {
		if !ok {
			os.RemoveAll(dir)
		}
	}()

	hcl := ""
	if emptyCA || caCerts != nil {
		caCertPath := filepath.Join(dir, "certs")
		hcl += fmt.Sprintf("ca_path = \"%s\"\n", caCertPath)
		require.NoError(t, os.Mkdir(caCertPath, 0755))
		if caCerts != nil {
			for i := range caCerts {
				caCert := caCerts[i]
				var b []byte
				if pemEncodeCA {
					b = pemutil.EncodeCertificate(caCert)
				} else {
					b = caCert.Raw
				}
				writeFile(t, filepath.Join(caCertPath, fmt.Sprintf("ca.%d.crt", i)), b, 0644)
			}
		}
	}

	if hashes != nil {
		hashPath := filepath.Join(dir, "hashes")
		hcl += fmt.Sprintf("hash_path = \"%s\"\n", hashPath)
		require.NoError(t, os.Mkdir(hashPath, 0755))
		for i := range hashes {
			writeFile(t, filepath.Join(hashPath, hashes[i]), []byte{}, 0644)
		}
	}

	ok = true
	return hcl, func() {
		os.RemoveAll(dir)
	}
}

func prepareAgentNA(t *testing.T, plugin *TPMAttestorPlugin) (agentnodeattestor.NodeAttestor, func()) {
	var agentNA agentnodeattestor.NodeAttestor
	agentNADone := spiretest.LoadPlugin(t, catalog.MakePlugin("test",
		agentnodeattestor.PluginServer(plugin),
	), &agentNA)
	return agentNA, agentNADone
}

func prepareServerNA(t *testing.T, plugin *server.TPMAttestorPlugin) (servernodeattestor.NodeAttestor, func()) {
	var serverNA servernodeattestor.NodeAttestor
	serverNADone := spiretest.LoadPlugin(t, catalog.MakePlugin("test",
		servernodeattestor.PluginServer(plugin),
	), &serverNA)
	return serverNA, serverNADone
}

func prepareKeyManager(t *testing.T) (keymanager.KeyManager, func()) {
	var km keymanager.KeyManager
	kmDone := spiretest.LoadPlugin(t, memory.BuiltIn(), &km)

	ok := false
	defer func() {
		if !ok {
			kmDone()
		}
	}()

	ok = true
	return km, kmDone
}

func writeFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	require.NoError(t, ioutil.WriteFile(path, data, mode))
}

func createCACertificate(t *testing.T) *x509.Certificate {
	tmpl := &x509.Certificate{
		BasicConstraintsValid: true,
		IsCA:                  true,
		URIs:                  []*url.URL{idutil.TrustDomainURI("domain.test")},
	}
	return createCertificate(t, tmpl, tmpl)
}

func createServerCertificate(t *testing.T, caCert *x509.Certificate) *x509.Certificate {
	tmpl := &x509.Certificate{
		URIs:     []*url.URL{idutil.ServerURI("domain.test")},
		DNSNames: []string{"localhost"},
	}
	return createCertificate(t, tmpl, caCert)
}

func createCertificate(t *testing.T, tmpl, parent *x509.Certificate) *x509.Certificate {
	now := time.Now()
	tmpl.SerialNumber = big.NewInt(0)
	tmpl.NotBefore = now
	if tmpl.NotAfter.IsZero() {
		tmpl.NotAfter = now.Add(time.Hour)
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, parent, testKey.Public(), testKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	return cert
}

func makeTrustBundle(bootstrapCert *x509.Certificate) []*x509.Certificate {
	var trustBundle []*x509.Certificate
	if bootstrapCert != nil {
		trustBundle = append(trustBundle, bootstrapCert)
	}
	return trustBundle
}
