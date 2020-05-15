package main

import (
	"github.com/bloomberg/spire-tpm-plugin/pkg/common_test"
	"github.com/stretchr/testify/require"
	"testing"

	"github.com/google/go-attestation/attest"
	sim "github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm-tools/tpm2tools"
)

var (
	tpmPubHashExpected = "c1XbxrikL+sgdCw7hKFlmh2/y/QenHiIfLazBlsG/yQ="
)

func TestFakeTPM(t *testing.T) {
	s, err := sim.GetWithFixedSeedInsecure(0)
	require.NoError(t, err)
	defer tpm2tools.CheckedClose(t, s)

	tpm, err := attest.OpenTPM(&attest.OpenConfig{
		TPMVersion:     attest.TPMVersion20,
		CommandChannel: &common_test.TPMCmdChannel{ReadWriteCloser: s},
	})
	require.NoError(t, err)

	_, log, err := common_test.LoadEKCert(s)
	require.NoError(t, err, log)

	eks, err := tpm.EKs()
	require.NoError(t, err)
	require.Len(t, eks, 1)
	require.NotNil(t, eks[0].Public)

	info, err := tpm.Info()
	require.NoError(t, err)
	require.Equal(t, "Microsoft", info.Manufacturer.String())

	tpmPubHash, err := getTpmPubHash(tpm)
	require.NoError(t, err)
	require.Equal(t, tpmPubHashExpected, tpmPubHash)
}
