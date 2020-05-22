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
	tpmPubHashExpected = "1b5bbe2e96054f7bc34ebe7ba9a4a9eac5611c6879285ceff6094fa556af485c"
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

	// test can read manufacturer
	info, err := tpm.Info()
	require.NoError(t, err)
	require.Equal(t, info.Manufacturer.String(), "Microsoft")

	// test without cert
	eks, err := tpm.EKs()
	require.NoError(t, err)
	require.Len(t, eks, 1)
	require.Nil(t, eks[0].Certificate)
	require.NotNil(t, eks[0].Public)

	tpmPubHash, err := getTpmPubHash(tpm)
	require.NoError(t, err)
	require.Equal(t, tpmPubHash, tpmPubHashExpected)

	// test with cert
	_, log, err := common_test.LoadEKCert(s)
	require.NoError(t, err, log)

	eks, err = tpm.EKs()
	require.NoError(t, err)
	require.Len(t, eks, 1)
	require.NotNil(t, eks[0].Certificate)
	require.NotNil(t, eks[0].Public)

	tpmPubHash, err = getTpmPubHash(tpm)
	require.NoError(t, err)
	require.Equal(t, tpmPubHash, tpmPubHashExpected)
}
