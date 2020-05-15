package common_test

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

func LoadEKCert(rw io.ReadWriter) (*x509.Certificate, *bytes.Buffer, error) {
	_, filename, _, _ := runtime.Caller(0)
	dir, err := filepath.Abs(filepath.Dir(filename))
	if err != nil {
		return nil, nil, err
	}
	generatorPath := ""
	for dir != "/" {
		tryPath := filepath.Join(dir, "ci", "tpm2_ek_cert_generator")
		if _, err := os.Stat(tryPath); !os.IsNotExist(err) {
			generatorPath = tryPath
		}
		dir = filepath.Dir(dir)
	}
	if generatorPath == "" {
		return nil, nil, errors.New("could not locate ./ci/tpm2_ek_cert_generator")
	}

	closeCh2321 := make(chan struct{})
	readyCh2321 := make(chan struct{})
	go tcpServer(rw, 2321, readyCh2321, closeCh2321, commandHandler)
	defer func() { closeCh2321 <- struct{}{} }()
	closeCh2322 := make(chan struct{})
	readyCh2322 := make(chan struct{})
	go tcpServer(rw, 2322, readyCh2322, closeCh2322, platformHandler)
	defer func() { closeCh2322 <- struct{}{} }()
	<-readyCh2321
	<-readyCh2322

	log := &bytes.Buffer{}
	cmd := exec.Command("sh", "-c", "make clean && exec make")
	cmd.Dir = generatorPath
	cmd.Env = append(os.Environ(), "TPM2TOOLS_TCTI=mssim")
	cmd.Stdout = log
	cmd.Stderr = log
	if err := cmd.Run(); err != nil {
		return nil, log, err
	}

	f, err := os.Open(filepath.Join(generatorPath, "__working_dir", "tpm2_CA.crt"))
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	pemBytes, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, nil, err
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, nil, errors.New("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, err
	}

	return cert, nil, nil
}
