package common_test

import (
	"errors"
	"io"
)

type TPMCmdChannel struct {
	io.ReadWriteCloser
}

func (cc *TPMCmdChannel) MeasurementLog() ([]byte, error) {
	return nil, errors.New("unsupported")
}
