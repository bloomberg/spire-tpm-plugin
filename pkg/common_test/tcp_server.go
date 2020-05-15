package common_test

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
)

// this code is derived from example at
// https://github.com/microsoft/TSS.MSR/blob/master/Tpm2Tester/TpmProxy/NetProxy.cs

type tcpTpmCommands uint32

const (
	signalPowerOn     tcpTpmCommands = 1
	signalPowerOff    tcpTpmCommands = 2
	signalPPOn        tcpTpmCommands = 3
	signalPPOff       tcpTpmCommands = 4
	signalHashStart   tcpTpmCommands = 5
	signalHashData    tcpTpmCommands = 6
	signalHashEnd     tcpTpmCommands = 7
	sendCommand       tcpTpmCommands = 8
	signalCancelOn    tcpTpmCommands = 9
	signalCancelOff   tcpTpmCommands = 10
	signalNvOn        tcpTpmCommands = 11
	signalNvOff       tcpTpmCommands = 12
	signalKeyCacheOn  tcpTpmCommands = 13
	signalKeyCacheOff tcpTpmCommands = 14
	remoteHandshake   tcpTpmCommands = 15
	sessionEnd        tcpTpmCommands = 20
	stop              tcpTpmCommands = 21
	actGetSignaled    tcpTpmCommands = 26
	testFailureMode   tcpTpmCommands = 30
)

var zeroInt = []byte{0, 0, 0, 0}
var oneInt = []byte{1, 1, 1, 1}

func tcpServer(rw io.ReadWriter, port int, readyCh chan<- struct{}, closeCh <-chan struct{},
	handler func(io.ReadWriter, net.Conn, chan<- error, chan<- struct{})) error {
	addr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("localhost:%d", port))
	if err != nil {
		return err
	}
	listener, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return err
	}
	defer listener.Close()
	acceptCh := make(chan net.Conn)
	go tcpAcceptor(listener, acceptCh, port)
	readyCh <- struct{}{}
Loop:
	for true {
		select {
		case conn := <-acceptCh:
			errorCh := make(chan error)
			doneCh := make(chan struct{})
			go handler(rw, conn, errorCh, doneCh)
			select {
			case err = <-errorCh:
				fmt.Fprintln(os.Stderr, "connection error: ", err)
				break
			case <-doneCh:
				break
			case <-closeCh:
				break Loop
			}
		case <-closeCh:
			break Loop
		}
	}
	return nil
}

func tcpAcceptor(listener net.Listener, acceptCh chan<- net.Conn, port int) {
	for {
		conn, _ := listener.Accept()
		acceptCh <- conn
	}
}

func platformHandler(rw io.ReadWriter, conn net.Conn, errorCh chan<- error, doneCh chan<- struct{}) {
	defer conn.Close()
	for {
		_, err := readInt(conn)
		if err != nil {
			if err == io.EOF {
				doneCh <- struct{}{}
				return
			}
			errorCh <- err
			return
		}
		err = write(zeroInt, conn)
		if err != nil {
			errorCh <- err
			return
		}
	}
}

func commandHandler(rw io.ReadWriter, conn net.Conn, errorCh chan<- error, doneCh chan<- struct{}) {
	defer conn.Close()
	for {
		command, err := readInt(conn)
		if err != nil {
			if err == io.EOF {
				doneCh <- struct{}{}
				return
			}
			errorCh <- err
			return
		}
		switch tcpTpmCommands(command) {
		case remoteHandshake:
			version, err := readInt(conn)
			if err != nil {
				errorCh <- err
				return
			}
			if version == 0 {
				errorCh <- errors.New("incompatible client (version 0, expected version 1 or higher)")
				return
			}
			break
		case signalHashStart:
		case signalHashEnd:
			err = write(oneInt, conn)
			if err != nil {
				errorCh <- err
				return
			}
			break
		case signalHashData:
			_, err = readVarArray(conn)
			if err != nil {
				errorCh <- err
				return
			}
			err = write(oneInt, conn)
			if err != nil {
				errorCh <- err
				return
			}
			break
		case sendCommand:
			_, err := read(1, conn)
			if err != nil {
				errorCh <- err
				return
			}
			cmd, err := readVarArray(conn)
			if err != nil {
				errorCh <- err
				return
			}
			err = write(cmd, rw)
			if err != nil {
				errorCh <- err
				return
			}
			res, err := readEof(rw)
			if err != nil {
				errorCh <- err
				return
			}
			err = writeVarArray(res, conn)
			if err != nil {
				errorCh <- err
				return
			}
			err = write(zeroInt, conn)
			if err != nil {
				errorCh <- err
				return
			}
			break
		case sessionEnd:
		case stop:
			// Send back ACK and exit the communication loop
			err = write(zeroInt, conn)
			if err != nil {
				errorCh <- err
				return
			}
			doneCh <- struct{}{}
			return
		default:
			errorCh <- fmt.Errorf("unhandled command code %d", command)
			return
		}
	}
}

func write(x []byte, s io.ReadWriter) error {
	_, err := s.Write(x)
	return err
}

func read(numBytes uint32, s io.ReadWriter) ([]byte, error) {
	var numRead uint32
	res := make([]byte, numBytes)

	for numRead < numBytes {
		numReadLoop, err := s.Read(res[numRead:numBytes])
		if err != nil {
			return nil, err
		}
		numRead += uint32(numReadLoop)
	}

	return res, nil
}

func readEof(s io.ReadWriter) ([]byte, error) {
	res := make([]byte, 0)
	eof := false
	for {
		buf := make([]byte, 1024)
		numRead, err := s.Read(buf)
		if err != nil {
			if err == io.EOF {
				eof = true
			} else {
				return nil, err
			}
		}
		res = append(res, buf[:numRead]...)
		if eof {
			break
		}
	}
	return res, nil
}

func writeInt(x uint32, s io.ReadWriter) error {
	bytes := make([]byte, 4)
	binary.BigEndian.PutUint32(bytes, x)
	return write(bytes, s)
}

func readInt(s io.ReadWriter) (uint32, error) {
	bytes, err := read(4, s)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(bytes), nil
}

func readVarArray(s io.ReadWriter) ([]byte, error) {
	bufLen, err := readInt(s)
	if err != nil {
		return nil, err
	}
	return read(bufLen, s)
}

func writeVarArray(x []byte, s io.ReadWriter) error {
	err := writeInt(uint32(len(x)), s)
	if err != nil {
		return err
	}
	return write(x, s)
}
