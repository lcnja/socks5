package socks5

import (
	"net"
)

const (
	AuthMethodNoAuth       = uint8(0x00)
	AuthMethodNoAcceptable = uint8(0xff)
)

type Authenticator interface {
	Authenticate(local net.Conn) error
	Code() uint8
}

type NoAuthAuthenticator struct{}

func (a NoAuthAuthenticator) Code() uint8 {
	return AuthMethodNoAuth
}

func (a NoAuthAuthenticator) Authenticate(local net.Conn) error {
	_, err := local.Write([]byte{V5, AuthMethodNoAuth})
	return err
}
