package socks5

import (
	"context"
	"encoding/binary"
	"fmt"
	log "github.com/sirupsen/logrus"
	"io"
	"net"
)

type Stream struct {
	ctx context.Context

	l    *log.Logger
	ip   net.IP
	fqdn string
	port int

	serverAuthMethods map[uint8]Authenticator
	clientAuthMethods []uint8

	local  net.Conn
	remote net.Conn
}

func (s *Stream) version() error {
	data := make([]byte, 1)
	_, err := io.LimitReader(s.local, 1).Read(data)
	if err != nil {
		return err
	}

	if data[0] != V5 {
		return fmt.Errorf("invalid version %v, expected is %v", data[0], V5)
	}

	return nil
}

func (s *Stream) cmd() error {
	data := make([]byte, 1)
	_, err := io.LimitReader(s.local, 1).Read(data)
	if err != nil {
		return err
	}

	if data[0] != CmdTypeConnect {
		return fmt.Errorf("invalid cmd %v, expected is %v", data, CmdTypeConnect)
	}

	return nil
}

func (s *Stream) rsv() error {
	data := make([]byte, 1)
	_, err := io.LimitReader(s.local, 1).Read(data)
	if err != nil {
		return err
	}

	if data[0] != RSV {
		return fmt.Errorf("invalid rsv %v, expected is %v", data, RSV)
	}

	return nil
}

func (s *Stream) methods() error {
	data := make([]byte, 1)
	_, err := io.LimitReader(s.local, 1).Read(data)
	if err != nil {
		return err
	}

	nMethods := int(data[0])
	s.clientAuthMethods = make([]byte, nMethods)

	_, err = io.ReadAtLeast(s.local, s.clientAuthMethods, nMethods)
	if err != nil {
		return fmt.Errorf("handle methods failed: %v", err)
	}

	return nil
}

func (s *Stream) authenticate() error {
	for _, method := range s.clientAuthMethods {
		authenticator, ok := s.serverAuthMethods[method]
		if ok {
			err := authenticator.Authenticate(s.local)
			if err != nil {
				return fmt.Errorf("handle authenticate %v failed: %v", s.local, err)
			}

			return nil
		}
	}

	_, err := s.local.Write([]byte{V5, AuthMethodNoAcceptable})

	return fmt.Errorf("no supported authentication: %v", err)
}

func (s *Stream) handleIPv4() error {
	ipv4 := []byte{0, 0, 0, 0}

	_, err := io.LimitReader(s.local, 4).Read(ipv4)
	if err != nil {
		return err
	}
	s.ip = net.IPv4(ipv4[0], ipv4[1], ipv4[2], ipv4[3])

	return nil
}

func (s *Stream) handleFQDN() error {
	length := []byte{0}
	_, err := io.LimitReader(s.local, 1).Read(length)
	if err != nil {
		return err
	}

	var (
		n          int
		addrLength = int64(length[0])
		buf        = make([]byte, addrLength)
	)

	n, err = io.LimitReader(s.local, addrLength).Read(buf)
	if int64(n) != addrLength {
		return fmt.Errorf("invalid fqdn addr: %v", err)
	}
	s.fqdn = string(buf)

	return nil
}

func (s *Stream) atyp() error {
	var addrType = make([]byte, 1)
	_, err := io.LimitReader(s.local, 1).Read(addrType)
	if err != nil {
		return err
	}

	switch addrType[0] {
	case ATYPIPv4:
		return s.handleIPv4()

	case ATYPDomainName:
		return s.handleFQDN()

	case ATYPIPv6:
		return fmt.Errorf("unsupport address type ipv6: %v", s.local)

	default:
		return fmt.Errorf("invalid address type: %v", s.local)
	}
}

func (s *Stream) dstPort() error {
	var (
		data = make([]byte, 2)
		n    = 0
		err  error
	)

	n, err = io.LimitReader(s.local, 2).Read(data)
	if n != 2 || err != nil {
		return fmt.Errorf("invalid port: %v", err)
	}
	s.port = int(binary.BigEndian.Uint16(data))

	return nil
}

func (s *Stream) connect() (err error) {
	var dstAddr string
	if s.fqdn != "" {
		dstAddr = fmt.Sprintf("%s:%d", s.fqdn, s.port)
	} else {
		dstAddr = fmt.Sprintf("%s:%d", s.ip.To4().String(), s.port)
	}

	s.remote, err = net.Dial(TCP, dstAddr)
	if err != nil {
		return fmt.Errorf("dial to dst %v failed: %v", dstAddr, err)
	}

	return nil
}

func (s *Stream) reply(resp uint8) (err error) {
	var addr *AddrSpec

	local, ok := s.remote.LocalAddr().(*net.TCPAddr)
	if ok {
		addr = &AddrSpec{
			IP:   local.IP,
			Port: local.Port,
		}
	}

	var (
		addrType uint8
		addrBody []byte
		addrPort uint16
	)

	switch {
	case addr == nil:
		addrType = ATYPIPv4
		addrBody = net.IPv4(0, 0, 0, 0)
		addrPort = uint16(0)
	case addr.FQDN != "":
		addrType = ATYPDomainName
		addrBody = append([]byte{byte(len(addr.FQDN))}, addr.FQDN...)
		addrPort = uint16(addr.Port)

	case addr.IP.To4() != nil:
		addrType = ATYPIPv4
		addrBody = addr.IP.To4()
		addrPort = uint16(addr.Port)

	case addr.IP.To16() != nil:
		return fmt.Errorf("unsupport ipv6 yet: %v", addr)

	default:
		return fmt.Errorf("format address failed: %v", addr)
	}

	msg := make([]byte, len(addrBody)+6)
	msg[0] = V5
	msg[1] = resp
	msg[2] = RSV
	msg[3] = addrType

	copy(msg[4:], addrBody)

	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, addrPort)

	copy(msg[4+len(addrBody):], port)

	_, err = s.local.Write(msg)
	return err
}

func (s *Stream) forward() {
	go func() {
		<-s.ctx.Done()
		_ = s.local.Close()
		_ = s.remote.Close()
	}()

	go func() {
		defer s.local.Close()
		io.Copy(s.local, s.remote)
	}()

	go func() {
		defer s.remote.Close()
		io.Copy(s.remote, s.local)
	}()
}
