// https://tools.ietf.org/html/rfc1928

// +----+----------+----------+
// |VER | NMETHODS | METHODS  |
// +----+----------+----------+
// | 1  |    1     | 1 to 255 |
// +----+----------+----------+
// VER    protocol version: X'05'

// The SOCKS request is formed as follows:
//
// +----+-----+-------+------+----------+----------+
// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
// +----+-----+-------+------+----------+----------+
// | 1  |  1  | X'00' |  1   | Variable |    2     |
// +----+-----+-------+------+----------+----------+
// VER protocol version
//     X'05'
// CMD
//     CONNECT X'01'
//     BIND X'02'
//     UDP ASSOCIATE X'03'
// ATYP   address type of following address
//     IP V4 address: X'01'
//     DOMAINNAME: X'03'
//     IP V6 address: X'04'

// +----+-----+-------+------+----------+----------+
// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
// +----+-----+-------+------+----------+----------+
// | 1  |  1  | X'00' |  1   | Variable |    2     |
// +----+-----+-------+------+----------+----------+
//    VER    protocol version: X'05'
//    REP    Reply field:
//    X'00' succeeded
//    X'01' general SOCKS server failure
//    X'02' connection not allowed by ruleset
//    X'03' Network unreachable
//    X'04' Host unreachable
//    X'05' Connection refused
//    X'06' TTL expired
//    X'07' Command not supported
//    X'08' Address type not supported
//    X'09' to X'FF' unassigned
//    RSV    RESERVED
//    ATYP   address type of following address
//      IP V4 address: X'01'
//      DOMAINNAME: X'03'
//      IP V6 address: X'04'
//    BND.ADDR       server bound address
//    BND.PORT       server bound port in network octet order

package socks5

import (
	"context"
	"fmt"
	log "github.com/sirupsen/logrus"
	"net"
	"strings"
)

const (
	TCP = "tcp"
)

const (
	V5 = uint8(0x05)
)

const (
	RepSucceeded = uint8(0x00)
)

const (
	CmdTypeConnect = uint8(0x01)
)

const (
	ATYPIPv4       = uint8(0x01)
	ATYPDomainName = uint8(0x03)
	ATYPIPv6       = uint8(0x04) // not support
)

const (
	RSV = uint8(0x00)
)

type AddrSpec struct {
	IP   net.IP
	FQDN string
	Port int
}

func (p *AddrSpec) Address() string {
	if p.FQDN != "" {
		return fmt.Sprintf("%s:%d", p.FQDN, p.Port)
	}

	return fmt.Sprintf("%s:%d", p.IP.String(), p.Port)
}

type Config struct {
	Address     AddrSpec
	AuthMethods []Authenticator
	LogLevel    log.Level
}

type Server struct {
	ctx         context.Context
	config      *Config
	listener    net.Listener
	cancel      context.CancelFunc
	authMethods map[uint8]Authenticator
	logger      *log.Logger
}

func NewServer(ctx context.Context, cancel context.CancelFunc, config *Config, logger *log.Logger) *Server {
	server := &Server{
		ctx:         ctx,
		cancel:      cancel,
		config:      config,
		authMethods: map[uint8]Authenticator{},
		logger:      logger,
	}

	for _, method := range config.AuthMethods {
		server.authMethods[method.Code()] = method
	}

	return server
}

func (s *Server) Stop() {
	s.cancel()

	if s.listener != nil {
		_ = s.listener.Close()
	}
}

func (s *Server) Run() (err error) {
	s.listener, err = net.Listen(TCP, s.config.Address.Address())
	if err != nil {
		return err
	}

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
			conn, err := s.listener.Accept()
			if err != nil {
				if strings.Contains(err.Error(), "use of closed network connection") {
					break
				}

				return err
			}

			go func() {
				err := s.handleSocks5Connection(conn)
				if err != nil {
					log.Error(err)
				}
			}()
		}
	}
}

func (s *Server) handleSocks5Connection(conn net.Conn) (err error) {
	stream := &Stream{
		ctx:               s.ctx,
		local:             conn,
		serverAuthMethods: s.authMethods,
		clientAuthMethods: []uint8{},
	}

	err = stream.version()
	if err != nil {
		return err
	}

	err = stream.methods()
	if err != nil {
		return err
	}

	err = stream.authenticate()
	if err != nil {
		return err
	}

	err = stream.version()
	if err != nil {
		return err
	}
	err = stream.cmd()
	if err != nil {
		return err
	}
	err = stream.rsv()
	if err != nil {
		return err
	}
	err = stream.atyp()
	if err != nil {
		return err
	}
	err = stream.dstPort()
	if err != nil {
		return err
	}

	err = stream.connect()
	if err != nil {
		return err
	}

	err = stream.reply(RepSucceeded)
	if err != nil {
		return err
	}

	stream.forward()

	return nil
}
