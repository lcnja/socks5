package main

import (
	"context"
	"github.com/lcnja/socks5"
	log "github.com/sirupsen/logrus"
	"net"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	config := &socks5.Config{
		Address: socks5.AddrSpec{
			IP:   net.IPv4(127, 0, 0, 1),
			Port: 1080,
		},
		AuthMethods: []socks5.Authenticator{socks5.NoAuthAuthenticator{}},
		LogLevel:    log.DebugLevel,
	}

	logger := log.StandardLogger()
	logger.SetLevel(config.LogLevel)

	ctx, cancel := context.WithCancel(context.Background())
	srv := socks5.NewServer(
		ctx,
		cancel,
		config,
		logger,
	)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)

	go func() {
		select {
		case <-sig:
			srv.Stop()
		}
	}()

	err := srv.Run()
	if err != nil {
		panic(err)
	}
}
