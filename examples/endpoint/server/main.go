// Command server accepts NetherNet connections using the HTTP endpoint as the
// signaling method, and logs each one.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/helix-bedrock/nethernet"
	"github.com/helix-bedrock/nethernet/endpoint"
)

// debug indicates whether to show debug log in the output.
var debug = flag.Bool("debug", true, "Show debug log")

func main() {
	flag.Usage = func() {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s <address:port> [cert.pem] [key.pem]\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	if *debug {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})))
	}
	if err := run(); err != nil {
		slog.Error(err.Error())
	}
}

func run() error {
	var (
		address  = flag.Arg(0)
		certFile = flag.Arg(1)
		keyFile  = flag.Arg(2)
	)
	if address == "" {
		flag.Usage()
		return errors.New("missing address")
	}
	if (certFile != "") != (keyFile != "") {
		flag.Usage()
		return errors.New("either certificate or key file is missing")
	}

	server := endpoint.NewHandler()
	l, err := nethernet.ListenConfig{
		// The example client does not send an identity assertion, so this
		// endpoint server opts into anonymous/offline connections explicitly.
		AllowAnonymous:    true,
		DisableTrickleICE: true,
	}.Listen(server)
	if err != nil {
		return fmt.Errorf("listen on NetherNet: %w", err)
	}
	defer slog.Info("server closed")
	defer func() { _ = l.Close() }()

	tcp, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("listen on TCP: %w", err)
	}
	defer func() { _ = tcp.Close() }()

	enableTLS := certFile != "" && keyFile != ""
	srv := &http.Server{Addr: address, Handler: server, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		var err error
		if enableTLS {
			err = srv.ServeTLS(tcp, certFile, keyFile)
		} else {
			err = srv.Serve(tcp)
		}
		if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("accept on HTTP: " + err.Error())
		}
	}()
	defer func() { _ = srv.Close() }()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Kill, os.Interrupt)
	defer cancel()
	go func() {
		<-ctx.Done()
		if err := l.Close(); err != nil {
			slog.Error("close NetherNet listener: " + err.Error())
		}
	}()

	slog.Info("listening on NetherNet", "address", tcp.Addr(), "https", enableTLS)

	for {
		conn, err := l.Accept()
		if err != nil {
			return nil
		}
		nc, ok := conn.(*nethernet.Conn)
		if !ok {
			continue
		}
		slog.Info("connected",
			"remoteAddr", nc.RemoteAddr(),
			"localAddr", nc.LocalAddr(),
			"latency", nc.Latency(),
		)
	}
}
