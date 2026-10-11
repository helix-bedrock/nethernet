// Command client connects to a NetherNet server using the HTTP endpoint as the
// signaling method. It sends no client identity, so the server must allow
// anonymous (offline) connections.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"time"

	"github.com/helix-bedrock/nethernet"
	"github.com/helix-bedrock/nethernet/endpoint"
)

func main() {
	flag.Parse()
	if err := run(); err != nil {
		slog.Error(err.Error())
	}
}

func run() error {
	address := flag.Arg(0)
	if address == "" {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s <url>\n", os.Args[0])
		flag.PrintDefaults()
		return errors.New("missing url")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Kill, os.Interrupt)
	defer cancel()

	client := endpoint.NewClient()

	slog.Info("establishing connection over NetherNet... send an interrupt signal (Ctrl+C) to abort", "url", address)
	conn, err := nethernet.Dialer{DisableTrickleICE: true}.DialContext(ctx, address, client)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer func() { _ = conn.Close() }()

	slog.Info("connected",
		"remoteAddr", conn.RemoteAddr(),
		"localAddr", conn.LocalAddr(),
		"latency", conn.Latency(),
	)

	slog.Info("disconnecting in 15 seconds...")
	select {
	case <-ctx.Done():
	case <-conn.Context().Done():
	case <-time.After(time.Second * 15):
	}
	return nil
}
