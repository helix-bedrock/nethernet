package endpoint

import (
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// RequestTimeout is how long BDS gives a connection to complete its request. Give it to
	// [http.Server.ReadTimeout].
	RequestTimeout = 30 * time.Second
	// maxOpenConnections is how many connections BDS keeps open. It closes any more at once.
	maxOpenConnections = 64
	// maxRequestSize is how many bytes BDS takes from one connection. It drops any that sends more.
	maxRequestSize = 0x10000
)

// tlsHandshakeFailure is a fatal TLS handshake_failure alert. Clients try https first, and this
// tells them at once to go on to http.
var tlsHandshakeFailure = []byte{0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x28}

// NewListener wraps a plain TCP listener with what BDS's HTTP server does before any request is
// read: at most 64 open connections, at most 64 KiB from each, and a TLS ClientHello answered
// with a handshake_failure alert instead of being read as a bad request.
func NewListener(l net.Listener, log *slog.Logger) net.Listener {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &listener{Listener: l, log: log}
}

// listener implements [NewListener].
type listener struct {
	net.Listener
	log  *slog.Logger
	open atomic.Int32
}

// Accept implements [net.Listener].
func (l *listener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if l.open.Load() >= maxOpenConnections {
			l.log.Warn("rejecting new connection: too many open", "max", maxOpenConnections)
			_ = c.Close()
			continue
		}
		l.open.Add(1)
		return &conn{Conn: c, l: l}, nil
	}
}

// conn is a connection accepted by a listener.
type conn struct {
	net.Conn
	l *listener

	// first holds the first two bytes read, and read counts all bytes read. Only the server's
	// one reader at a time touches them.
	first [2]byte
	read  int
	once  sync.Once
}

// Read implements [net.Conn].
func (c *conn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n == 0 {
		return n, err
	}
	before := c.read
	if before < len(c.first) {
		copy(c.first[before:], b[:n])
	}
	c.read += n
	if before < len(c.first) && c.read >= len(c.first) && c.first == [2]byte{0x16, 0x03} {
		c.l.log.Debug("received TLS ClientHello: sending handshake_failure", "remote", c.RemoteAddr())
		_, _ = c.Conn.Write(tlsHandshakeFailure)
		_ = c.Close()
		return 0, net.ErrClosed
	}
	if c.read > maxRequestSize {
		c.l.log.Warn("dropping oversized request", "max", maxRequestSize, "remote", c.RemoteAddr())
		_ = c.Close()
		return 0, net.ErrClosed
	}
	return n, err
}

// Close implements [net.Conn].
func (c *conn) Close() error {
	c.once.Do(func() { c.l.open.Add(-1) })
	return c.Conn.Close()
}
