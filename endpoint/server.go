package endpoint

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// requestTimeout is how long BDS gives a connection to complete its request.
	requestTimeout = 30 * time.Second
	// maxOpenConnections is how many connections BDS keeps open. It closes any more at once.
	maxOpenConnections = 64
	// maxRequestSize is how many bytes BDS takes from one connection. It drops any that sends more.
	maxRequestSize = 0x10000
)

// tlsHandshakeFailure is a fatal TLS handshake_failure alert. Clients try https first, and this
// tells them at once to go on to http.
var tlsHandshakeFailure = []byte{0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x28}

// ServeListener answers requests from a plain TCP listener the way BDS's own HTTP server does: at
// most 64 open connections, one request of at most 64 KiB and 30 seconds on each, a TLS ClientHello
// answered with a handshake_failure alert, anything malformed dropped with no reply, and replies
// with only its headers in its order. It blocks until l fails or [Handler.Close] closes it.
func (h *Handler) ServeListener(l net.Listener) error {
	s := &server{h: h, l: l, conns: make(map[net.Conn]struct{})}
	h.closeFunc = s.close
	h.addr = l.Addr()
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		if !s.add(c) {
			h.conf.Logger.Warn("rejecting new connection: too many open", "max", maxOpenConnections)
			_ = c.Close()
			continue
		}
		go s.serve(c)
	}
}

// server is what [Handler.ServeListener] keeps while running.
type server struct {
	h     *Handler
	l     net.Listener
	mu    sync.Mutex
	conns map[net.Conn]struct{}
}

// add counts a new connection, if there is room.
func (s *server) add(c net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.conns) >= maxOpenConnections {
		return false
	}
	s.conns[c] = struct{}{}
	return true
}

// close stops the listener and every connection.
func (s *server) close() error {
	err := s.l.Close()
	s.mu.Lock()
	defer s.mu.Unlock()
	for c := range s.conns {
		_ = c.Close()
	}
	return err
}

// serve answers the one request of a connection and closes it.
func (s *server) serve(c net.Conn) {
	defer func() {
		_ = c.Close()
		s.mu.Lock()
		delete(s.conns, c)
		s.mu.Unlock()
	}()
	log := s.h.conf.Logger.With("remote", c.RemoteAddr())
	if err := c.SetDeadline(time.Now().Add(requestTimeout)); err != nil {
		return
	}
	var buf []byte
	chunk := make([]byte, 4096)
	for {
		n, err := c.Read(chunk)
		if n > 0 {
			if len(buf)+n > maxRequestSize {
				log.Warn("dropping oversized request", "max", maxRequestSize)
				return
			}
			buf = append(buf, chunk[:n]...)
			if len(buf) > 1 && buf[0] == 0x16 && buf[1] == 0x03 {
				log.Debug("received TLS ClientHello: sending handshake_failure")
				_, _ = c.Write(tlsHandshakeFailure)
				return
			}
			req, complete, perr := parseRequest(buf)
			if perr != nil {
				log.Warn("dropping malformed request", "error", perr)
				return
			}
			if complete {
				r := &reply{header: http.Header{}, status: http.StatusOK}
				s.h.route(r, req)
				_, _ = c.Write(r.bytes())
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// parseRequest parses a request once all of it has arrived. complete is false until then.
func parseRequest(b []byte) (req *http.Request, complete bool, err error) {
	end := bytes.Index(b, []byte("\r\n\r\n"))
	if end < 0 {
		return nil, false, nil
	}
	lines := strings.Split(string(b[:end]), "\r\n")
	method, rest, ok := strings.Cut(lines[0], " ")
	if !ok {
		return nil, false, errors.New("request line missing method/path separator")
	}
	target, _, ok := strings.Cut(rest, " ")
	if !ok {
		return nil, false, errors.New("request line missing path/version separator")
	}
	length := -1
	for _, line := range lines[1:] {
		name, value, ok := strings.Cut(line, ":")
		if !ok || !strings.EqualFold(name, "Content-Length") {
			continue
		}
		n, err := strconv.Atoi(strings.Trim(value, " \t"))
		if err != nil || n < 0 {
			return nil, false, errors.New("invalid Content-Length")
		}
		if length >= 0 && length != n {
			return nil, false, errors.New("conflicting Content-Length headers")
		}
		length = n
	}
	if length > maxRequestSize {
		return nil, false, errors.New("Content-Length exceeds per-request byte cap")
	}
	body := b[end+4:]
	if length < 0 {
		length = 0
	}
	if len(body) < length {
		return nil, false, nil
	}
	req, err = http.NewRequest(method, target, bytes.NewReader(body[:length]))
	if err != nil {
		return nil, false, fmt.Errorf("request line: %w", err)
	}
	req.RequestURI = target
	return req, true, nil
}

// reply collects what a handler answers.
type reply struct {
	header http.Header
	status int
	body   bytes.Buffer
}

// Header implements [http.ResponseWriter].
func (r *reply) Header() http.Header { return r.header }

// WriteHeader implements [http.ResponseWriter].
func (r *reply) WriteHeader(status int) { r.status = status }

// Write implements [http.ResponseWriter].
func (r *reply) Write(b []byte) (int, error) { return r.body.Write(b) }

// bytes is the reply as BDS writes it.
func (r *reply) bytes() []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", r.status, http.StatusText(r.status))
	if t := r.header.Get("Content-Type"); t != "" {
		fmt.Fprintf(&b, "Content-Type: %s\r\n", t)
	}
	fmt.Fprintf(&b, "Content-Length: %d\r\nConnection: close\r\n\r\n", r.body.Len())
	b.Write(r.body.Bytes())
	return b.Bytes()
}
