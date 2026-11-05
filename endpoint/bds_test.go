package endpoint

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/helix-bedrock/nethernet"
)

// reply sends one request straight to a handler.
func reply(h *Handler, method, target, body string) *http.Response {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, target, strings.NewReader(body)))
	return rec.Result()
}

// Every route and refusal is BDS's, with its text.
func TestHandlerRoutes(t *testing.T) {
	h := newTestHandler()
	for _, c := range []struct {
		method, target, body string
		status               int
		text                 string
	}{
		{http.MethodPut, "/v1/join", "", http.StatusNotFound, "Not Found"},
		{http.MethodGet, "/v1/join/1", "", http.StatusNotFound, "Not Found"},
		{http.MethodPost, "/v1/join", "x", http.StatusNotFound, "Not Found"},
		{http.MethodPost, "/v1/join/abc", "x", http.StatusBadRequest, "Expected /v1/join/{networkId}"},
		{http.MethodPost, "/v1/join/", "x", http.StatusBadRequest, "Expected /v1/join/{networkId}"},
		{http.MethodPost, "/v1/join/1?a=b", "x", http.StatusBadRequest, "Expected /v1/join/{networkId}"},
		{http.MethodPost, "/v1/join/0", "x", http.StatusBadRequest, "Invalid networkId"},
		{http.MethodPost, "/v1/join/1", "", http.StatusBadRequest, "Missing SDP offer in request body"},
		{http.MethodGet, "/v1/join?a=b", "", http.StatusOK, ""},
	} {
		res := reply(h, c.method, c.target, c.body)
		got, _ := io.ReadAll(res.Body)
		if res.StatusCode != c.status || string(got) != c.text {
			t.Errorf("%s %s: %d %q, want %d %q", c.method, c.target, res.StatusCode, got, c.status, c.text)
		}
		if res.Header.Get("Connection") != "close" {
			t.Errorf("%s %s: does not close", c.method, c.target)
		}
	}
	if got := reply(h, http.MethodGet, "/v1/join", "").Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("status is %q", got)
	}
}

// answering signals back what it is told for each offer it gets.
type answering struct {
	h       *Handler
	kind    string
	data    string
	offered chan *nethernet.Signal
}

func (a *answering) NotifySignal(s *nethernet.Signal) bool {
	a.offered <- s
	if a.kind != "" {
		go func() {
			_ = a.h.Signal(context.Background(), &nethernet.Signal{Type: a.kind, ConnectionID: s.ConnectionID, NetworkID: s.NetworkID, Data: a.data})
		}()
	}
	return true
}

// An error signal is a 200 with its code as the body, as any signal is.
func TestHandlerRepliesWithAnySignal(t *testing.T) {
	for _, c := range []struct{ kind, data string }{
		{nethernet.SignalTypeAnswer, "v=0"},
		{nethernet.SignalTypeError, "37"},
	} {
		h := newTestHandler()
		a := &answering{h: h, kind: c.kind, data: c.data, offered: make(chan *nethernet.Signal, 2)}
		stop := h.Notify(a)
		res := reply(h, http.MethodPost, "/v1/join/5", "offer")
		got, _ := io.ReadAll(res.Body)
		stop()
		if res.StatusCode != http.StatusOK || string(got) != c.data || res.Header.Get("Content-Type") != "application/sdp" {
			t.Errorf("%s: %d %q %q", c.kind, res.StatusCode, got, res.Header.Get("Content-Type"))
		}
		if id := (<-a.offered).ConnectionID; id != 1 {
			t.Errorf("first connection ID %d", id)
		}
	}
}

// With no answer in time: a 504, and the session is not told, so it goes on.
func TestHandlerAnswerTimeout(t *testing.T) {
	h := HandlerConfig{NegotiationContext: func(parent context.Context) (context.Context, context.CancelFunc) {
		return context.WithTimeout(parent, 10*time.Millisecond)
	}}.New()
	h.disableNotifyTypeCheck = true
	a := &answering{h: h, offered: make(chan *nethernet.Signal, 2)}
	defer h.Notify(a)()
	res := reply(h, http.MethodPost, "/v1/join/5", "offer")
	got, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusGatewayTimeout || string(got) != "Gateway Timeout" {
		t.Errorf("%d %q", res.StatusCode, got)
	}
	<-a.offered
	if len(a.offered) != 0 {
		t.Error("the session was told of the timeout")
	}
}

// A signal for a request already answered or gone is dropped without complaint.
func TestHandlerDropsSignalForNoRequest(t *testing.T) {
	h := newTestHandler()
	err := h.Signal(context.Background(), &nethernet.Signal{Type: nethernet.SignalTypeError, ConnectionID: 9, NetworkID: "5", Data: "15"})
	if err != nil {
		t.Error(err)
	}
}

// serveTest runs a handler on a real socket through NewListener.
func serveTest(t *testing.T) net.Addr {
	t.Helper()
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: newTestHandler(), ReadTimeout: RequestTimeout}
	go func() { _ = srv.Serve(NewListener(tcp, nil)) }()
	t.Cleanup(func() { _ = srv.Close() })
	return tcp.Addr()
}

// A TLS ClientHello gets the alert at once and the connection is closed, even if it has no line
// ending for an HTTP server to wait for.
func TestListenerRefusesTLS(t *testing.T) {
	c, err := net.Dial("tcp", serveTest(t).String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Write([]byte{0x16, 0x03, 0x01, 0x00, 0x05, 1, 2, 3, 4, 5}); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte{0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x28}) {
		t.Errorf("got %x", got)
	}
}

// More than 64 KiB from a connection drops it with no reply.
func TestListenerDropsOversized(t *testing.T) {
	c, err := net.Dial("tcp", serveTest(t).String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_, _ = c.Write([]byte("POST /v1/join/5 HTTP/1.1\r\nHost: a\r\nContent-Length: 70000\r\n\r\n"))
	_, _ = c.Write(make([]byte, 70000))
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	got, _ := io.ReadAll(c)
	if len(got) != 0 {
		t.Errorf("replied %q", got)
	}
}

// Past 64 open connections a new one is closed at once.
func TestListenerCapsOpenConnections(t *testing.T) {
	addr := serveTest(t)
	var open []net.Conn
	defer func() {
		for _, c := range open {
			_ = c.Close()
		}
	}()
	for range maxOpenConnections {
		c, err := net.Dial("tcp", addr.String())
		if err != nil {
			t.Fatal(err)
		}
		open = append(open, c)
	}
	// A reply on the last one shows all of them were accepted.
	last := open[len(open)-1]
	if _, err := last.Write([]byte("GET /v1/join HTTP/1.1\r\nHost: a\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := http.ReadResponse(bufio.NewReader(last), nil); err != nil {
		t.Fatal(err)
	}
	// That reply closed the last one, so its slot is free again: fill it, then go over.
	var over net.Conn
	for range 2 {
		c, err := net.Dial("tcp", addr.String())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()
		over = c
	}
	_ = over.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err := over.Read(make([]byte, 1))
	var ne net.Error
	if err == nil || (errors.As(err, &ne) && ne.Timeout()) {
		t.Errorf("connection over the cap stayed open: %v", err)
	}
}
