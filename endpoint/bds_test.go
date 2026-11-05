package endpoint

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/helix-bedrock/nethernet"
)

// call sends one request straight to a handler.
func call(h *Handler, method, target, body string) *http.Response {
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
		res := call(h, c.method, c.target, c.body)
		got, _ := io.ReadAll(res.Body)
		if res.StatusCode != c.status || string(got) != c.text {
			t.Errorf("%s %s: %d %q, want %d %q", c.method, c.target, res.StatusCode, got, c.status, c.text)
		}
		if res.Header.Get("Connection") != "close" {
			t.Errorf("%s %s: does not close", c.method, c.target)
		}
	}
	if got := call(h, http.MethodGet, "/v1/join", "").Header.Get("Content-Type"); got != "application/json" {
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
		res := call(h, http.MethodPost, "/v1/join/5", "offer")
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
	res := call(h, http.MethodPost, "/v1/join/5", "offer")
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

// serveTest runs a handler on a real socket the way BDS serves.
func serveTest(t *testing.T) (net.Addr, *Handler) {
	t.Helper()
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h := newTestHandler()
	go func() { _ = h.ServeListener(tcp) }()
	t.Cleanup(func() { _ = tcp.Close() })
	return tcp.Addr(), h
}

// send writes raw bytes and reads all that come back.
func send(t *testing.T, addr net.Addr, b []byte) []byte {
	t.Helper()
	c, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_, _ = c.Write(b)
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	got, _ := io.ReadAll(c)
	return got
}

// A reply has only BDS's headers, in its order.
func TestServerReplyBytes(t *testing.T) {
	addr, _ := serveTest(t)
	got := send(t, addr, []byte("PUT /x HTTP/1.1\r\nHost: a\r\n\r\n"))
	want := "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: 9\r\nConnection: close\r\n\r\nNot Found"
	if string(got) != want {
		t.Errorf("got %q", got)
	}
}

// A body may arrive after the headers; it is split as Content-Length says.
func TestServerReadsBody(t *testing.T) {
	addr, h := serveTest(t)
	a := &answering{h: h, kind: nethernet.SignalTypeAnswer, data: "v=0", offered: make(chan *nethernet.Signal, 1)}
	defer h.Notify(a)()
	got := send(t, addr, []byte("POST /v1/join/5 HTTP/1.1\r\ncontent-length: 5\r\n\r\noffer"))
	if !bytes.HasSuffix(got, []byte("\r\n\r\nv=0")) || !bytes.Contains(got, []byte("application/sdp")) {
		t.Errorf("got %q", got)
	}
	if s := <-a.offered; s.Data != "offer" {
		t.Errorf("offer %q", s.Data)
	}
}

// Anything malformed is dropped with no reply.
func TestServerDropsMalformed(t *testing.T) {
	addr, _ := serveTest(t)
	for _, req := range []string{
		"GET\r\n\r\n",
		"GET /v1/join\r\n\r\n",
		"POST /v1/join/5 HTTP/1.1\r\nContent-Length: x\r\n\r\n",
		"POST /v1/join/5 HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab",
		"POST /v1/join/5 HTTP/1.1\r\nContent-Length: 70000\r\n\r\n",
	} {
		if got := send(t, addr, []byte(req)); len(got) != 0 {
			t.Errorf("%q: replied %q", req, got)
		}
	}
}

// A TLS ClientHello gets the alert at once and the connection is closed, even if it has no line
// ending for an HTTP server to wait for.
func TestServerRefusesTLS(t *testing.T) {
	addr, _ := serveTest(t)
	got := send(t, addr, []byte{0x16, 0x03, 0x01, 0x00, 0x05, 1, 2, 3, 4, 5})
	if !bytes.Equal(got, []byte{0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x28}) {
		t.Errorf("got %x", got)
	}
}

// More than 64 KiB from a connection drops it with no reply.
func TestServerDropsOversized(t *testing.T) {
	addr, _ := serveTest(t)
	if got := send(t, addr, make([]byte, maxRequestSize+1)); len(got) != 0 {
		t.Errorf("replied %q", got)
	}
}

// Past 64 open connections a new one is closed at once.
func TestServerCapsOpenConnections(t *testing.T) {
	addr, _ := serveTest(t)
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
	var err error
	for range 50 {
		var over net.Conn
		if over, err = net.Dial("tcp", addr.String()); err != nil {
			t.Fatal(err)
		}
		_ = over.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		_, err = over.Read(make([]byte, 1))
		_ = over.Close()
		var ne net.Error
		if err != nil && !(errors.As(err, &ne) && ne.Timeout()) {
			return
		}
	}
	t.Errorf("connection over the cap stayed open: %v", err)
}

// The status has BDS's fields in its order, and its version and connection kind.
func TestStatusFields(t *testing.T) {
	h := newTestHandler()
	h.Status(Status{ServerName: "a", Protocol: 2225, Version: "1.26.60", LevelName: "b", PlayerCount: 1, MaxPlayerCount: 10, OnlineAuth: true})
	res := call(h, http.MethodGet, "/v1/join", "")
	got, _ := io.ReadAll(res.Body)
	re := regexp.MustCompile(`^\{"dataVersion":7,"name":"a","protocol":2225,"version":"1.26.60","level":"b","players":1,"maxPlayers":10,"gameType":0,"editor":false,"hardcore":false,"onlineAuth":true,"selfSignedAuth":false,"nonce":"[0-9a-f]+","connection":4\}$`)
	if !re.Match(got) {
		t.Errorf("got %s", got)
	}
	again, _ := io.ReadAll(call(h, http.MethodGet, "/v1/join", "").Body)
	if !bytes.Equal(got, again) {
		t.Error("the nonce changed inside its lifetime")
	}
	h.nonceAt = time.Now().Add(-nonceLifetime - time.Second)
	later, _ := io.ReadAll(call(h, http.MethodGet, "/v1/join", "").Body)
	if bytes.Equal(got, later) {
		t.Error("the nonce did not change after its lifetime")
	}
}
