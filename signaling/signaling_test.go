package signaling

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/helix-bedrock/nethernet"
	"golang.org/x/net/websocket"
)

// fakeService is the signaling service: it answers TurnAuth and remembers what it got.
type fakeService struct {
	got     chan rpc
	headers chan http.Header
	path    chan string
	send    chan string
}

func newFakeService(t *testing.T) (*fakeService, string) {
	t.Helper()
	f := &fakeService{got: make(chan rpc, 32), headers: make(chan http.Header, 1), path: make(chan string, 1), send: make(chan string, 4)}
	srv := httptest.NewServer(websocket.Server{
		Handshake: func(*websocket.Config, *http.Request) error { return nil },
		Handler: func(ws *websocket.Conn) {
			f.headers <- ws.Request().Header
			f.path <- ws.Request().URL.Path
			go func() {
				for m := range f.send {
					_ = websocket.Message.Send(ws, m)
				}
			}()
			for {
				var text string
				if err := websocket.Message.Receive(ws, &text); err != nil {
					return
				}
				var m rpc
				if err := json.Unmarshal([]byte(text), &m); err != nil {
					continue
				}
				f.got <- m
				if m.Method == methodTurnAuth {
					f.send <- `{"jsonrpc":"2.0","id":"` + m.ID + `","result":{"ExpirationInSeconds":3600,"TurnAuthServers":[{"Username":"u","Password":"p","Urls":["stun:example.invalid:3478"]}]}}`
				}
			}
		},
	})
	t.Cleanup(srv.Close)
	return f, srv.URL
}

// wait returns the next message with the method.
func (f *fakeService) wait(t *testing.T, method string) rpc {
	t.Helper()
	for {
		select {
		case m := <-f.got:
			if m.Method == method {
				return m
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("no %s", method)
		}
	}
}

type notifierFunc func(*nethernet.Signal) bool

func (f notifierFunc) NotifySignal(s *nethernet.Signal) bool { return f(s) }

// Signing in uses BDS's path and headers, brings ICE servers, and carries signals both ways.
func TestSignIn(t *testing.T) {
	f, base := newFakeService(t)
	const id = "12345678-1234-1234-1234-123456789abc"
	c, err := Dial(t.Context(), Config{
		URL: base, SignInID: id, PingInterval: 20 * time.Millisecond,
		Token: func(context.Context) (string, error) { return "tok", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()

	h := <-f.headers
	if h.Get("Authorization") != "Bearer tok" || h.Get("Session-Id") == "" || h.Get("Request-Id") == "" {
		t.Errorf("headers %v", h)
	}
	if p := <-f.path; p != "/ws/v1.0/messaging/connect/20CA2/"+id {
		t.Errorf("path %s", p)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	creds, err := c.Credentials(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(creds.ICEServers) != 1 || creds.ICEServers[0].Username != "u" || creds.ICEServers[0].URLs[0] != "stun:example.invalid:3478" {
		t.Errorf("ICE servers %+v", creds)
	}
	f.wait(t, methodPing)

	in := make(chan *nethernet.Signal, 1)
	defer c.Notify(notifierFunc(func(s *nethernet.Signal) bool { in <- s; return true }))()
	f.send <- `{"jsonrpc":"2.0","method":"Signaling_ReceiveMessage_v1_0","params":{"netherNetId":"77","message":"CONNECTREQUEST 5 v=0"}}`
	select {
	case s := <-in:
		if s.Type != nethernet.SignalTypeOffer || s.ConnectionID != 5 || s.Data != "v=0" || s.NetworkID != "77" {
			t.Errorf("signal %+v", s)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no signal")
	}

	if err := c.Signal(ctx, &nethernet.Signal{Type: nethernet.SignalTypeAnswer, ConnectionID: 5, Data: "v=1", NetworkID: "77"}); err != nil {
		t.Fatal(err)
	}
	var p sendParams
	if err := json.Unmarshal(f.wait(t, methodSend).Params, &p); err != nil {
		t.Fatal(err)
	}
	if p.ToPlayerID != "77" || p.Message != "CONNECTRESPONSE 5 v=1" || p.MessageID == "" {
		t.Errorf("sent %+v", p)
	}

	_ = c.Close()
	if c.Context().Err() == nil {
		t.Error("closing did not end the context")
	}
}

func TestSignInNeedsID(t *testing.T) {
	if _, err := Dial(t.Context(), Config{URL: "ws://127.0.0.1:1"}); err == nil {
		t.Error("signed in with no ID")
	}
}

// writeTestKey writes a PEM key and certificate, and returns the path.
func writeTestKey(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "t"}, NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	b := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	b = append(b, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	path := filepath.Join(t.TempDir(), "cert.pem")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// The token request has BDS's form and a client assertion that verifies, and is kept for reuse.
func TestAzureToken(t *testing.T) {
	key, cert, err := LoadCertificate(writeTestKey(t))
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/tenant/oauth2/v2.0/token" || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Errorf("request %s %s", r.URL.Path, r.Header)
		}
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		for k, v := range map[string]string{"client_id": "app", "scope": "api://mcsignaling/.default", "grant_type": "client_credentials", "client_assertion_type": assertionType} {
			if r.Form.Get(k) != v {
				t.Errorf("%s = %q", k, r.Form.Get(k))
			}
		}
		parts := strings.Split(r.Form.Get("client_assertion"), ".")
		if len(parts) != 3 {
			t.Fatalf("assertion %q", r.Form.Get("client_assertion"))
		}
		sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
		sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		if err := rsa.VerifyPKCS1v15(&key.PublicKey, 5, sum[:], sig); err != nil {
			t.Errorf("signature: %v", err)
		}
		claims, _ := base64.RawURLEncoding.DecodeString(parts[1])
		var c map[string]any
		_ = json.Unmarshal(claims, &c)
		if c["iss"] != "app" || c["sub"] != "app" || !strings.HasSuffix(c["aud"].(string), "/tenant/oauth2/v2.0/token") || c["jti"] == "" {
			t.Errorf("claims %v", c)
		}
		_, _ = w.Write([]byte(`{"access_token":"tok","expires_in":3600}`))
	}))
	defer srv.Close()
	a := &AzureAuth{ApplicationID: "app", TenantID: "tenant", Key: key, Certificate: cert, TokenURL: srv.URL}
	for range 2 {
		got, err := a.Token(t.Context())
		if err != nil || got != "tok" {
			t.Fatalf("%q %v", got, err)
		}
	}
	if calls != 1 {
		t.Errorf("asked Azure AD %d times", calls)
	}
}

// Discovery gives the signaling service's address.
func TestDiscover(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1.0/discovery/MinecraftDedicatedServer/builds/1.26.60" {
			t.Errorf("path %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"result":{"serviceEnvironments":{"signaling":{"prod":{"serviceUri":"https://s.example.invalid"}}}}}`))
	}))
	defer srv.Close()
	got, err := Discover(t.Context(), nil, srv.URL, "1.26.60", "prod")
	if err != nil || got != "https://s.example.invalid" {
		t.Errorf("%q %v", got, err)
	}
	if _, err := url.Parse(got); err != nil {
		t.Error(err)
	}
}
