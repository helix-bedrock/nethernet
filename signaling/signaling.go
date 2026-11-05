// Package signaling signs in to Microsoft's signaling service the way BDS does: a WebSocket
// carrying JSON-RPC, which brings signals from players anywhere and the ICE servers (STUN and
// TURN) to reach them with. [Conn] is a [nethernet.Signaling].
package signaling

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/helix-bedrock/nethernet"
	"golang.org/x/net/websocket"
)

// The JSON-RPC methods of the service.
const (
	methodPing      = "System_Ping_v1_0"
	methodPong      = "System_Pong_v1_0"
	methodTurnAuth  = "Signaling_TurnAuth_v1_0"
	methodSend      = "Signaling_SendClientMessage_v1_0"
	methodReceive   = "Signaling_ReceiveMessage_v1_0"
	methodError     = "Signaling_ReceiveError_v1_0"
	methodDelivered = "Signaling_DeliveryNotification_V1_0"
)

const (
	// titleProduction and titleOther name the service's two kinds of environment in the path.
	titleProduction = "20CA2"
	titleOther      = "E9D1"
	// defaultPingInterval is half of a heartbeat BDS reads from its configuration. The
	// configured value was not read from BDS, so this one is an assumption.
	defaultPingInterval = 30 * time.Second
	// turnRefreshMargin renews ICE servers this long before they expire.
	turnRefreshMargin = time.Minute
	// writeTimeout limits one write to the service.
	writeTimeout = 15 * time.Second
)

// Config configures [Dial].
type Config struct {
	// URL is the service's address from discovery. https and http become wss and ws.
	URL string
	// SignInID is BDS's nethernet-id, a UUID naming this server to the service.
	SignInID string
	// NotProduction uses the path of environments other than production.
	NotProduction bool
	// Token returns the access token to sign in with. See [AzureAuth].
	Token func(ctx context.Context) (string, error)
	// PingInterval is how often the connection is kept alive. If 0, 30 seconds.
	PingInterval time.Duration
	// Log receives what happens. If nil, nothing is logged.
	Log *slog.Logger
}

// Conn is a connection to the service. Its methods may be called from any goroutine.
type Conn struct {
	conf   Config
	ws     *websocket.Conn
	writeM sync.Mutex

	ctx    context.Context
	cancel context.CancelCauseFunc

	mu        sync.Mutex
	notifiers map[int]nethernet.Notifier
	nextID    int
	turn      *nethernet.Credentials
	turnReady chan struct{}
}

// rpc is one JSON-RPC message, either way.
type rpc struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      string          `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

// sendParams are the parameters of methodSend.
type sendParams struct {
	ToPlayerID string `json:"toPlayerId"`
	MessageID  string `json:"messageId"`
	Message    string `json:"message"`
}

// receiveParams are the parameters of methodReceive.
type receiveParams struct {
	NetherNetID string `json:"netherNetId"`
	Message     string `json:"message"`
}

// Dial signs in and starts asking for ICE servers. The context limits signing in only.
func Dial(ctx context.Context, conf Config) (*Conn, error) {
	if conf.SignInID == "" {
		return nil, errors.New("signaling: no sign-in ID")
	}
	if conf.Log == nil {
		conf.Log = slog.New(slog.DiscardHandler)
	}
	if conf.PingInterval <= 0 {
		conf.PingInterval = defaultPingInterval
	}
	target, err := connectURL(conf)
	if err != nil {
		return nil, err
	}
	var token string
	if conf.Token != nil {
		if token, err = conf.Token(ctx); err != nil {
			return nil, fmt.Errorf("signaling: token: %w", err)
		}
	}
	sessionID, err := newUUID()
	if err != nil {
		return nil, err
	}
	requestID, err := newUUID()
	if err != nil {
		return nil, err
	}
	wc, err := websocket.NewConfig(target, target)
	if err != nil {
		return nil, fmt.Errorf("signaling: %w", err)
	}
	wc.Header = http.Header{
		"Authorization": {"Bearer " + token},
		"Session-Id":    {sessionID},
		"Request-Id":    {requestID},
	}
	ws, err := wc.DialContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("signaling: connect: %w", err)
	}
	c := &Conn{conf: conf, ws: ws, notifiers: make(map[int]nethernet.Notifier), turnReady: make(chan struct{})}
	c.ctx, c.cancel = context.WithCancelCause(context.Background())
	go c.read()
	go c.keepAlive()
	if err := c.askTurn(); err != nil {
		_ = c.Close()
		return nil, err
	}
	return c, nil
}

// connectURL is BDS's /ws/v1.0/messaging/connect/{title}/{sign-in ID} on the service's address.
func connectURL(conf Config) (string, error) {
	u, err := url.Parse(conf.URL)
	if err != nil {
		return "", fmt.Errorf("signaling: url: %w", err)
	}
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	}
	title := titleProduction
	if conf.NotProduction {
		title = titleOther
	}
	return u.JoinPath("/ws/v1.0/messaging/connect", title, conf.SignInID).String(), nil
}

// newUUID returns a random UUID in BDS's form.
func newUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("signaling: uuid: %w", err)
	}
	b[6], b[8] = b[6]&0x0f|0x40, b[8]&0x3f|0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}

// call sends a method.
func (c *Conn) call(method string, params any) error {
	id, err := newUUID()
	if err != nil {
		return err
	}
	raw, err := json.Marshal(params)
	if err != nil {
		return fmt.Errorf("signaling: encode %s: %w", method, err)
	}
	b, err := json.Marshal(rpc{JSONRPC: "2.0", ID: id, Method: method, Params: raw})
	if err != nil {
		return fmt.Errorf("signaling: encode %s: %w", method, err)
	}
	c.writeM.Lock()
	defer c.writeM.Unlock()
	if err := c.ws.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return fmt.Errorf("signaling: send %s: %w", method, err)
	}
	if err := websocket.Message.Send(c.ws, string(b)); err != nil {
		return fmt.Errorf("signaling: send %s: %w", method, err)
	}
	return nil
}

// askTurn asks for ICE servers. The answer comes through read.
func (c *Conn) askTurn() error { return c.call(methodTurnAuth, struct{}{}) }

// read handles what the service sends until the connection ends.
func (c *Conn) read() {
	for {
		var text string
		if err := websocket.Message.Receive(c.ws, &text); err != nil {
			c.cancel(fmt.Errorf("signaling: connection: %w", err))
			return
		}
		var m rpc
		if err := json.Unmarshal([]byte(text), &m); err != nil {
			c.conf.Log.Warn("bad message from signaling service", "err", err)
			continue
		}
		c.handle(m)
	}
}

// handle handles one message from the service.
func (c *Conn) handle(m rpc) {
	switch m.Method {
	case methodReceive:
		var p receiveParams
		if err := json.Unmarshal(m.Params, &p); err != nil {
			c.conf.Log.Warn("bad signal from signaling service", "err", err)
			return
		}
		s := &nethernet.Signal{}
		if err := s.UnmarshalText([]byte(p.Message)); err != nil {
			c.conf.Log.Warn("bad signal from signaling service", "err", err)
			return
		}
		s.NetworkID = p.NetherNetID
		c.notify(s)
	case methodError:
		c.conf.Log.Warn("signaling service reported an error", "params", string(m.Params))
	case methodPong, methodDelivered:
	case "":
		if len(m.Error) != 0 {
			c.conf.Log.Warn("signaling service refused a request", "error", string(m.Error))
			return
		}
		c.handleTurn(m.Result)
	default:
		c.conf.Log.Debug("unknown method from signaling service", "method", m.Method)
	}
}

// handleTurn takes ICE servers from an answer, and asks again before they expire.
func (c *Conn) handleTurn(result json.RawMessage) {
	var creds nethernet.Credentials
	if len(result) == 0 || json.Unmarshal(result, &creds) != nil || len(creds.ICEServers) == 0 {
		return
	}
	c.mu.Lock()
	first := c.turn == nil
	c.turn = &creds
	c.mu.Unlock()
	if first {
		close(c.turnReady)
	}
	if wait := time.Duration(creds.ExpirationInSeconds)*time.Second - turnRefreshMargin; wait > 0 {
		time.AfterFunc(wait, func() {
			if c.ctx.Err() == nil {
				if err := c.askTurn(); err != nil {
					c.conf.Log.Warn("cannot renew ICE servers", "err", err)
				}
			}
		})
	}
}

// notify hands a signal to those listening.
func (c *Conn) notify(s *nethernet.Signal) {
	c.mu.Lock()
	ns := make([]nethernet.Notifier, 0, len(c.notifiers))
	for _, n := range c.notifiers {
		ns = append(ns, n)
	}
	c.mu.Unlock()
	for _, n := range ns {
		n.NotifySignal(s)
	}
}

// keepAlive pings until the connection ends.
func (c *Conn) keepAlive() {
	t := time.NewTicker(c.conf.PingInterval)
	defer t.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-t.C:
			if err := c.call(methodPing, struct{}{}); err != nil {
				c.cancel(err)
				return
			}
		}
	}
}

// Signal implements [nethernet.Signaling].
func (c *Conn) Signal(_ context.Context, s *nethernet.Signal) error {
	id, err := newUUID()
	if err != nil {
		return err
	}
	return c.call(methodSend, sendParams{ToPlayerID: s.NetworkID, MessageID: id, Message: s.String()})
}

// Notify implements [nethernet.Signaling].
func (c *Conn) Notify(n nethernet.Notifier) (stop func()) {
	if n == nil {
		return func() {}
	}
	c.mu.Lock()
	id := c.nextID
	c.nextID++
	c.notifiers[id] = n
	c.mu.Unlock()
	return func() {
		c.mu.Lock()
		delete(c.notifiers, id)
		c.mu.Unlock()
	}
}

// Context implements [nethernet.Signaling]. It ends with the connection.
func (c *Conn) Context() context.Context { return c.ctx }

// Credentials implements [nethernet.Signaling]: the ICE servers from the service.
func (c *Conn) Credentials(ctx context.Context) (*nethernet.Credentials, error) {
	select {
	case <-c.turnReady:
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.turn, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.ctx.Done():
		return nil, context.Cause(c.ctx)
	}
}

// NetworkID implements [nethernet.Signaling]: the sign-in ID.
func (c *Conn) NetworkID() string { return strings.ToLower(c.conf.SignInID) }

// PongData implements [nethernet.Signaling]. The service carries no status.
func (c *Conn) PongData([]byte) {}

// Close ends the connection.
func (c *Conn) Close() error {
	c.cancel(errClosed)
	return c.ws.Close()
}

// errClosed is the cause of a connection closed by [Conn.Close].
var errClosed = errors.New("signaling: closed")
