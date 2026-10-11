package nethernet

import (
	"context"

	"github.com/helix-bedrock/nethernet/internal/hook"
)

// Verdict is returned by hooks that may stop what they observe.
type Verdict = hook.Verdict

const (
	// Allow lets the data or action continue. It is the zero value.
	Allow = hook.Allow
	// Drop stops the data or action. Later hooks are not called.
	Drop = hook.Drop
)

// SignalEvent describes a signal received from or sent to the signaling
// service: offers, answers, ICE candidates and errors.
type SignalEvent struct {
	// Signal is the signal. A hook may change its fields; incoming changes
	// affect how it is handled and outgoing changes affect what is sent.
	Signal *Signal
}

// AttemptEvent describes a new connection offer from a remote network, before
// the listener allocates anything for it.
type AttemptEvent struct {
	// NetworkID is the remote network that sent the offer.
	NetworkID string
	// ConnectionID identifies the connection within that network.
	ConnectionID uint64
	// Offer is the SDP offer.
	Offer string
}

// StateEvent describes a state change of one of a connection's transports.
type StateEvent struct {
	// Conn is the connection whose transport changed state.
	Conn *Conn
	// Transport is "ice", "dtls" or "sctp".
	Transport string
	// State is the new state, as reported by Pion.
	State string
}

// MessageEvent describes one raw data-channel message: a single segment
// including its one-byte remaining-segment header.
type MessageEvent struct {
	// Conn is the connection the message belongs to.
	Conn *Conn
	// Reliability is the data channel the message travels on.
	Reliability MessageReliability
	// Data is the raw message. It is only valid during the hook; a hook may
	// replace it to change what is processed or sent.
	Data []byte
}

// PacketEvent describes one complete packet, after segments are reassembled
// (incoming) or before they are split (outgoing): usually one Minecraft batch.
type PacketEvent struct {
	// Conn is the connection the packet belongs to.
	Conn *Conn
	// Reliability is the data channel the packet travels on.
	Reliability MessageReliability
	// Data is the packet. It is only valid during the hook; a hook may replace
	// it to change what is delivered or sent.
	Data []byte
}

// connHooks are hooks that can be set on a Listener (for every connection) or
// on a single Conn.
type connHooks struct {
	messageIn, messageOut hook.List[func(*MessageEvent) Verdict]
	packetIn, packetOut   hook.List[func(*PacketEvent) Verdict]
	state                 hook.List[func(*StateEvent)]
	disconnect            hook.List[func(*Conn)]
}

// listenerHooks are hooks only a Listener has.
type listenerHooks struct {
	connHooks
	signalIn, signalOut hook.List[func(*SignalEvent) Verdict]
	attempt             hook.List[func(*AttemptEvent) Verdict]
	connect             hook.List[func(*Conn)]
}

// OnSignalIn registers fn for every signal the listener receives. Returning
// Drop ignores the signal. It returns a function that removes the hook.
func (l *Listener) OnSignalIn(fn func(*SignalEvent) Verdict) (remove func()) {
	return l.hooks.signalIn.Add(fn)
}

// OnSignalOut registers fn for every signal the listener or its connections
// send. Returning Drop stops it from being sent.
func (l *Listener) OnSignalOut(fn func(*SignalEvent) Verdict) (remove func()) {
	return l.hooks.signalOut.Add(fn)
}

// OnConnectionAttempt registers fn for every new connection offer, before
// anything is allocated for it. Returning Drop ignores the offer.
func (l *Listener) OnConnectionAttempt(fn func(*AttemptEvent) Verdict) (remove func()) {
	return l.hooks.attempt.Add(fn)
}

// OnConnect registers fn to be called when a connection is fully established,
// just before Accept returns it.
func (l *Listener) OnConnect(fn func(*Conn)) (remove func()) {
	return l.hooks.connect.Add(fn)
}

// OnDisconnect registers fn to be called when any connection of the listener
// closes.
func (l *Listener) OnDisconnect(fn func(*Conn)) (remove func()) {
	return l.hooks.disconnect.Add(fn)
}

// OnStateChange registers fn for ICE, DTLS and SCTP state changes on any
// connection. It is called from Pion's callbacks and must not block.
func (l *Listener) OnStateChange(fn func(*StateEvent)) (remove func()) {
	return l.hooks.state.Add(fn)
}

// OnMessageIn registers fn for every raw data-channel message (segment)
// received on any connection. Returning Drop discards it.
func (l *Listener) OnMessageIn(fn func(*MessageEvent) Verdict) (remove func()) {
	return l.hooks.messageIn.Add(fn)
}

// OnMessageOut registers fn for every raw data-channel message (segment) sent
// on any connection. Returning Drop discards it.
func (l *Listener) OnMessageOut(fn func(*MessageEvent) Verdict) (remove func()) {
	return l.hooks.messageOut.Add(fn)
}

// OnPacketIn registers fn for every complete packet received on any
// connection. Returning Drop discards it.
func (l *Listener) OnPacketIn(fn func(*PacketEvent) Verdict) (remove func()) {
	return l.hooks.packetIn.Add(fn)
}

// OnPacketOut registers fn for every packet sent on any connection, before it
// is split into segments. Returning Drop discards it.
func (l *Listener) OnPacketOut(fn func(*PacketEvent) Verdict) (remove func()) {
	return l.hooks.packetOut.Add(fn)
}

// OnStateChange registers fn for state changes of this connection only.
func (conn *Conn) OnStateChange(fn func(*StateEvent)) (remove func()) {
	return conn.hooks.state.Add(fn)
}

// OnMessageIn registers fn for raw messages received on this connection only.
func (conn *Conn) OnMessageIn(fn func(*MessageEvent) Verdict) (remove func()) {
	return conn.hooks.messageIn.Add(fn)
}

// OnMessageOut registers fn for raw messages sent on this connection only.
func (conn *Conn) OnMessageOut(fn func(*MessageEvent) Verdict) (remove func()) {
	return conn.hooks.messageOut.Add(fn)
}

// OnPacketIn registers fn for complete packets received on this connection
// only.
func (conn *Conn) OnPacketIn(fn func(*PacketEvent) Verdict) (remove func()) {
	return conn.hooks.packetIn.Add(fn)
}

// OnPacketOut registers fn for packets sent on this connection only.
func (conn *Conn) OnPacketOut(fn func(*PacketEvent) Verdict) (remove func()) {
	return conn.hooks.packetOut.Add(fn)
}

// OnDisconnect registers fn to be called when this connection closes.
func (conn *Conn) OnDisconnect(fn func(*Conn)) (remove func()) {
	return conn.hooks.disconnect.Add(fn)
}

// lhooks returns the hooks of the listener that accepted conn, or nil for
// dialed connections.
func (conn *Conn) lhooks() *connHooks {
	if conn.listener == nil {
		return nil
	}
	return &conn.listener.hooks.connHooks
}

// runMessage runs raw message hooks. It returns the (possibly replaced) data
// and false if a hook dropped it.
func (conn *Conn) runMessage(in bool, r MessageReliability, b []byte) ([]byte, bool) {
	var l, c []hook.Entry[func(*MessageEvent) Verdict]
	if lh := conn.lhooks(); lh != nil {
		if in {
			l = lh.messageIn.Get()
		} else {
			l = lh.messageOut.Get()
		}
	}
	if in {
		c = conn.hooks.messageIn.Get()
	} else {
		c = conn.hooks.messageOut.Get()
	}
	if l == nil && c == nil {
		return b, true
	}
	e := &MessageEvent{Conn: conn, Reliability: r, Data: b}
	if hook.Run(conn.log, e, l, c) == Drop {
		return nil, false
	}
	return e.Data, true
}

// runPacket runs packet hooks. It returns the (possibly replaced) data and
// false if a hook dropped it.
func (conn *Conn) runPacket(in bool, r MessageReliability, b []byte) ([]byte, bool) {
	var l, c []hook.Entry[func(*PacketEvent) Verdict]
	if lh := conn.lhooks(); lh != nil {
		if in {
			l = lh.packetIn.Get()
		} else {
			l = lh.packetOut.Get()
		}
	}
	if in {
		c = conn.hooks.packetIn.Get()
	} else {
		c = conn.hooks.packetOut.Get()
	}
	if l == nil && c == nil {
		return b, true
	}
	e := &PacketEvent{Conn: conn, Reliability: r, Data: b}
	if hook.Run(conn.log, e, l, c) == Drop {
		return nil, false
	}
	return e.Data, true
}

// runState runs state hooks for a transport state change.
func (conn *Conn) runState(transport, state string) {
	var l []hook.Entry[func(*StateEvent)]
	if lh := conn.lhooks(); lh != nil {
		l = lh.state.Get()
	}
	c := conn.hooks.state.Get()
	if l == nil && c == nil {
		return
	}
	hook.Observe(conn.log, &StateEvent{Conn: conn, Transport: transport, State: state}, l, c)
}

// runDisconnect runs the disconnect hooks of the connection and its listener.
func (conn *Conn) runDisconnect() {
	var l []hook.Entry[func(*Conn)]
	if lh := conn.lhooks(); lh != nil {
		l = lh.disconnect.Get()
	}
	c := conn.hooks.disconnect.Get()
	if l == nil && c == nil {
		return
	}
	hook.Observe(conn.log, conn, l, c)
}

// sendSignal sends s through signaling, running the signal-out hooks of l
// first. l may be nil for dialed connections.
func sendSignal(ctx context.Context, l *Listener, signaling Signaling, s *Signal) error {
	if l != nil {
		if hooks := l.hooks.signalOut.Get(); hooks != nil {
			if hook.Run(l.conf.Log, &SignalEvent{Signal: s}, hooks) == Drop {
				return nil
			}
		}
	}
	return signaling.Signal(ctx, s)
}
