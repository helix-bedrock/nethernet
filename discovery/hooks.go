package discovery

import (
	"net"

	"github.com/helix-bedrock/nethernet/internal/hook"
)

// Verdict is returned by hooks that may stop what they observe.
type Verdict = hook.Verdict

const (
	// Allow lets the packet continue. It is the zero value.
	Allow = hook.Allow
	// Drop stops the packet. Later hooks are not called.
	Drop = hook.Drop
)

// PacketEvent describes one LAN discovery packet, received from or sent to the
// local network. Anyone on the network can send these, so hooks see them
// before the listener acts on them.
type PacketEvent struct {
	// Addr is the address the packet came from or is sent to.
	Addr net.Addr
	// SenderID is the network ID of the sender: the remote network for incoming
	// packets, this listener for outgoing ones.
	SenderID uint64
	// Packet is the decoded packet. A hook may change its fields.
	Packet Packet
	// Raw is the encrypted packet as received. It is nil for outgoing packets,
	// which are encoded after the hooks run.
	Raw []byte
}

// discoveryHooks are the hooks of a discovery Listener.
type discoveryHooks struct {
	in, out hook.List[func(*PacketEvent) Verdict]
}

// OnPacketIn registers fn for every discovery packet received from the local
// network, after it is decrypted and decoded. Returning Drop ignores it. It
// returns a function that removes the hook.
func (l *Listener) OnPacketIn(fn func(*PacketEvent) Verdict) (remove func()) {
	return l.hooks.in.Add(fn)
}

// OnPacketOut registers fn for every discovery packet the listener sends.
// Returning Drop stops it from being sent.
func (l *Listener) OnPacketOut(fn func(*PacketEvent) Verdict) (remove func()) {
	return l.hooks.out.Add(fn)
}
