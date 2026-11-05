package nethernet

import (
	"github.com/pion/ice/v4"
	"github.com/pion/webrtc/v4"
)

const (
	// DefaultMaxPacketSize is the largest packet a peer may send, joined from its segments, unless
	// [ListenConfig.MaxPacketSize] or [Dialer.MaxPacketSize] says otherwise. NetherNet itself allows
	// 255 segments of 256 KiB, near 64 MiB, which no real packet comes close to.
	DefaultMaxPacketSize = 16 << 20

	// DefaultMaxNegotiations is how many offers a Listener negotiates at once, unless
	// [ListenConfig.MaxNegotiations] says otherwise. A negotiation lives until ICE connects or fails,
	// so this bounds what a flood of offers can hold.
	DefaultMaxNegotiations = 1024

	// maxKeptSendBuffer is the largest send buffer a data channel keeps between writes. Bigger
	// segments are rare, and keeping one per player would cost too much memory.
	maxKeptSendBuffer = 64 << 10
)

// ApplySettings sets what NetherNet needs on a [webrtc.SettingEngine] for the API given to a
// [ListenConfig] or [Dialer]. Listen and DialContext use it when they make their own API.
//
//   - A peer's message is cut at the 256 KiB this package announces in its SDP: pion would take
//     one of up to 1 GiB otherwise. BDS's SCTP stack bounds it too.
//   - SCTP zero checksum (RFC 9653) is offered: when the peer offers it as well, neither side
//     computes CRC32c, as DTLS already guards every packet. Peers that do not offer it are not
//     affected.
//   - mDNS candidates are off: native libwebrtc, which BDS and the game use, does not make them, and
//     each connection would open a multicast socket for nothing.
func ApplySettings(se *webrtc.SettingEngine) {
	if se == nil {
		return
	}
	se.SetSCTPMaxMessageSize(maxMessageSize + 1)
	se.EnableSCTPZeroChecksum(true)
	se.SetICEMulticastDNSMode(ice.MulticastDNSModeDisabled)
}

// newAPI is the API used when the caller gives none.
func newAPI() *webrtc.API {
	var se webrtc.SettingEngine
	ApplySettings(&se)
	return webrtc.NewAPI(webrtc.WithSettingEngine(se))
}

// packetLimit is the largest packet the peer may send.
func (conn *Conn) packetLimit() int {
	if conn == nil || conn.maxPacketSize <= 0 {
		return DefaultMaxPacketSize
	}
	return conn.maxPacketSize
}
