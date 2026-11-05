package nethernet

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"

	"github.com/pion/webrtc/v4"
)

// MessageReliability represents the reliability of messages sent in a data channel.
// It is an internal type specific to this package's implementation, and shouldn't
// be sent over network in any way.
type MessageReliability uint8

const (
	// MessageReliabilityReliable guarantees the ordering of messages. Currently, this is the
	// only reliability parameter used in the game.
	MessageReliabilityReliable MessageReliability = iota
	// MessageReliabilityUnreliable seems to be unused, and it is unclear how it
	// works with multiple segments as packet drops could leave the message data
	// in unconstructed state.
	// While it is technically possible to send or receive packets in this channel,
	// it is currently recommended to use only MessageReliabilityReliable.
	MessageReliabilityUnreliable

	// messageReliabilityCapacity is the maximum value for MessageReliability, used as the capacity for array.
	messageReliabilityCapacity
)

// Parameters returns a [webrtc.DataChannelParameters], which may be used for creating a data channel for
// the MessageReliability or to ensure that a data channel is valid to handle it in the Conn.
func (r MessageReliability) Parameters() *webrtc.DataChannelParameters {
	switch r {
	case MessageReliabilityReliable:
		return &webrtc.DataChannelParameters{
			Label:   "ReliableDataChannel",
			Ordered: true,
		}
	case MessageReliabilityUnreliable:
		param := uint16(0)
		return &webrtc.DataChannelParameters{
			Label:          "UnreliableDataChannel",
			MaxRetransmits: &param,
		}
	default:
		// Unknown reliability: callers must check for nil.
		return nil
	}
}

// Valid determines whether the [webrtc.DataChannel] can be safe to use in Conn.
// If the data channel does not have the exact same parameters returned by [MessageReliability.Parameters],
// it will return false.
func (r MessageReliability) Valid(channel *webrtc.DataChannel) bool {
	params := r.Parameters()
	if params == nil || channel == nil {
		return false
	}
	// Compare non-pointer values
	if channel.Label() != params.Label ||
		channel.Protocol() != params.Protocol ||
		channel.Ordered() != params.Ordered ||
		channel.Negotiated() != params.Negotiated {
		return false
	}
	// Compare pointer values that should be compared deeply with the underlying values
	return r.compareOptional(channel.MaxPacketLifeTime(), params.MaxPacketLifeTime) &&
		r.compareOptional(channel.MaxRetransmits(), params.MaxRetransmits)
}

// compareOptional returns true if both optional uint16 values are equal.
// It evaluates two nil *uint16s as equal, and if both pointers are non nil,
// it compares the underlying uint16 values. If one is nil and the other is not,
// it returns false.
func (r MessageReliability) compareOptional(a, b *uint16) bool {
	if a != nil && b != nil {
		return *a == *b
	}
	return a == nil && b == nil
}

// wrapDataChannel wraps a [webrtc.DataChannel] and sets up handlers to reconstruct
// fragmented messages. Received message segments are reassembled and sent to packets
// when all segments have arrived.
func wrapDataChannel(channel *webrtc.DataChannel, reliability MessageReliability, conn *Conn) *dataChannel {
	ch := &dataChannel{
		DataChannel: channel,
		reliability: reliability,
		// Previously, message.data was pre-allocated for all possible segments.
		// Since most messages are smaller than 256KB and don't require fragmentation,
		// we no longer need to pre-allocate a large buffer.
		message: &message{},
		packets: make(chan []byte),
		close:   make(chan struct{}),
	}
	ch.OnMessage(func(msg webrtc.DataChannelMessage) {
		data, keep := conn.runMessage(true, reliability, msg.Data)
		if !keep {
			return
		}
		if err := ch.handleMessage(conn, data); err != nil {
			if errors.Is(err, net.ErrClosed) {
				conn.log.Debug("message dropped due to closure of data channel",
					slog.String("label", ch.Label()))
				return
			}
			// Receiving an invalid or incomplete message is considered unrecoverable
			// as segmented packets cannot be completed. Closing the connection also
			// helps mitigate malformed or malicious input from a peer.
			// The DataChannel invokes this callback while holding an internal lock,
			// so the connection is closed in a goroutine to avoid deadlock.
			go func(err error) { _ = conn.close(err) }(fmt.Errorf("nethernet: handle message in %s: %w", ch.Label(), err))
		}
	})
	ch.OnClose(func() {
		// This handler function itself is invoked while holding an internal lock, so call close in a goroutine to avoid deadlock.
		go func(err error) { _ = conn.close(err) }(fmt.Errorf("nethernet: data channel %q closed by remote peer", ch.Label()))
	})
	return ch
}

// dataChannel represents the data channel responsible for sending and receiving messages in MessageReliability
// within a Conn. It contains the fields necessary for handling multiple segments received in the embedded [webrtc.DataChannel].
type dataChannel struct {
	*webrtc.DataChannel

	// An embedded message contains the buffer that holds the segments received
	// to now and the count of the last segment count.
	*message
	// messageMu guards message because Pion may invoke OnMessage concurrently
	// with Conn/data channel closure.
	messageMu sync.Mutex

	// reliability is the reliability parameter for dataChannel.
	// It controls how multiple segments received in the data channel is handled.
	reliability MessageReliability

	// When writing multiple segments to the dataChannel, it should be locked using
	// its embedded [sync.Mutex] for guaranteeing ordered segment counts.
	write sync.Mutex
	// sendBuf is reused for each segment written, guarded by write.
	sendBuf []byte

	// packets can be used to receive packets that are fully-reconstructed from
	// one or more segments received in the dataChannel.
	packets chan []byte

	// close is a channel that is closed when a dataChannel is closed.
	close chan struct{}
	// once ensures the dataChannel is closed only once.
	once sync.Once
}

// message is the reassembly state of ReliableDataChannel: what is left to come and what came.
type message struct {
	// segments is how many segments are still to come.
	segments uint8
	// data is the packet so far.
	data []byte
}

// parseMessage splits a segment into its count of segments to come and its payload. A segment
// needs its header byte and at least one byte of payload.
func parseMessage(b []byte) (segments uint8, data []byte, err error) {
	if len(b) < 2 {
		return 0, nil, io.ErrUnexpectedEOF
	}
	return b[0], b[1:], nil
}

// handleMessage handles a message received from a [webrtc.DataChannel] for the reliability. It parses
// the incoming data into a message using parseMessage and handles the segments, and if all segments has
// been received, it sends the buffer to either [Conn.Read] or [Conn.ReadPacket].
func (c *dataChannel) handleMessage(conn *Conn, b []byte) error {
	select {
	case <-c.close:
		return net.ErrClosed
	default:
	}

	segments, data, err := parseMessage(b)
	if err != nil {
		return fmt.Errorf("parse: %w", err)
	}
	limit := conn.packetLimit()

	// BDS never joins unreliable messages and ignores their first byte.
	if c.reliability == MessageReliabilityUnreliable {
		if len(data) > limit {
			return fmt.Errorf("packet larger than %d bytes", limit)
		}
		return c.deliver(conn, data)
	}

	c.messageMu.Lock()
	defer c.messageMu.Unlock()

	if c.segments > 0 && c.segments-1 != segments {
		return fmt.Errorf("invalid promised segments: expected %d, got %d", c.segments-1, segments)
	}
	if len(c.data)+len(data) > limit {
		// A peer may promise 255 segments of 256 KiB; nothing real is that big.
		return fmt.Errorf("packet larger than %d bytes", limit)
	}
	c.segments = segments

	if c.data == nil {
		if segments == 0 {
			// The usual case, one segment: pion gave this message its own slice, so it is
			// the packet as it is, with no copy.
			return c.deliver(conn, data)
		}
		c.data = make([]byte, 0, min((int(segments)+1)*len(data), limit))
	}
	c.data = append(c.data, data...)
	if segments > 0 {
		return nil
	}
	packet := c.data
	c.data = nil
	return c.deliver(conn, packet)
}

// deliver hands a whole packet to those reading it.
func (c *dataChannel) deliver(conn *Conn, packet []byte) error {
	if conn != nil {
		var keep bool
		if packet, keep = conn.runPacket(true, c.reliability, packet); !keep {
			return nil
		}
	}
	select {
	case <-c.close:
		return net.ErrClosed
	case c.packets <- packet:
	}

	return nil
}

// Close closes the underlying [webrtc.DataChannel].
func (c *dataChannel) Close() (err error) {
	c.once.Do(func() {
		close(c.close)
		c.messageMu.Lock()
		clear(c.data)
		c.messageMu.Unlock()
		err = c.DataChannel.Close()
	})
	return err
}
