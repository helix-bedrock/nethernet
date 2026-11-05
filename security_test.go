package nethernet

import (
	"log/slog"
	"testing"
	"time"
)

func newTestChannel(r MessageReliability) *dataChannel {
	return &dataChannel{reliability: r, message: &message{}, packets: make(chan []byte, 1), close: make(chan struct{})}
}

// A packet past the limit ends the connection, whether it comes in one segment or many.
func TestPacketLimit(t *testing.T) {
	conn := &Conn{maxPacketSize: 4, log: slog.New(slog.DiscardHandler)}
	c := newTestChannel(MessageReliabilityReliable)
	if err := c.handleMessage(conn, []byte{0, 1, 2, 3, 4, 5}); err == nil {
		t.Error("took a packet of 5 bytes with a limit of 4")
	}
	c = newTestChannel(MessageReliabilityReliable)
	if err := c.handleMessage(conn, []byte{2, 1, 2}); err != nil {
		t.Fatal(err)
	}
	if err := c.handleMessage(conn, []byte{1, 3, 4}); err != nil {
		t.Fatal(err)
	}
	if err := c.handleMessage(conn, []byte{0, 5}); err == nil {
		t.Error("joined a packet of 5 bytes with a limit of 4")
	}
	if err := newTestChannel(MessageReliabilityUnreliable).handleMessage(conn, []byte{0, 1, 2, 3, 4, 5}); err == nil {
		t.Error("took an unreliable packet of 5 bytes with a limit of 4")
	}
	c = newTestChannel(MessageReliabilityReliable)
	if err := c.handleMessage(conn, []byte{0, 1, 2, 3, 4}); err != nil {
		t.Errorf("refused a packet at the limit: %v", err)
	}
}

// One segment is handed on as it came, with no copy.
func TestOneSegmentNotCopied(t *testing.T) {
	c := newTestChannel(MessageReliabilityReliable)
	b := []byte{0, 'a', 'b'}
	if err := c.handleMessage(nil, b); err != nil {
		t.Fatal(err)
	}
	if got := <-c.packets; &got[0] != &b[1] {
		t.Error("the packet was copied")
	}
}

// Offers past MaxNegotiations are dropped, and taken again once one ends.
func TestMaxNegotiations(t *testing.T) {
	s := newBlockingCredentialsSignaling()
	l, err := ListenConfig{Log: slog.New(slog.DiscardHandler), MaxNegotiations: 1, AllowAnonymous: true}.Listen(s)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	offer := &Signal{Type: SignalTypeOffer, ConnectionID: 1, Data: testOfferSDP, NetworkID: "a"}
	if !l.NotifySignal(offer) {
		t.Fatal("first offer dropped")
	}
	<-s.started
	if l.NotifySignal(&Signal{Type: SignalTypeOffer, ConnectionID: 2, Data: testOfferSDP, NetworkID: "a"}) {
		t.Error("second offer taken over the limit")
	}
	// The client gives up; its negotiation ends and frees its place.
	l.NotifySignal(&Signal{Type: SignalTypeError, ConnectionID: 1, Data: "1", NetworkID: "a"})
	deadline := time.Now().Add(5 * time.Second)
	for l.pending.Load() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("the negotiation did not end")
		}
		time.Sleep(time.Millisecond)
	}
	if !l.NotifySignal(&Signal{Type: SignalTypeOffer, ConnectionID: 3, Data: testOfferSDP, NetworkID: "a"}) {
		t.Error("offer dropped after the first ended")
	}
}

// testOfferSDP is a minimal offer that parses.
const testOfferSDP = "v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\nc=IN IP4 0.0.0.0\r\na=ice-ufrag:abcd\r\na=ice-pwd:abcdefghijklmnopqrstuvwx\r\na=fingerprint:sha-256 00:11\r\na=setup:actpass\r\na=mid:0\r\na=sctp-port:5000\r\na=max-message-size:262144\r\n"

func BenchmarkReceiveOneSegment(b *testing.B) {
	c := newTestChannel(MessageReliabilityReliable)
	msg := make([]byte, 1024)
	b.ReportAllocs()
	for b.Loop() {
		if err := c.handleMessage(nil, msg); err != nil {
			b.Fatal(err)
		}
		<-c.packets
	}
}
