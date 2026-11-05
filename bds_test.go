package nethernet

import (
	"testing"
	"time"
)

// BDS never joins unreliable messages and ignores their first byte, whatever it is.
func TestUnreliableIgnoresHeader(t *testing.T) {
	c := &dataChannel{reliability: MessageReliabilityUnreliable, message: &message{}, packets: make(chan []byte, 1), close: make(chan struct{})}
	if err := c.handleMessage(nil, []byte{7, 'a', 'b'}); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-c.packets:
		if string(got) != "ab" {
			t.Errorf("got %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("no packet")
	}
}

// A reliable message still joins, and a wrong count still ends it.
func TestReliableJoinsSegments(t *testing.T) {
	c := &dataChannel{reliability: MessageReliabilityReliable, message: &message{}, packets: make(chan []byte, 1), close: make(chan struct{})}
	if err := c.handleMessage(nil, []byte{1, 'a'}); err != nil {
		t.Fatal(err)
	}
	if err := c.handleMessage(nil, []byte{0, 'b'}); err != nil {
		t.Fatal(err)
	}
	if got := <-c.packets; string(got) != "ab" {
		t.Errorf("got %q", got)
	}
	if err := c.handleMessage(nil, []byte{2, 'a'}); err != nil {
		t.Fatal(err)
	}
	if err := c.handleMessage(nil, []byte{0, 'b'}); err == nil {
		t.Error("a wrong segment count was taken")
	}
}
