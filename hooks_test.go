package nethernet

import (
	"bytes"
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// hookedPair listens with setup applied before any signal arrives, dials the
// listener over in-memory signaling and returns the listener and both ends.
func hookedPair(t *testing.T, setup func(*Listener)) (*Listener, *Conn, *Conn) {
	t.Helper()
	client, server := newMemorySignalingPair("client", "server")
	t.Cleanup(client.close)
	t.Cleanup(server.close)

	l, err := (ListenConfig{AllowAnonymous: true}).Listen(server)
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	if setup != nil {
		setup(l)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	accepted := make(chan net.Conn, 1)
	go func() {
		if c, err := l.Accept(); err == nil {
			accepted <- c
		}
	}()
	clientConn, err := (Dialer{}).DialContext(ctx, server.NetworkID(), client)
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	t.Cleanup(func() { _ = clientConn.Close() })
	select {
	case c := <-accepted:
		serverConn, ok := c.(*Conn)
		if !ok {
			t.Fatalf("accepted %T, want *Conn", c)
		}
		t.Cleanup(func() { _ = serverConn.Close() })
		return l, clientConn, serverConn
	case <-ctx.Done():
		t.Fatalf("Accept() timed out: %v", ctx.Err())
	}
	return nil, nil, nil
}

// packets reads every packet from c into the returned channel.
func packets(c *Conn) <-chan []byte {
	ch := make(chan []byte, 16)
	go func() {
		defer close(ch)
		for {
			b, err := c.ReadPacket()
			if err != nil {
				return
			}
			ch <- b
		}
	}()
	return ch
}

// within returns the next packet from ch, or nil if none arrives in d.
func within(ch <-chan []byte, d time.Duration) []byte {
	select {
	case b := <-ch:
		return b
	case <-time.After(d):
		return nil
	}
}

func TestListenerHooksObserveHandshake(t *testing.T) {
	var signalsIn, signalsOut, attempts, connects, states, messagesIn atomic.Int32
	_, client, server := hookedPair(t, func(l *Listener) {
		l.OnSignalIn(func(*SignalEvent) Verdict { signalsIn.Add(1); return Allow })
		l.OnSignalOut(func(*SignalEvent) Verdict { signalsOut.Add(1); return Allow })
		l.OnConnectionAttempt(func(e *AttemptEvent) Verdict {
			if e.NetworkID == "client" && e.Offer != "" {
				attempts.Add(1)
			}
			return Allow
		})
		l.OnConnect(func(*Conn) { connects.Add(1) })
		l.OnStateChange(func(*StateEvent) { states.Add(1) })
		l.OnMessageIn(func(*MessageEvent) Verdict { messagesIn.Add(1); return Allow })
	})
	in := packets(server)
	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if b := within(in, 5*time.Second); !bytes.Equal(b, []byte("hello")) {
		t.Fatalf("server read %q, want hello", b)
	}
	if signalsIn.Load() == 0 || signalsOut.Load() == 0 || states.Load() == 0 || messagesIn.Load() == 0 {
		t.Fatalf("hooks not called: signalsIn=%d signalsOut=%d states=%d messagesIn=%d",
			signalsIn.Load(), signalsOut.Load(), states.Load(), messagesIn.Load())
	}
	if attempts.Load() != 1 || connects.Load() != 1 {
		t.Fatalf("attempt=%d connect=%d, want 1 and 1", attempts.Load(), connects.Load())
	}
}

func TestPacketInHookCanReplaceData(t *testing.T) {
	_, client, server := hookedPair(t, func(l *Listener) {
		l.OnPacketIn(func(e *PacketEvent) Verdict {
			if bytes.Equal(e.Data, []byte("original")) {
				e.Data = []byte("changed")
			}
			return Allow
		})
	})
	in := packets(server)
	if _, err := client.Write([]byte("original")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if b := within(in, 5*time.Second); !bytes.Equal(b, []byte("changed")) {
		t.Fatalf("server read %q, want changed", b)
	}
}

func TestConnPacketOutHookDropsAndRemoves(t *testing.T) {
	_, client, server := hookedPair(t, nil)
	in := packets(client)
	remove := server.OnPacketOut(func(*PacketEvent) Verdict { return Drop })
	if _, err := server.Write([]byte("dropped")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if b := within(in, 300*time.Millisecond); b != nil {
		t.Fatalf("client read %q, want nothing while the hook drops packets", b)
	}
	remove()
	remove() // removing twice is safe
	if _, err := server.Write([]byte("sent")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if b := within(in, 5*time.Second); !bytes.Equal(b, []byte("sent")) {
		t.Fatalf("client read %q, want sent after removing the hook", b)
	}
}

func TestAttemptHookCanReject(t *testing.T) {
	client, server := newMemorySignalingPair("client", "server")
	t.Cleanup(client.close)
	t.Cleanup(server.close)
	l, err := (ListenConfig{AllowAnonymous: true}).Listen(server)
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	l.OnConnectionAttempt(func(*AttemptEvent) Verdict { return Drop })
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	if c, err := (Dialer{}).DialContext(ctx, server.NetworkID(), client); err == nil {
		_ = c.Close()
		t.Fatal("dial succeeded, want it rejected by the attempt hook")
	}
}

func TestPanickingHookDoesNotCrash(t *testing.T) {
	_, client, server := hookedPair(t, func(l *Listener) {
		l.OnPacketIn(func(*PacketEvent) Verdict { panic("broken hook") })
	})
	in := packets(server)
	if _, err := client.Write([]byte("still works")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if b := within(in, 5*time.Second); !bytes.Equal(b, []byte("still works")) {
		t.Fatalf("server read %q, want the packet despite the panicking hook", b)
	}
}

func TestDisconnectHooks(t *testing.T) {
	var listenerSaw, connSaw atomic.Int32
	_, client, server := hookedPair(t, func(l *Listener) {
		l.OnDisconnect(func(*Conn) { listenerSaw.Add(1) })
	})
	server.OnDisconnect(func(*Conn) { connSaw.Add(1) })
	_ = client.Close()
	_ = server.Close()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && (listenerSaw.Load() == 0 || connSaw.Load() == 0) {
		time.Sleep(10 * time.Millisecond)
	}
	if listenerSaw.Load() != 1 || connSaw.Load() != 1 {
		t.Fatalf("disconnect hooks: listener=%d conn=%d, want 1 and 1", listenerSaw.Load(), connSaw.Load())
	}
}

// BenchmarkHookCheckNoHooks measures what an unused hook costs on the hot
// path: it must be a few nanoseconds and allocate nothing.
func BenchmarkHookCheckNoHooks(b *testing.B) {
	c := &Conn{listener: &Listener{}}
	data := []byte{1, 2, 3}
	b.ReportAllocs()
	for b.Loop() {
		if _, keep := c.runPacket(true, MessageReliabilityReliable, data); !keep {
			b.Fatal("dropped")
		}
	}
}
