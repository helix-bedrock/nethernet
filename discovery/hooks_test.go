package discovery

import (
	"log/slog"
	"net"
	"testing"
)

func newHookTestListener() *Listener {
	return &Listener{
		conf:      ListenConfig{NetworkID: 1, Log: slog.New(slog.DiscardHandler)},
		addresses: make(map[uint64]address),
		responses: make(map[uint64][]byte),
	}
}

func TestPacketInHookSeesAndDrops(t *testing.T) {
	l := newHookTestListener()
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 7551}
	raw := Marshal(&ResponsePacket{ApplicationData: []byte("pong")}, 2)

	var seen *PacketEvent
	remove := l.OnPacketIn(func(e *PacketEvent) Verdict {
		seen = e
		return Drop
	})
	if err := l.handlePacket(raw, addr); err != nil {
		t.Fatalf("handlePacket: %v", err)
	}
	if seen == nil || seen.SenderID != 2 || seen.Addr != addr || len(seen.Raw) != len(raw) {
		t.Fatalf("hook saw %+v, want sender 2 from %v with raw bytes", seen, addr)
	}
	if _, ok := seen.Packet.(*ResponsePacket); !ok {
		t.Fatalf("hook saw packet %T, want *ResponsePacket", seen.Packet)
	}
	if len(l.addresses) != 0 {
		t.Fatal("dropped packet still updated the address table")
	}

	remove()
	if err := l.handlePacket(raw, addr); err != nil {
		t.Fatalf("handlePacket after remove: %v", err)
	}
	if _, ok := l.addresses[2]; !ok {
		t.Fatal("packet was not handled after removing the hook")
	}
}

func TestPanickingDiscoveryHookDoesNotCrash(t *testing.T) {
	l := newHookTestListener()
	l.OnPacketIn(func(*PacketEvent) Verdict { panic("broken hook") })
	raw := Marshal(&ResponsePacket{ApplicationData: []byte("pong")}, 2)
	if err := l.handlePacket(raw, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 7551}); err != nil {
		t.Fatalf("handlePacket: %v", err)
	}
	if _, ok := l.addresses[2]; !ok {
		t.Fatal("packet was not handled after the hook panicked")
	}
}
