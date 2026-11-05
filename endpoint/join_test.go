package endpoint

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/helix-bedrock/nethernet"
	"github.com/pion/webrtc/v4"
)

// A client joins through the HTTP server, is offered the mapped address as a server-reflexive
// candidate, and packets of every size reach the other side.
func TestJoinThroughServer(t *testing.T) {
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h := HandlerConfig{}.New()
	go func() { _ = h.ServeListener(tcp) }()
	t.Cleanup(func() { _ = h.Close() })

	l, err := nethernet.ListenConfig{
		AllowAnonymous: true,
		PortMappings:   []nethernet.PortMapping{{Min: 1, Max: 65535, PublicIP: netip.MustParseAddr("127.0.0.1")}},
	}.Listen(h)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	addr := "http://127.0.0.1:" + strconv.Itoa(tcp.Addr().(*net.TCPAddr).Port)
	var d nethernet.Dialer
	client, err := d.DialContext(ctx, addr, NewClient())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	accepted, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = accepted.Close() }()

	srflx := false
	for _, c := range client.RemoteAddr().(*nethernet.Addr).Candidates {
		if c.Typ == webrtc.ICECandidateTypeSrflx && c.Address == "127.0.0.1" {
			srflx = true
		}
	}
	if !srflx {
		t.Error("no server-reflexive candidate was offered")
	}

	server := accepted.(*nethernet.Conn)
	for _, size := range []int{1, 1000, 300000} {
		if _, err := server.Write(make([]byte, size)); err != nil {
			t.Fatal(err)
		}
		got, err := client.ReadPacket()
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != size {
			t.Errorf("sent %d, got %d", size, len(got))
		}
	}
}
