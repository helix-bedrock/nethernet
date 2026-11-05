package endpoint

import (
	"net"
	"net/netip"
	"testing"
)

// fakeConn is a connection from an address, for counting.
type fakeConn struct {
	net.Conn
	addr *net.TCPAddr
}

func (c fakeConn) RemoteAddr() net.Addr { return c.addr }

func connFrom(ip string, port int) fakeConn {
	return fakeConn{addr: &net.TCPAddr{IP: net.ParseIP(ip), Port: port}}
}

// One address may hold only its share of the open connections; others still get in, up to 64.
func TestServerCapsPerAddress(t *testing.T) {
	s := &server{conns: map[net.Conn]struct{}{}, perIP: map[netip.Addr]int{}}
	var first net.Conn
	for i := range maxConnectionsPerIP {
		c := connFrom("10.0.0.1", i)
		if !s.add(c) {
			t.Fatalf("connection %d refused", i)
		}
		if i == 0 {
			first = c
		}
	}
	if s.add(connFrom("10.0.0.1", 9999)) {
		t.Error("one address took more than its share")
	}
	if s.add(connFrom("::ffff:10.0.0.1", 9998)) {
		t.Error("the IPv6 form of the address took more than its share")
	}
	s.remove(first)
	if !s.add(connFrom("10.0.0.1", 9999)) {
		t.Error("a closed connection did not free its place")
	}
	n := maxConnectionsPerIP
	for i := 0; n < maxOpenConnections; i++ {
		if !s.add(connFrom(net.IPv4(10, 1, byte(i/maxConnectionsPerIP), 1).String(), i)) {
			t.Fatalf("refused at %d open", n)
		}
		n++
	}
	if s.add(connFrom("10.2.0.1", 1)) {
		t.Error("took more than 64 open connections")
	}
}
