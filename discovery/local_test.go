package discovery

import (
	"net"
	"testing"
)

// Packets are taken from this network only, unless AllowPublic is set.
func TestLocalSourcesOnly(t *testing.T) {
	l := &Listener{}
	for ip, want := range map[string]bool{
		"127.0.0.1": true, "192.168.1.5": true, "10.0.0.2": true, "172.16.0.1": true,
		"169.254.1.1": true, "100.100.1.1": true, "fe80::1": true, "fd00::1": true, "::ffff:192.168.1.5": true,
		"8.8.8.8": false, "2001:4860::8888": false,
	} {
		if got := l.isLocal(&net.UDPAddr{IP: net.ParseIP(ip), Port: 7551}); got != want {
			t.Errorf("%s: local %v", ip, got)
		}
	}
	l.conf.AllowPublic = true
	if !l.isLocal(&net.UDPAddr{IP: net.ParseIP("8.8.8.8")}) {
		t.Error("AllowPublic did not take a public address")
	}
}
