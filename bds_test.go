package nethernet

import (
	"net/netip"
	"testing"
	"time"

	"github.com/pion/sdp/v3"
	"github.com/pion/webrtc/v4"
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

// The forms of BDS's server-udp-ports.
func TestParsePortMappings(t *testing.T) {
	public := netip.MustParseAddr("50.0.0.1")
	got, err := ParsePortMappings("19132, 20000-20009:30000-30009", public)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != (PortMapping{Min: 19132, Max: 19132, PublicIP: public}) ||
		got[1] != (PortMapping{Min: 30000, Max: 30009, Offset: -10000, PublicIP: public}) {
		t.Errorf("got %+v", got)
	}
	own, err := ParsePortMappings("60.0.0.2:19132", public)
	if err != nil || own[0].PublicIP != netip.MustParseAddr("60.0.0.2") {
		t.Errorf("own address: %+v %v", own, err)
	}
	v6, err := ParsePortMappings("[2001:db8::1]:19132:19133", netip.Addr{})
	if err != nil || v6[0].PublicIP != netip.MustParseAddr("2001:db8::1") || v6[0].Offset != -1 {
		t.Errorf("IPv6: %+v %v", v6, err)
	}
	for _, bad := range []string{"9-1", "1-2:1-3", "1.1.1.1:5,2.2.2.2:6", "[::1:5", "x"} {
		if _, err := ParsePortMappings(bad, public); err == nil {
			t.Errorf("%q was taken", bad)
		}
	}
}

// A host candidate gives a server-reflexive one at the mapped address, once.
func TestMappedCandidates(t *testing.T) {
	host := webrtc.ICECandidate{Foundation: "1", Priority: 2130706431, Address: "192.168.1.5", Protocol: webrtc.ICEProtocolUDP, Port: 19132, Typ: webrtc.ICECandidateTypeHost, Component: 1}
	m := []PortMapping{{Min: 19132, Max: 19132, PublicIP: netip.MustParseAddr("50.0.0.1")}}
	got := mappedCandidates(m, []webrtc.ICECandidate{host, host})
	if len(got) != 1 || got[0].Typ != webrtc.ICECandidateTypeSrflx || got[0].Address != "50.0.0.1" || got[0].Port != 19132 ||
		got[0].RelatedAddress != "192.168.1.5" || got[0].RelatedPort != 19132 || got[0].Priority>>24 != srflxTypePreference {
		t.Errorf("got %+v", got)
	}
	if got := mappedCandidates([]PortMapping{{Min: 1, Max: 2, PublicIP: netip.MustParseAddr("50.0.0.1")}}, []webrtc.ICECandidate{host}); len(got) != 0 {
		t.Errorf("a port out of range gave %+v", got)
	}
}

// An offer with no max-message-size has the default; one too small waits for ICE.
func TestMaxMessageSizeDefault(t *testing.T) {
	d := &sdp.SessionDescription{MediaDescriptions: []*sdp.MediaDescription{{}}}
	m := d.MediaDescriptions[0]
	m.WithICECredentials("a", "b").WithFingerprint("sha-256", "AA").WithValueAttribute("setup", "active")
	got, err := parseDescription(d)
	if err != nil || got.sctp.MaxMessageSize != defaultSCTPMessageSize {
		t.Fatalf("%+v %v", got, err)
	}
	m.WithValueAttribute("max-message-size", "1")
	if got, err = parseDescription(d); err != nil || got.sctp.MaxMessageSize != 1 {
		t.Fatalf("%+v %v", got, err)
	}
}
