package nethernet

import (
	"testing"

	"github.com/pion/sdp/v3"
)

// These fuzz tests feed arbitrary input to every parser that reads data from
// remote peers or signaling services. None of them may panic.

func FuzzSignalUnmarshalText(f *testing.F) {
	f.Add([]byte("CONNECTREQUEST 123 v=0"))
	f.Add([]byte("CANDIDATEADD 1 candidate:1 1 udp 1 127.0.0.1 19132 typ host"))
	f.Add([]byte("CONNECTERROR 5 1"))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, b []byte) {
		_ = (&Signal{}).UnmarshalText(b)
	})
}

func FuzzParseMessage(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 1, 2, 3})
	f.Add([]byte{1, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = parseMessage(b)
	})
}

func FuzzParseRemoteCandidate(f *testing.F) {
	f.Add("candidate:1 1 udp 2130706431 127.0.0.1 19132 typ host")
	f.Add("")
	f.Add("candidate:")
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = parseRemoteCandidate(s)
	})
}

func FuzzParseSignalErrorCode(f *testing.F) {
	f.Add("1")
	f.Add("")
	f.Add("-99999999999999999999")
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = parseSignalErrorCode(s)
	})
}

func FuzzParsePublicKey(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x30, 0x59})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = parsePublicKey(b)
	})
}

func FuzzParseDescription(f *testing.F) {
	f.Add("v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n")
	f.Add("v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\na=ice-ufrag:a\r\na=ice-pwd:b\r\na=fingerprint:sha-256 00\r\n")
	f.Fuzz(func(t *testing.T, s string) {
		d := &sdp.SessionDescription{}
		if err := d.UnmarshalString(s); err != nil {
			return
		}
		_, _ = parseDescription(d)
	})
}
