package discovery

import (
	"bytes"
	"log/slog"
	"testing"
)

// LAN discovery packets come from anyone on the local network. These fuzz
// tests make sure no packet, valid or not, can panic the decoder.

func FuzzUnmarshal(f *testing.F) {
	f.Add(Marshal(&RequestPacket{}, 1))
	f.Add(Marshal(&ResponsePacket{ApplicationData: []byte("data")}, 2))
	f.Add(Marshal(&MessagePacket{RecipientID: 3, Data: "hello"}, 4))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _, _ = Unmarshal(b)
	})
}

func FuzzPacketBodies(f *testing.F) {
	f.Add(byte(0), []byte{})
	f.Add(byte(1), []byte{4, 0, 0, 0, 1, 2, 3, 4})
	f.Add(byte(2), []byte{1, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 'h', 'e', 'l', 'l', 'o'})
	f.Fuzz(func(t *testing.T, which byte, b []byte) {
		r := bytes.NewReader(b)
		switch which % 3 {
		case 0:
			_ = (&Header{}).Read(r)
		case 1:
			_ = (&ResponsePacket{}).Read(r)
		default:
			_ = (&MessagePacket{}).Read(r)
		}
	})
}

func FuzzServerData(f *testing.F) {
	if b, err := (&ServerData{ServerName: "Helix", LevelName: "world"}).MarshalBinary(); err == nil {
		f.Add(b)
	}
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		_ = (&ServerData{}).UnmarshalBinary(b)
	})
}

func FuzzBinaryReaders(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = readBool(bytes.NewBuffer(b))
		_, _ = readString(bytes.NewBuffer(b))
		_, _ = readVarint32(bytes.NewBuffer(b))
		_, _ = readVaruint32(bytes.NewBuffer(b))
	})
}

func FuzzPongData(f *testing.F) {
	f.Add([]byte("MCPE;Helix;800;1.26;1;10;123;world;Survival;1;19132;19132;0;"))
	f.Add([]byte(""))
	f.Add([]byte(";;;;;;;;"))
	f.Fuzz(func(t *testing.T, b []byte) {
		l := &Listener{conf: ListenConfig{Log: slog.New(slog.DiscardHandler)}}
		l.PongData(b)
	})
}
