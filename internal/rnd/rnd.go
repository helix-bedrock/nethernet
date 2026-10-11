// Package rnd provides random numbers for IDs that must not be predictable.
package rnd

import (
	"crypto/rand"
	"encoding/binary"
)

// Uint64 returns a random uint64 from crypto/rand. Connection and network IDs
// route signaling messages, so a guessable ID could let another peer interfere
// with a connection. crypto/rand.Read never returns an error on supported
// platforms.
func Uint64() uint64 {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return binary.LittleEndian.Uint64(b[:])
}
