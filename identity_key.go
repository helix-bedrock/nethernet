package nethernet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// DefaultIdentityKeyPath is where the Bedrock Dedicated Server keeps its
// server identity key, relative to its working directory.
const DefaultIdentityKeyPath = "keys/server_identity_key.pem"

// The identity key identifies a server to players. Clients that connect over
// plain HTTP signaling ask the player to trust the server the first time, and
// again whenever the key changes, so a server that keeps its key keeps its
// players' trust across restarts.
//
// The functions below follow BDS 1.26.60: the key is an unencrypted P-384
// private key in a PEM file; when the file is missing, a key is generated in
// memory and not saved by itself (BDS saves it on the "serveridentity save"
// command). Whether to save it is the server's choice.

// LoadIdentityKey reads an unencrypted P-384 private key from a PEM file, in
// SEC 1 ("EC PRIVATE KEY", as openssl ecparam writes, with or without an
// "EC PARAMETERS" block before it) or PKCS #8 ("PRIVATE KEY") form. A missing
// file returns an error matching os.ErrNotExist.
func LoadIdentityKey(path string) (*ecdsa.PrivateKey, error) {
	b, err := os.ReadFile(path) //nolint:gosec // the server owner chooses the path
	if err != nil {
		return nil, err // already names the path
	}
	key, err := parseIdentityKey(b)
	if err != nil {
		return nil, fmt.Errorf("nethernet: identity key %s: %w", path, err)
	}
	return key, nil
}

func parseIdentityKey(b []byte) (*ecdsa.PrivateKey, error) {
	for {
		var block *pem.Block
		block, b = pem.Decode(b)
		if block == nil {
			return nil, errors.New("no private key PEM block")
		}
		if len(block.Headers) != 0 {
			return nil, errors.New("encrypted keys are not supported")
		}
		var key *ecdsa.PrivateKey
		switch block.Type {
		case "EC PARAMETERS":
			continue
		case "EC PRIVATE KEY":
			k, err := x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse SEC 1 key: %w", err)
			}
			key = k
		case "PRIVATE KEY":
			parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse PKCS #8 key: %w", err)
			}
			k, ok := parsed.(*ecdsa.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("key is %T, want an ECDSA key", parsed)
			}
			key = k
		default:
			return nil, fmt.Errorf("unexpected PEM block %q", block.Type)
		}
		if key.Curve != elliptic.P384() {
			return nil, fmt.Errorf("key uses %s, want P-384", key.Curve.Params().Name)
		}
		return key, nil
	}
}

// GenerateIdentityKey returns a new P-384 identity key.
func GenerateIdentityKey() (*ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("nethernet: generate identity key: %w", err)
	}
	return key, nil
}

// LoadOrGenerateIdentityKey loads the key at path, or generates one in memory
// when the file does not exist, as BDS does at startup. saved reports whether
// the key came from the file. A file that exists but cannot be used is an
// error, so a broken key never silently changes the server's identity.
func LoadOrGenerateIdentityKey(path string) (key *ecdsa.PrivateKey, saved bool, err error) {
	key, err = LoadIdentityKey(path)
	if err == nil {
		return key, true, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, false, err
	}
	key, err = GenerateIdentityKey()
	return key, false, err
}

// SaveIdentityKey writes key to path as an unencrypted SEC 1 PEM file,
// readable only by its owner, creating the folder if needed. It replaces an
// existing file in one step, so a crash never leaves half a key behind.
func SaveIdentityKey(path string, key *ecdsa.PrivateKey) error {
	if key == nil || key.Curve != elliptic.P384() {
		return errors.New("nethernet: save identity key: want a P-384 key")
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("nethernet: save identity key: %w", err)
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("nethernet: save identity key: %w", err)
	}
	f, err := os.CreateTemp(dir, ".identity-*.pem")
	if err != nil {
		return fmt.Errorf("nethernet: save identity key: %w", err)
	}
	tmp := f.Name()
	_, werr := f.Write(data)
	cerr := f.Close()
	if err := errors.Join(werr, cerr); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("nethernet: save identity key: %w", err)
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("nethernet: save identity key: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("nethernet: save identity key: %w", err)
	}
	return nil
}

// DeleteIdentityKey removes the saved key at path. Deleting a key that is not
// there is not an error. The running server keeps its identity until it
// restarts.
func DeleteIdentityKey(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("nethernet: delete identity key: %w", err)
	}
	return nil
}
