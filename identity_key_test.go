package nethernet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestIdentityKeyRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys", "server_identity_key.pem")
	key, saved, err := LoadOrGenerateIdentityKey(path)
	if err != nil || saved {
		t.Fatalf("missing file: saved %v, err %v", saved, err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a generated key was saved without being asked to")
	}
	if err := SaveIdentityKey(path, key); err != nil {
		t.Fatal(err)
	}
	loaded, saved, err := LoadOrGenerateIdentityKey(path)
	if err != nil || !saved || !loaded.Equal(key) {
		t.Fatalf("saved key: saved %v, equal %v, err %v", saved, loaded != nil && loaded.Equal(key), err)
	}
	if err := DeleteIdentityKey(path); err != nil {
		t.Fatal(err)
	}
	if err := DeleteIdentityKey(path); err != nil {
		t.Fatalf("deleting a missing key: %v", err)
	}
}

// TestOpenSSLKeyForms reads the forms the BDS guide's openssl commands write.
func TestOpenSSLKeyForms(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sec1, _ := x509.MarshalECPrivateKey(key)
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(key)
	params := pem.EncodeToMemory(&pem.Block{Type: "EC PARAMETERS", Bytes: []byte{6, 5, 43, 129, 4, 0, 34}})
	for name, data := range map[string][]byte{
		"sec1":             pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1}),
		"sec1 with params": append(params, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1})...),
		"pkcs8":            pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}),
	} {
		got, err := parseIdentityKey(data)
		if err != nil || !got.Equal(key) {
			t.Errorf("%s: err %v", name, err)
		}
	}
}

func TestBadIdentityKeys(t *testing.T) {
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalECPrivateKey(p256)
	for name, data := range map[string][]byte{
		"empty":     nil,
		"not a key": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1}}),
		"P-256":     pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}),
		"encrypted": pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: der}),
	} {
		if _, err := parseIdentityKey(data); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A broken saved key must not be swapped for a new identity.
	path := filepath.Join(t.TempDir(), "k.pem")
	if err := os.WriteFile(path, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadOrGenerateIdentityKey(path); err == nil {
		t.Fatal("a broken key file was replaced by a generated key")
	}
}
