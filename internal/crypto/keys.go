package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/jimididit/kunari/internal/safepath"
)

// KeyPair holds an Ed25519 signing key used for manifests and event chains.
type KeyPair struct {
	Public  ed25519.PublicKey
	Private ed25519.PrivateKey
}

func Generate() (*KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &KeyPair{Public: pub, Private: priv}, nil
}

func (k *KeyPair) Sign(msg []byte) []byte {
	return ed25519.Sign(k.Private, msg)
}

func Verify(pub ed25519.PublicKey, msg, sig []byte) bool {
	return ed25519.Verify(pub, msg, sig)
}

func (k *KeyPair) PublicHex() string {
	return hex.EncodeToString(k.Public)
}

func (k *KeyPair) PrivateHex() string {
	return hex.EncodeToString(k.Private)
}

func ParsePrivateHex(s string) (*KeyPair, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("private key must be %d bytes", ed25519.PrivateKeySize)
	}
	priv := ed25519.PrivateKey(b)
	return &KeyPair{Private: priv, Public: priv.Public().(ed25519.PublicKey)}, nil
}

func LoadOrCreate(path string) (*KeyPair, error) {
	if path == "" {
		return Generate()
	}
	path, err := safepath.Clean(path)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path) // path cleaned by safepath.Clean
	if err == nil {
		return ParsePrivateHex(string(trimSpace(data)))
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	kp, err := Generate()
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, []byte(kp.PrivateHex()+"\n"), 0o600); err != nil {
		return nil, err
	}
	return kp, nil
}

func trimSpace(b []byte) []byte {
	i, j := 0, len(b)
	for i < j && (b[i] == ' ' || b[i] == '\n' || b[i] == '\r' || b[i] == '\t') {
		i++
	}
	for j > i && (b[j-1] == ' ' || b[j-1] == '\n' || b[j-1] == '\r' || b[j-1] == '\t') {
		j--
	}
	return b[i:j]
}
