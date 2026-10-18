package hub

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/jimididit/kunari/internal/safepath"
)

const secretBytes = 32

// loadOrCreateIngestSecret reads a hex-encoded secret from path, or creates one.
func loadOrCreateIngestSecret(path string) ([]byte, error) {
	return loadOrCreateSecret(path, "ingest secret")
}

// loadOrCreateAPIToken loads/creates the operator read API bearer token.
func loadOrCreateAPIToken(path string) ([]byte, error) {
	return loadOrCreateSecret(path, "api token")
}

func loadOrCreateSecret(path, label string) ([]byte, error) {
	path, err := safepath.Clean(path)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path) // #nosec G304 -- path cleaned by safepath.Clean
	if err == nil {
		raw := trimSpaceBytes(b)
		if len(raw) == 0 {
			return nil, fmt.Errorf("%s file %q is empty", label, path)
		}
		// Accept raw bytes or hex encoding.
		if decoded, err := hex.DecodeString(string(raw)); err == nil && len(decoded) >= 16 {
			return decoded, nil
		}
		if len(raw) >= 16 {
			return raw, nil
		}
		return nil, fmt.Errorf("%s must be at least 16 bytes", label)
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	buf := make([]byte, secretBytes)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	encoded := []byte(hex.EncodeToString(buf) + "\n")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		return nil, err
	}
	return buf, nil
}

func trimSpaceBytes(b []byte) []byte {
	i, j := 0, len(b)
	for i < j && (b[i] == ' ' || b[i] == '\t' || b[i] == '\n' || b[i] == '\r') {
		i++
	}
	for j > i && (b[j-1] == ' ' || b[j-1] == '\t' || b[j-1] == '\n' || b[j-1] == '\r') {
		j--
	}
	return b[i:j]
}
