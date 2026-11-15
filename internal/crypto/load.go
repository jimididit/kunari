package crypto

import (
	"fmt"
	"os"

	"github.com/jimididit/kunari/internal/safepath"
)

// Load reads an existing Ed25519 private key file. It does not create one.
func Load(path string) (*KeyPair, error) {
	if path == "" {
		return nil, fmt.Errorf("key path required")
	}
	path, err := safepath.Clean(path)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path) // #nosec G304 -- path cleaned by safepath.Clean
	if err != nil {
		return nil, err
	}
	return ParsePrivateHex(string(trimSpace(data)))
}
