package registry

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/jimididit/kunari/internal/safepath"
)

// ImportFile reads a signed manifest JSON file and upserts it into the store.
// trustedPubHex must match the manifest signing public key.
func (s *Store) ImportFile(path, trustedPubHex string) (*Manifest, error) {
	path, err := safepath.Clean(path)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path) // #nosec G304 -- path cleaned by safepath.Clean
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("manifest json: %w", err)
	}
	if err := s.Import(&m, trustedPubHex); err != nil {
		return nil, err
	}
	return &m, nil
}
