package sensor

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"github.com/jimididit/kunari/internal/safepath"
)

const agentIDFile = "agent.id"

// loadOrCreateAgentID returns a stable opaque ID for this sentinel install.
// Stored under data_dir so hub last-seen / missing-agent alerts survive restarts.
func loadOrCreateAgentID(dataDir string) (string, error) {
	dataDir, err := safepath.Clean(dataDir)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dataDir, agentIDFile)
	b, err := os.ReadFile(path) // #nosec G304 -- path under safepath-cleaned data_dir
	if err == nil {
		id := strings.TrimSpace(string(b))
		if id != "" {
			return id, nil
		}
	}
	id := uuid.Must(uuid.NewV7()).String()
	if err := os.WriteFile(path, []byte(id+"\n"), 0o600); err != nil {
		return "", err
	}
	if err := hardenPrivateFile(path); err != nil {
		return "", err
	}
	return id, nil
}
