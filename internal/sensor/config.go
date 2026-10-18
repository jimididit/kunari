package sensor

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/jimididit/kunari/internal/safepath"
)

// Config is the on-disk sentinel configuration.
type Config struct {
	Targets          []Target     `json:"targets"`
	Allowlist        []AllowEntry `json:"allowlist"`
	HeartbeatEvery   string       `json:"heartbeat_every"` // duration, default 60s
	DataDir          string       `json:"data_dir"`
	KeyPath          string       `json:"key_path"`
	PreferTier       []string     `json:"prefer_tiers,omitempty"`
	AgentVersion     string       `json:"agent_version"`
}

func LoadConfig(path string) (*Config, error) {
	path, err := safepath.Clean(path)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path) // #nosec G304 -- path cleaned by safepath.Clean
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	if len(c.Allowlist) == 0 {
		c.Allowlist = DefaultAllowlist()
	}
	if c.HeartbeatEvery == "" {
		c.HeartbeatEvery = "60s"
	}
	if c.AgentVersion == "" {
		c.AgentVersion = "0.1.0-dev"
	}
	for i := range c.Targets {
		p, err := safepath.Clean(c.Targets[i].Path)
		if err != nil {
			return nil, fmt.Errorf("target %d: %w", i, err)
		}
		c.Targets[i].Path = p
	}
	return &c, nil
}

func (c *Config) HeartbeatDuration() time.Duration {
	d, err := time.ParseDuration(c.HeartbeatEvery)
	if err != nil || d < 5*time.Second {
		return 60 * time.Second
	}
	return d
}

func (c *Config) Hash() string {
	b, _ := json.Marshal(struct {
		Targets   []Target     `json:"targets"`
		Allowlist []AllowEntry `json:"allowlist"`
		Prefer    []string     `json:"prefer_tiers,omitempty"`
	}{c.Targets, c.Allowlist, c.PreferTier})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func WriteExampleConfig(path string, targets []Target) error {
	c := Config{
		Targets:        targets,
		Allowlist:      DefaultAllowlist(),
		HeartbeatEvery: "60s",
		DataDir:        "./data-sentinel",
		KeyPath:        "./data-sentinel/signing.key",
		AgentVersion:   "0.1.0-dev",
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	path, err = safepath.Clean(path)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}
