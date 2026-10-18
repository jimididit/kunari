package sensor

import (
	"fmt"
	"net/url"
	"os"
	"strings"
)

// HardenSensitivePaths tightens permissions on the sentinel config, data dir,
// and optional hub secret. Safe to call on every start.
func HardenSensitivePaths(configPath string, cfg *Config) error {
	if err := hardenPrivateFile(configPath); err != nil {
		return fmt.Errorf("sentinel config: %w", err)
	}
	if cfg.DataDir != "" {
		if err := hardenPrivateDir(cfg.DataDir); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("sentinel data_dir: %w", err)
		}
	}
	if cfg.HubSecretFile != "" {
		if err := hardenPrivateFile(cfg.HubSecretFile); err != nil {
			return fmt.Errorf("hub_secret_file: %w", err)
		}
	}
	return nil
}

// hubPushLogHost returns a low-leakage host label for logs (no path, no query).
func hubPushLogHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "(unset)"
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "(invalid)"
	}
	return u.Scheme + "://" + u.Host
}
