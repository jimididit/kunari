package cli

import (
	"os"
	"strings"
)

const sentinelConfigEnv = "KUNARI_SENTINEL_CONFIG"

// resolveSentinelConfigPath picks --config, then KUNARI_SENTINEL_CONFIG, then sentinel.json.
// Prefer the env var in service units so argv need not expose the config path.
func resolveSentinelConfigPath(flag string) string {
	if s := strings.TrimSpace(flag); s != "" {
		return s
	}
	if s := strings.TrimSpace(os.Getenv(sentinelConfigEnv)); s != "" {
		return s
	}
	return "sentinel.json"
}

func stdoutIsCharDevice() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
