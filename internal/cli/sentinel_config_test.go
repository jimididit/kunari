package cli

import (
	"testing"
)

func TestResolveSentinelConfigPath(t *testing.T) {
	t.Setenv(sentinelConfigEnv, "")
	if got := resolveSentinelConfigPath(""); got != "sentinel.json" {
		t.Fatalf("default: got %q", got)
	}
	if got := resolveSentinelConfigPath(" ./cfg.json "); got != "./cfg.json" {
		t.Fatalf("flag: got %q", got)
	}
	t.Setenv(sentinelConfigEnv, "/opt/kunari-agent/etc/sentinel.json")
	if got := resolveSentinelConfigPath(""); got != "/opt/kunari-agent/etc/sentinel.json" {
		t.Fatalf("env: got %q", got)
	}
	if got := resolveSentinelConfigPath("/explicit.json"); got != "/explicit.json" {
		t.Fatalf("flag wins over env: got %q", got)
	}
}
