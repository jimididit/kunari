package sensor_test

import (
	"testing"

	"github.com/jimididit/kunari/internal/sensor"
)

func TestMatchAllowlist(t *testing.T) {
	list := sensor.DefaultAllowlist()
	for _, exe := range []string{
		`C:\Windows\System32\SearchProtocolHost.exe`,
		`C:/Windows/System32/SearchProtocolHost.exe`,
	} {
		ok, reason := sensor.MatchAllowlist(exe, list)
		if !ok || reason == "" {
			t.Fatalf("expected indexer match for %q, ok=%v reason=%q", exe, ok, reason)
		}
	}
	ok, reason := sensor.MatchAllowlist("/usr/bin/updatedb", list)
	if !ok || reason == "" {
		t.Fatalf("expected updatedb match, ok=%v reason=%q", ok, reason)
	}
	ok, _ = sensor.MatchAllowlist("/usr/bin/cat", list)
	if ok {
		t.Fatal("cat should not match")
	}
	// Basename alone must not silence alerts (renamed attacker binary).
	ok, _ = sensor.MatchAllowlist(`C:\Users\evil\SearchIndexer.exe`, list)
	if ok {
		t.Fatal("renamed attacker binary must not match default allowlist")
	}
	ok, _ = sensor.MatchAllowlist(`/home/evil/updatedb`, list)
	if ok {
		t.Fatal("updatedb outside /usr must not match")
	}
}
