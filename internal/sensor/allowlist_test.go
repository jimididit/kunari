package sensor_test

import (
	"testing"

	"github.com/jimididit/kunari/internal/sensor"
)

func TestMatchAllowlist(t *testing.T) {
	list := sensor.DefaultAllowlist()
	ok, reason := sensor.MatchAllowlist(`C:\Windows\System32\SearchProtocolHost.exe`, list)
	if !ok || reason == "" {
		t.Fatalf("expected indexer match, ok=%v reason=%q", ok, reason)
	}
	ok, _ = sensor.MatchAllowlist("/usr/bin/cat", list)
	if ok {
		t.Fatal("cat should not match")
	}
}
