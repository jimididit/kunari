package sensor_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/jimididit/kunari/internal/sensor"
)

// Unprivileged sentinel smoke: arm best available tier, touch decoy, expect a recorded event.
// Does not require fanotify / win-sacl-4663 / FDA - suitable for GHA runners.
func TestUnprivilegedSentinelTouchE2E(t *testing.T) {
	dir := t.TempDir()
	decoy := filepath.Join(dir, "decoy.env")
	if err := os.WriteFile(decoy, []byte("KUNARI_SMOKE=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dataDir := filepath.Join(dir, "data")
	cfgPath := filepath.Join(dir, "sentinel.json")
	cfg := &sensor.Config{
		Targets: []sensor.Target{{
			Path:    decoy,
			TokenID: "abcdabcdabcdabcd",
			Memo:    "ci-smoke",
		}},
		Allowlist:      sensor.DefaultAllowlist(),
		HeartbeatEvery: "1h",
		DataDir:        dataDir,
		KeyPath:        filepath.Join(dataDir, "signing.key"),
		AgentVersion:   "ci-smoke",
	}
	if err := sensor.WriteExampleConfig(cfgPath, cfg.Targets, "", ""); err != nil {
		t.Fatal(err)
	}
	// Reload through LoadConfig so HardenSensitivePaths runs (Windows ACL + Unix modes).
	loaded, err := sensor.LoadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	loaded.DataDir = dataDir
	loaded.KeyPath = filepath.Join(dataDir, "signing.key")
	loaded.HeartbeatEvery = "1h"
	loaded.Targets = cfg.Targets

	r, err := sensor.NewRunner(loaded, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	tier := r.Watcher.Tier()
	switch runtime.GOOS {
	case "linux":
		if tier != sensor.TierInotify && tier != sensor.TierFanotify {
			t.Fatalf("unexpected linux tier %q", tier)
		}
	case "windows":
		if tier != sensor.TierWinRDC && tier != sensor.TierWinSACL {
			t.Fatalf("unexpected windows tier %q", tier)
		}
	case "darwin":
		if tier != sensor.TierMacFSEvents && tier != sensor.TierMacESLogger {
			t.Fatalf("unexpected darwin tier %q", tier)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- r.Run(ctx) }()

	// Allow watcher to arm.
	time.Sleep(300 * time.Millisecond)

	switch runtime.GOOS {
	case "windows":
		// win-rdc sees modify/delete/rename, not plain reads.
		f, err := os.OpenFile(decoy, os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteString("# touch\n"); err != nil {
			_ = f.Close()
			t.Fatal(err)
		}
		_ = f.Close()
	default:
		b, err := os.ReadFile(decoy)
		if err != nil {
			t.Fatal(err)
		}
		if len(b) == 0 {
			t.Fatal("empty decoy")
		}
	}

	eventsPath := filepath.Join(dataDir, "events.jsonl")
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		st, err := os.Stat(eventsPath)
		if err == nil && st.Size() > 0 {
			cancel()
			select {
			case <-errCh:
			case <-time.After(2 * time.Second):
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	t.Fatalf("no events recorded under tier=%s (os=%s)", tier, runtime.GOOS)
}
