//go:build windows

package sensor

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenBestWindowsOrder(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bait.env")
	if err := os.WriteFile(path, []byte("x=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	targets := []Target{{Path: path, TokenID: "abcdabcdabcdabcd"}}
	w, err := openBestWindows(targets, []string{string(TierWinETW)})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	switch w.Tier() {
	case TierWinETW, TierWinSACL, TierWinRDC:
		// ETW when elevated; otherwise SACL/RDC fallback.
	default:
		t.Fatalf("unexpected tier %q", w.Tier())
	}
}
