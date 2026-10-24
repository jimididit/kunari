//go:build windows

package sensor

import "testing"

func TestNTPathResolverComponentBoundary(t *testing.T) {
	r := &ntPathResolver{devs: map[string]string{
		`\device\harddiskvolume3`:  `c:`,
		`\device\harddiskvolume30`: `d:`,
	}}
	got := r.toWin32(`\Device\HarddiskVolume30\foo\bar.env`)
	if got != `d:\foo\bar.env` {
		t.Fatalf("volume30: got %q", got)
	}
	got = r.toWin32(`\Device\HarddiskVolume3\foo\bar.env`)
	if got != `c:\foo\bar.env` {
		t.Fatalf("volume3: got %q", got)
	}
	// No separator after a shorter prefix must not map.
	r2 := &ntPathResolver{devs: map[string]string{
		`\device\harddiskvolume3`: `c:`,
	}}
	raw := `\Device\HarddiskVolume3foo\bar.env`
	if got := r2.toWin32(raw); got != raw {
		t.Fatalf("missing sep should leave path unchanged, got %q", got)
	}
}
