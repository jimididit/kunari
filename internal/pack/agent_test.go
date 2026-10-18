package pack

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/jimididit/kunari/internal/sensor"
)

func TestBuildAgentLinux(t *testing.T) {
	dir := t.TempDir()
	art := filepath.Join(dir, "bait.env")
	if err := os.WriteFile(art, []byte("SECRET=lab\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sec := filepath.Join(dir, "ingest.secret")
	if err := os.WriteFile(sec, []byte("0123456789abcdef0123456789abcdef\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "pack")
	if err := BuildAgent(AgentOptions{
		Target:        "linux",
		OutDir:        out,
		ArtifactPath:  art,
		TokenID:       "abcdabcdabcdabcd",
		HubURL:        "https://hub.example.com",
		HubSecretFile: sec,
	}); err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{
		"DEPLOY.md",
		"install.sh",
		"kunari-sentinel.service",
		"decoys/bait.env",
		"etc/sentinel.json",
		"etc/ingest.secret",
		"bin/README.txt",
	} {
		if _, err := os.Stat(filepath.Join(out, filepath.FromSlash(rel))); err != nil {
			t.Fatalf("missing %s: %v", rel, err)
		}
	}
	raw, err := os.ReadFile(filepath.Join(out, "etc", "sentinel.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg sensor.Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.HubURL != "https://hub.example.com" {
		t.Fatalf("hub %q", cfg.HubURL)
	}
	if len(cfg.Targets) != 1 || !strings.Contains(cfg.Targets[0].Path, "/opt/kunari-agent/decoys/bait.env") {
		t.Fatalf("target path %q", cfg.Targets[0].Path)
	}
	unit, _ := os.ReadFile(filepath.Join(out, "kunari-sentinel.service"))
	if !strings.Contains(string(unit), "User=kunari") {
		t.Fatal("unit missing User=kunari")
	}
	if runtime.GOOS != "windows" {
		st, err := os.Stat(filepath.Join(out, "install.sh"))
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm()&0o100 == 0 {
			t.Fatalf("install.sh should be executable, mode %04o", st.Mode().Perm())
		}
	}
}

func TestBuildAgentWindowsPaths(t *testing.T) {
	dir := t.TempDir()
	art := filepath.Join(dir, "bait.env")
	_ = os.WriteFile(art, []byte("x=1\n"), 0o600)
	out := filepath.Join(dir, "winpack")
	if err := BuildAgent(AgentOptions{
		Target:       "windows",
		OutDir:       out,
		ArtifactPath: art,
		TokenID:      "abcdabcdabcdabcd",
		HubURL:       "https://hub.example.com/",
	}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(out, "etc", "sentinel.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg sensor.Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	want := `C:\ProgramData\KunariAgent\decoys\bait.env`
	if cfg.Targets[0].Path != want {
		t.Fatalf("got %q want %q", cfg.Targets[0].Path, want)
	}
	if _, err := os.Stat(filepath.Join(out, "install.ps1")); err != nil {
		t.Fatal(err)
	}
}

func TestNormalizeTarget(t *testing.T) {
	if _, err := normalizeTarget("solaris"); err == nil {
		t.Fatal("expected error")
	}
	g, err := normalizeTarget("macOS")
	if err != nil || g != "darwin" {
		t.Fatalf("got %q %v", g, err)
	}
}
