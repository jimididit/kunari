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

func TestBuildAgentRequiresIngestFile(t *testing.T) {
	dir := t.TempDir()
	art := filepath.Join(dir, "bait.env")
	_ = os.WriteFile(art, []byte("x=1\n"), 0o600)
	err := BuildAgent(AgentOptions{
		Target:       "linux",
		OutDir:       filepath.Join(dir, "pack"),
		ArtifactPath: art,
		TokenID:      "abcdabcdabcdabcd",
		HubURL:       "https://hub.example.com",
	})
	if err == nil {
		t.Fatal("expected error without hub-secret-file")
	}
}

func TestBuildAgentRejectsUnsafePrefix(t *testing.T) {
	dir := t.TempDir()
	art := filepath.Join(dir, "bait.env")
	sec := filepath.Join(dir, "ingest.secret")
	_ = os.WriteFile(art, []byte("x=1\n"), 0o600)
	_ = os.WriteFile(sec, []byte("0123456789abcdef0123456789abcdef\n"), 0o600)
	err := BuildAgent(AgentOptions{
		Target:        "linux",
		OutDir:        filepath.Join(dir, "pack"),
		ArtifactPath:  art,
		TokenID:       "abcdabcdabcdabcd",
		HubURL:        "https://hub.example.com",
		HubSecretFile: sec,
		InstallPrefix: "/tmp/kunari; curl evil.test",
	})
	if err == nil {
		t.Fatal("expected unsafe prefix rejection")
	}
}

func TestBuildAgentRejectsLinuxHomePrefix(t *testing.T) {
	dir := t.TempDir()
	art := filepath.Join(dir, "bait.env")
	sec := filepath.Join(dir, "ingest.secret")
	_ = os.WriteFile(art, []byte("x=1\n"), 0o600)
	_ = os.WriteFile(sec, []byte("0123456789abcdef0123456789abcdef\n"), 0o600)
	err := BuildAgent(AgentOptions{
		Target:        "linux",
		OutDir:        filepath.Join(dir, "pack"),
		ArtifactPath:  art,
		TokenID:       "abcdabcdabcdabcd",
		HubURL:        "https://hub.example.com",
		HubSecretFile: sec,
		InstallPrefix: "/home/jdi/kunari-agent",
	})
	if err == nil {
		t.Fatal("expected /home prefix rejection")
	}
	if !strings.Contains(err.Error(), "/home") {
		t.Fatalf("error should mention /home: %v", err)
	}
	sh := linuxInstall("/home/jdi/kunari-agent", "kunari")
	if !strings.Contains(sh, "/home/*") {
		t.Fatal("install.sh should guard against /home prefixes at runtime")
	}
}

func TestBuildAgentWindowsPaths(t *testing.T) {
	dir := t.TempDir()
	art := filepath.Join(dir, "bait.env")
	sec := filepath.Join(dir, "ingest.secret")
	_ = os.WriteFile(art, []byte("x=1\n"), 0o600)
	_ = os.WriteFile(sec, []byte("0123456789abcdef0123456789abcdef\n"), 0o600)
	out := filepath.Join(dir, "winpack")
	if err := BuildAgent(AgentOptions{
		Target:        "windows",
		OutDir:        out,
		ArtifactPath:  art,
		TokenID:       "abcdabcdabcdabcd",
		HubURL:        "https://hub.example.com/",
		HubSecretFile: sec,
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
	ps1, err := os.ReadFile(filepath.Join(out, "install.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	body := string(ps1)
	if !strings.Contains(body, "schtasks.exe /Create") {
		t.Fatal("windows install should use schtasks (kunari.exe is not a Windows Service)")
	}
	if strings.Contains(body, "sc.exe create") || strings.Contains(body, "Start-Service KunariSentinel") {
		t.Fatal("windows install must not register kunari.exe as an sc.exe service")
	}
	if idxStop, idxCopy := strings.Index(body, "schtasks.exe /End"), strings.Index(body, "Copy-Item -LiteralPath $BinSrc"); idxStop < 0 || idxCopy < 0 || idxStop > idxCopy {
		t.Fatal("stop prior task must happen before binary copy")
	}
	if !strings.Contains(body, "icacls") {
		t.Fatal("windows install should set ACLs")
	}
	deploy, err := os.ReadFile(filepath.Join(out, "DEPLOY.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(deploy), "scheduled task") {
		t.Fatal("DEPLOY.md should document scheduled task install")
	}
}

func TestShQuote(t *testing.T) {
	if got := shQuote(`o'reilly`); got != `'o'"'"'reilly'` {
		t.Fatalf("got %q", got)
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
