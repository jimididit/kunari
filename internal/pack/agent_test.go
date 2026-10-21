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
	deployLinux, err := os.ReadFile(filepath.Join(out, "DEPLOY.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(deployLinux), "--detect both") || !strings.Contains(string(deployLinux), "Dual-layer") {
		t.Fatal("DEPLOY.md should document dual-layer / --detect both")
	}
	unit, _ := os.ReadFile(filepath.Join(out, "kunari-sentinel.service"))
	unitBody := string(unit)
	if !strings.Contains(unitBody, "User=kunari") {
		t.Fatal("unit missing User=kunari")
	}
	if !strings.Contains(unitBody, "Environment=KUNARI_SENTINEL_CONFIG=") {
		t.Fatal("unit should set KUNARI_SENTINEL_CONFIG (avoid config path in argv)")
	}
	if strings.Contains(unitBody, "sentinel run --config") {
		t.Fatal("unit ExecStart should not pass --config when env is set")
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
	sh := linuxInstall("/home/jdi/kunari-agent", "kunari", "kunari-sentinel")
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
	if !strings.Contains(body, "Register-ScheduledTask") {
		t.Fatal("windows install should use Register-ScheduledTask (kunari.exe is not a Windows Service)")
	}
	if !strings.Contains(body, "run-sentinel.cmd") || !strings.Contains(body, "KUNARI_SENTINEL_CONFIG") {
		t.Fatal("windows install should launch via run-sentinel.cmd with KUNARI_SENTINEL_CONFIG")
	}
	if strings.Contains(body, "sentinel run --config") {
		t.Fatal("windows task should not put --config on kunari.exe argv")
	}
	if strings.Contains(body, "sc.exe create") || strings.Contains(body, "Start-Service KunariSentinel") {
		t.Fatal("windows install must not register kunari.exe as an sc.exe service")
	}
	if strings.Contains(body, "2>$null") {
		t.Fatal("windows install must not use native 2>$null under ErrorActionPreference=Stop")
	}
	if !strings.Contains(body, "GetFileNameWithoutExtension($BinName)") {
		t.Fatal("windows install should derive process name from $BinName")
	}
	if idxStop, idxCopy := strings.Index(body, "Unregister-ScheduledTask"), strings.Index(body, "Copy-Item -LiteralPath $BinSrc"); idxStop < 0 || idxCopy < 0 || idxStop > idxCopy {
		t.Fatal("unregister prior task must happen before binary copy")
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
	if !strings.Contains(string(deploy), "Dual-layer") || !strings.Contains(string(deploy), "--detect both") {
		t.Fatal("DEPLOY.md should recommend forge --detect both")
	}
}

func TestBuildAgentWarnsOnSentinelOnlyManifest(t *testing.T) {
	dir := t.TempDir()
	art := filepath.Join(dir, "bait.env")
	if err := os.WriteFile(art, []byte("SECRET=lab\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	man := `{"schema":"kunari.manifest/1","token_id":"abcdabcdabcdabcd","name":"bait","type":"env","detect":"sentinel"}`
	if err := os.WriteFile(filepath.Join(dir, "bait.manifest.json"), []byte(man), 0o600); err != nil {
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
	deploy, err := os.ReadFile(filepath.Join(out, "DEPLOY.md"))
	if err != nil {
		t.Fatal(err)
	}
	body := string(deploy)
	if !strings.Contains(body, `detect="sentinel"`) && !strings.Contains(body, "detect=sentinel") {
		t.Fatal("DEPLOY.md should warn when sibling manifest is not detect=both")
	}
	if !strings.Contains(body, "--detect both") {
		t.Fatal("DEPLOY.md should still recommend --detect both")
	}
}

func TestDetectFromSiblingManifest(t *testing.T) {
	dir := t.TempDir()
	art := filepath.Join(dir, "x.env")
	if err := os.WriteFile(art, []byte("a=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "x.manifest.json"), []byte(`{"detect":"both"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := detectFromSiblingManifest(art); got != "both" {
		t.Fatalf("got %q", got)
	}
	if got := detectFromSiblingManifest(filepath.Join(dir, "missing.env")); got != "" {
		t.Fatalf("want empty, got %q", got)
	}
}

func TestBuildAgentCustomNames(t *testing.T) {
	dir := t.TempDir()
	art := filepath.Join(dir, "bait.env")
	sec := filepath.Join(dir, "ingest.secret")
	_ = os.WriteFile(art, []byte("x=1\n"), 0o600)
	_ = os.WriteFile(sec, []byte("0123456789abcdef0123456789abcdef\n"), 0o600)
	out := filepath.Join(dir, "pack")
	if err := BuildAgent(AgentOptions{
		Target:        "linux",
		OutDir:        out,
		ArtifactPath:  art,
		TokenID:       "abcdabcdabcdabcd",
		HubURL:        "https://hub.example.com",
		HubSecretFile: sec,
		BinaryName:    "acme-tripwire",
		UnitName:      "acme-tripwire",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(out, "acme-tripwire.service")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(out, "kunari-sentinel.service")); err == nil {
		t.Fatal("default unit file should not be written when --unit-name is set")
	}
	sh, err := os.ReadFile(filepath.Join(out, "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	body := string(sh)
	if !strings.Contains(body, "acme-tripwire") || !strings.Contains(body, "UNIT_NAME=") {
		t.Fatal("install.sh should use custom binary/unit names")
	}
	if !strings.Contains(body, "kunari-sentinel.service") {
		t.Fatal("install.sh should still clean up legacy kunari-sentinel unit")
	}
	deploy, _ := os.ReadFile(filepath.Join(out, "DEPLOY.md"))
	if !strings.Contains(string(deploy), "acme-tripwire.service") {
		t.Fatal("DEPLOY.md should mention custom unit")
	}
}

func TestBuildAgentRejectsDeniedBinaryName(t *testing.T) {
	dir := t.TempDir()
	art := filepath.Join(dir, "bait.env")
	sec := filepath.Join(dir, "ingest.secret")
	_ = os.WriteFile(art, []byte("x=1\n"), 0o600)
	_ = os.WriteFile(sec, []byte("0123456789abcdef0123456789abcdef\n"), 0o600)
	err := BuildAgent(AgentOptions{
		Target:        "windows",
		OutDir:        filepath.Join(dir, "pack"),
		ArtifactPath:  art,
		TokenID:       "abcdabcdabcdabcd",
		HubURL:        "https://hub.example.com",
		HubSecretFile: sec,
		BinaryName:    "svchost",
	})
	if err == nil {
		t.Fatal("expected denied binary name")
	}
	if !strings.Contains(err.Error(), "denied") {
		t.Fatalf("error should mention denied: %v", err)
	}
}

func TestBuildAgentWindowsCustomTask(t *testing.T) {
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
		HubURL:        "https://hub.example.com",
		HubSecretFile: sec,
		BinaryName:    "AcmeWatch",
		UnitName:      "AcmeWatchTask",
	}); err != nil {
		t.Fatal(err)
	}
	ps1, err := os.ReadFile(filepath.Join(out, "install.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	body := string(ps1)
	if !strings.Contains(body, "$BinName = 'AcmeWatch.exe'") {
		t.Fatalf("expected auto .exe suffix, got snippet missing; body has BinName? %v", strings.Contains(body, "AcmeWatch"))
	}
	if !strings.Contains(body, "$TaskName = 'AcmeWatchTask'") {
		t.Fatal("custom task name missing")
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
