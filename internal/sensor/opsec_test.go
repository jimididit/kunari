package sensor

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestHubPushLogHost(t *testing.T) {
	if got := hubPushLogHost("https://beacon.example.com:8443/api/v1/ingest?x=1"); got != "https://beacon.example.com:8443" {
		t.Fatalf("got %q", got)
	}
	if got := hubPushLogHost("http://127.0.0.1:8080"); got != "http://127.0.0.1:8080" {
		t.Fatalf("got %q", got)
	}
	if got := hubPushLogHost(""); got != "(unset)" {
		t.Fatalf("got %q", got)
	}
}

func TestHardenPrivateFileUnix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permission bits")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "sentinel.json")
	if err := os.WriteFile(path, []byte(`{"targets":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := hardenPrivateFile(path); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm()&0o077 != 0 {
		t.Fatalf("want private mode, got %04o", st.Mode().Perm())
	}
}

func TestWriteExampleConfigPrivate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.json")
	if err := WriteExampleConfig(path, []Target{{Path: filepath.Join(dir, "decoy.env"), TokenID: "tok"}}, "", ""); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		return
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm()&0o077 != 0 {
		t.Fatalf("want private mode, got %04o", st.Mode().Perm())
	}
}

func TestLoadConfigHardensPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permission bits")
	}
	dir := t.TempDir()
	decoy := filepath.Join(dir, "decoy.env")
	if err := os.WriteFile(decoy, []byte("x=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "sentinel.json")
	body := []byte(`{"targets":[{"Path":"` + filepath.ToSlash(decoy) + `","TokenID":"abcdabcdabcdabcd","Memo":""}],"data_dir":"` + filepath.ToSlash(filepath.Join(dir, "data")) + `","heartbeat_every":"60s"}`)
	if err := os.WriteFile(cfgPath, body, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(cfgPath); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm()&0o077 != 0 {
		t.Fatalf("LoadConfig should chmod config to 0600, got %04o", st.Mode().Perm())
	}
}
