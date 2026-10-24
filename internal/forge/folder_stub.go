package forge

import (
	"archive/zip"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// buildFolder returns a portable zip plus DirFiles so forge can materialize
// a real directory under --out. Prefer sentinel watch on secrets.env (file
// open/read/modify). Directory browse is weaker and tier-dependent.
// UNC desktop.ini IconResource is omitted (ADR-0005 / NTLM risk).
func buildFolder(name, theme, httpsURL, dnsName string) (*Artifact, error) {
	if httpsURL == "" && dnsName == "" {
		return nil, fmt.Errorf("folder requires --collector and/or --collector-dns (for the inner secrets.env)")
	}
	dirName := sanitizeName(name)
	envArt, err := buildEnv(name+"-inner", theme, httpsURL, dnsName)
	if err != nil {
		return nil, err
	}
	// Bland folder contents only - no operator/tripwire language on the endpoint.
	notes := strings.TrimSpace(themeFiller(theme, name)) + "\n\n" +
		"Export from payroll system. Keep secrets.env private.\n" +
		"Contact finance-ops if this archive is out of date.\n"
	desktop := "[.ShellClassInfo]\r\nConfirmFileOp=0\r\n" +
		"InfoTip=Finance archive - internal use only\r\n"

	dirFiles := map[string][]byte{
		"NOTES.txt":   []byte(notes),
		"secrets.env": envArt.Content,
		"desktop.ini": []byte(desktop),
	}
	zipMap := make(map[string][]byte, len(dirFiles))
	for rel, content := range dirFiles {
		zipMap[dirName+"/"+rel] = content
	}
	z, err := zipBytes(zipMap)
	if err != nil {
		return nil, err
	}
	return &Artifact{
		Filename: dirName + "-folder.zip",
		Content:  z,
		DirName:  dirName,
		DirFiles: dirFiles,
	}, nil
}

// buildStubExe cross-compiles a harmless stub that GETs the HTTPS beacon once and exits.
// No persistence, no arguments, no network besides that single request.
func buildStubExe(name, httpsURL string, platforms []string) (*Artifact, error) {
	if httpsURL == "" {
		return nil, fmt.Errorf("stub-exe requires --collector HTTPS URL")
	}
	if len(platforms) == 0 {
		platforms = []string{"windows", "linux", "macos"}
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		return nil, fmt.Errorf("stub-exe needs the Go toolchain on PATH to build stubs: %w", err)
	}
	tmp, err := os.MkdirTemp("", "kunari-stub-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)

	src := filepath.Join(tmp, "main.go")
	body := fmt.Sprintf(`package main

import (
	"net/http"
	"os"
	"time"
)

// One-shot HTTPS GET to STATUS_URL, then exit.
func main() {
	u := %q
	c := &http.Client{Timeout: 15 * time.Second}
	resp, err := c.Get(u)
	if err == nil {
		_ = resp.Body.Close()
	}
	os.Exit(0)
}
`, httpsURL)
	if err := os.WriteFile(src, []byte(body), 0o600); err != nil {
		return nil, err
	}

	files := map[string][]byte{
		"README.txt": []byte("CDN reachability helpers\n\n" +
			"Each binary performs a single HTTPS GET to the configured status URL, then exits.\n" +
			"No installers, no background services. For ops connectivity checks only.\n"),
	}
	base := sanitizeName(name)
	for _, p := range platforms {
		goos, goarch, outName, err := stubTarget(p, base)
		if err != nil {
			return nil, err
		}
		outPath := filepath.Join(tmp, outName)
		cmd := exec.Command(goBin, "build", "-trimpath", "-ldflags=-s -w", "-o", outPath, src) // #nosec G204 -- fixed go toolchain argv; src under temp dir we created
		cmd.Env = append(os.Environ(),
			"GOOS="+goos,
			"GOARCH="+goarch,
			"CGO_ENABLED=0",
		)
		cmd.Dir = tmp
		if out, err := cmd.CombinedOutput(); err != nil {
			return nil, fmt.Errorf("build stub %s/%s: %w: %s", goos, goarch, err, truncateBytes(out, 400))
		}
		bin, err := os.ReadFile(outPath) // #nosec G304 -- path under our temp dir
		if err != nil {
			return nil, err
		}
		files[goos+"-"+goarch+"/"+outName] = bin
	}
	z, err := zipBytes(files)
	if err != nil {
		return nil, err
	}
	return &Artifact{Filename: base + "-stubs.zip", Content: z}, nil
}

func stubTarget(platform, base string) (goos, goarch, outName string, err error) {
	switch platform {
	case "windows":
		return "windows", "amd64", base + ".exe", nil
	case "linux":
		return "linux", "amd64", base, nil
	case "macos":
		return "darwin", "amd64", base, nil
	default:
		return "", "", "", fmt.Errorf("unsupported stub platform %q", platform)
	}
}

func zipBytes(files map[string][]byte) ([]byte, error) {
	buf := new(bytes.Buffer)
	zw := zip.NewWriter(buf)
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(content); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func truncateBytes(b []byte, n int) string {
	s := string(b)
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
