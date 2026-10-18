package pack

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jimididit/kunari/internal/safepath"
	"github.com/jimididit/kunari/internal/sensor"
)

// AgentOptions builds a per-OS endpoint bundle: decoy(s), sentinel config, install script.
type AgentOptions struct {
	Target        string // linux | windows | darwin
	OutDir        string
	ArtifactPath  string
	TokenID       string
	Memo          string
	HubURL        string
	HubSecretFile string // optional; copied into pack as etc/ingest.secret
	InstallPrefix string // optional override of default install root
	BinaryName    string // optional; default kunari / kunari.exe
}

// BuildAgent writes an authorized-use agent package under OutDir.
func BuildAgent(opts AgentOptions) error {
	goos, err := normalizeTarget(opts.Target)
	if err != nil {
		return err
	}
	if opts.TokenID == "" || len(opts.TokenID) < 16 {
		return fmt.Errorf("--token is required (manifest token_id, at least 16 chars)")
	}
	if strings.TrimSpace(opts.HubURL) == "" {
		return fmt.Errorf("--hub-url is required")
	}
	art, err := safepath.Clean(opts.ArtifactPath)
	if err != nil {
		return fmt.Errorf("artifact: %w", err)
	}
	st, err := os.Stat(art)
	if err != nil {
		return fmt.Errorf("artifact: %w", err)
	}
	if st.IsDir() {
		return fmt.Errorf("artifact must be a file")
	}
	out, err := safepath.Clean(opts.OutDir)
	if err != nil {
		return err
	}
	prefix := opts.InstallPrefix
	if prefix == "" {
		prefix = defaultPrefix(goos)
	}
	binName := opts.BinaryName
	if binName == "" {
		if goos == "windows" {
			binName = "kunari.exe"
		} else {
			binName = "kunari"
		}
	}

	if err := os.MkdirAll(out, 0o700); err != nil {
		return err
	}
	for _, d := range []string{"bin", "decoys", "etc", "data"} {
		if err := os.MkdirAll(filepath.Join(out, d), 0o700); err != nil {
			return err
		}
	}

	base := filepath.Base(art)
	decoyDest := filepath.Join(out, "decoys", base)
	if err := copyFile(art, decoyDest, 0o600); err != nil {
		return fmt.Errorf("copy decoy: %w", err)
	}

	secretRel := "etc/ingest.secret"
	if opts.HubSecretFile != "" {
		sec, err := safepath.Clean(opts.HubSecretFile)
		if err != nil {
			return fmt.Errorf("hub-secret-file: %w", err)
		}
		if err := copyFile(sec, filepath.Join(out, filepath.FromSlash(secretRel)), 0o600); err != nil {
			return fmt.Errorf("copy hub secret: %w", err)
		}
	} else {
		placeholder := []byte("# Place hub ingest.secret here (hex), mode 0600.\n# Obtain from the hub data directory. Never embed in forged decoys.\n")
		if err := os.WriteFile(filepath.Join(out, filepath.FromSlash(secretRel)), placeholder, 0o600); err != nil {
			return err
		}
	}

	cfgPath := filepath.Join(out, "etc", "sentinel.json")
	cfg := sensor.Config{
		Targets: []sensor.Target{{
			Path:    targetJoin(goos, prefix, "decoys", base),
			TokenID: opts.TokenID,
			Memo:    opts.Memo,
		}},
		Allowlist:      sensor.DefaultAllowlist(),
		HeartbeatEvery: "60s",
		DataDir:        targetJoin(goos, prefix, "data"),
		KeyPath:        targetJoin(goos, prefix, "data", "signing.key"),
		AgentVersion:   "0.3.0",
		HubURL:         strings.TrimRight(opts.HubURL, "/"),
		HubSecretFile:  targetJoin(goos, prefix, "etc", "ingest.secret"),
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(cfgPath, append(b, '\n'), 0o600); err != nil {
		return err
	}

	binNote := filepath.Join(out, "bin", "README.txt")
	if err := os.WriteFile(binNote, []byte(binReadme(binName)), 0o600); err != nil {
		return err
	}

	deploy := deployMarkdown(goos, prefix, binName, base, opts.HubSecretFile != "")
	if err := os.WriteFile(filepath.Join(out, "DEPLOY.md"), []byte(deploy), 0o600); err != nil {
		return err
	}

	switch goos {
	case "linux":
		if err := os.WriteFile(filepath.Join(out, "install.sh"), []byte(linuxInstall(prefix, binName)), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(out, "kunari-sentinel.service"), []byte(linuxUnit(prefix, binName)), 0o600); err != nil {
			return err
		}
	case "darwin":
		if err := os.WriteFile(filepath.Join(out, "install.sh"), []byte(darwinInstall(prefix, binName)), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(out, "com.jimididit.kunari-sentinel.plist"), []byte(darwinPlist(prefix, binName)), 0o600); err != nil {
			return err
		}
	case "windows":
		if err := os.WriteFile(filepath.Join(out, "install.ps1"), []byte(windowsInstall(prefix, binName)), 0o600); err != nil {
			return err
		}
	}
	return nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	b, err := os.ReadFile(src) // #nosec G304 -- caller cleaned via safepath
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	return os.WriteFile(dst, b, mode)
}

func binReadme(binName string) string {
	return fmt.Sprintf(`Place the Kunari %s binary here before running the install script.

Download a release archive from https://github.com/jimididit/kunari/releases
matching this package's target OS/arch, or copy a locally built binary.

Authorized use only.
`, binName)
}
