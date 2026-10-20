package forge

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jimididit/kunari/internal/beacon"
	"github.com/jimididit/kunari/internal/collect"
	kcrypto "github.com/jimididit/kunari/internal/crypto"
	"github.com/jimididit/kunari/internal/registry"
)

type Result struct {
	ManifestPath string
	ArtifactPath string
	InstallPath  string
	DirPath      string // materialized folder directory (type=folder), else empty
	TokenID      string
}

func Run(opt Options) (*Result, error) {
	if err := registry.EnsureAuthz(opt.AuthzRef); err != nil {
		return nil, err
	}
	if opt.Name == "" {
		return nil, fmt.Errorf("--name is required")
	}
	if opt.Type == "" {
		return nil, fmt.Errorf("--type is required")
	}
	detect := opt.Detect
	if detect == "" {
		detect = "both"
	}
	switch detect {
	case "beacon", "sentinel", "both":
	default:
		return nil, fmt.Errorf("invalid --detect %q", detect)
	}
	if detect != "sentinel" && opt.Collector == "" && opt.CollectorDNS == "" {
		return nil, fmt.Errorf("beacon/both requires --collector and/or --collector-dns")
	}
	lvl, err := collect.Parse(defaultStr(opt.Collect, "standard"))
	if err != nil {
		return nil, err
	}
	platArg := "all"
	if len(opt.Platforms) > 0 {
		platArg = strings.Join(opt.Platforms, ",")
	}
	platforms, err := ParsePlatforms(platArg)
	if err != nil {
		return nil, err
	}

	keys, err := kcrypto.LoadOrCreate(opt.KeyPath)
	if err != nil {
		return nil, err
	}
	tokenID, err := beacon.NewTokenID()
	if err != nil {
		return nil, err
	}

	var httpsURL, dnsName string
	if opt.Collector != "" {
		httpsURL, err = beacon.HTTPSURL(opt.Collector, tokenID)
		if err != nil {
			return nil, err
		}
	}
	if opt.CollectorDNS != "" {
		dnsName, err = beacon.DNSName(opt.CollectorDNS, tokenID)
		if err != nil {
			return nil, err
		}
	}

	art, err := buildArtifact(opt.Type, opt.Name, defaultStr(opt.Theme, "devops"), httpsURL, dnsName, platforms)
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(opt.OutDir, 0o750); err != nil {
		return nil, err
	}
	artPath := filepath.Join(opt.OutDir, art.Filename)
	// Owner-readable decoy; operators may chmod for multi-user lab hosts.
	if err := os.WriteFile(artPath, art.Content, 0o600); err != nil {
		return nil, err
	}
	dirPath, err := materializeDir(opt.OutDir, art)
	if err != nil {
		return nil, err
	}

	m := &registry.Manifest{
		TokenID:        tokenID,
		Name:           opt.Name,
		Type:           opt.Type,
		Platforms:      platforms,
		Detect:         detect,
		Collect:        string(lvl),
		Memo:           opt.Memo,
		AuthzRef:       opt.AuthzRef,
		ArtifactSHA256: registry.HashBytes(art.Content),
		BeaconHTTPS:    httpsURL,
		BeaconDNS:      dnsName,
		CreatedAt:      time.Now().UTC(),
		Tags:           opt.Tags,
	}
	if opt.Expire > 0 {
		exp := m.CreatedAt.Add(opt.Expire)
		m.ExpiresAt = &exp
	}
	if err := m.Sign(keys); err != nil {
		return nil, err
	}

	manPath := filepath.Join(opt.OutDir, sanitizeName(opt.Name)+".manifest.json")
	mb, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(manPath, mb, 0o600); err != nil {
		return nil, err
	}

	install := renderInstall(m, art.Filename, art.DirName)
	instPath := filepath.Join(opt.OutDir, sanitizeName(opt.Name)+".INSTALL.md")
	if err := os.WriteFile(instPath, []byte(install), 0o600); err != nil {
		return nil, err
	}

	if opt.RegistryDB != "" {
		st, err := registry.Open(opt.RegistryDB)
		if err != nil {
			return nil, err
		}
		defer st.Close()
		if err := st.Put(m); err != nil {
			return nil, err
		}
	}

	return &Result{
		ManifestPath: manPath,
		ArtifactPath: artPath,
		InstallPath:  instPath,
		DirPath:      dirPath,
		TokenID:      tokenID,
	}, nil
}

func materializeDir(outDir string, art *Artifact) (string, error) {
	if art == nil || art.DirName == "" || len(art.DirFiles) == 0 {
		return "", nil
	}
	if err := validateRelName(art.DirName); err != nil {
		return "", fmt.Errorf("folder dir name: %w", err)
	}
	outAbs, err := filepath.Abs(outDir)
	if err != nil {
		return "", err
	}
	root := filepath.Join(outAbs, art.DirName)
	if !underDir(outAbs, root) {
		return "", fmt.Errorf("folder dir %q escapes output directory", art.DirName)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", err
	}
	for rel, content := range art.DirFiles {
		rel = filepath.ToSlash(filepath.Clean(rel))
		if err := validateRelName(rel); err != nil {
			return "", fmt.Errorf("folder entry: %w", err)
		}
		dst := filepath.Join(root, filepath.FromSlash(rel))
		if !underDir(root, dst) {
			return "", fmt.Errorf("folder entry %q escapes directory", rel)
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return "", err
		}
		mode := os.FileMode(0o600)
		if strings.EqualFold(filepath.Base(rel), "desktop.ini") {
			mode = 0o644
		}
		if err := os.WriteFile(dst, content, mode); err != nil {
			return "", err
		}
	}
	return root, nil
}

// validateRelName rejects absolute paths, empty names, and any ".." segment.
func validateRelName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" || name == "." {
		return fmt.Errorf("empty path")
	}
	if filepath.IsAbs(name) || filepath.VolumeName(name) != "" {
		return fmt.Errorf("absolute path %q", name)
	}
	clean := filepath.ToSlash(filepath.Clean(name))
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return fmt.Errorf("path escapes parent %q", name)
	}
	for _, part := range strings.Split(clean, "/") {
		if part == ".." {
			return fmt.Errorf("path escapes parent %q", name)
		}
	}
	return nil
}

func underDir(parent, child string) bool {
	parent = filepath.Clean(parent)
	child = filepath.Clean(child)
	if parent == child {
		return true
	}
	sep := string(filepath.Separator)
	return strings.HasPrefix(child, parent+sep)
}

func renderInstall(m *registry.Manifest, filename, dirName string) string {
	var b strings.Builder
	b.WriteString("# Kunari tripwire install notes\n\n")
	b.WriteString("**Authorized use only.** " + registry.AuthorizedUseNotice + "\n\n")
	b.WriteString(fmt.Sprintf("- token_id: `%s`\n", m.TokenID))
	b.WriteString(fmt.Sprintf("- artifact: `%s` (sha256 `%s`)\n", filename, m.ArtifactSHA256))
	b.WriteString(fmt.Sprintf("- detect: `%s`\n", m.Detect))
	b.WriteString(fmt.Sprintf("- authz-ref: `%s`\n", m.AuthzRef))
	if m.BeaconHTTPS != "" {
		b.WriteString(fmt.Sprintf("- beacon HTTPS: `%s`\n", m.BeaconHTTPS))
	}
	if m.BeaconDNS != "" {
		b.WriteString(fmt.Sprintf("- beacon DNS: `%s`\n", m.BeaconDNS))
	}
	b.WriteString("\n## Place\n\n")
	switch m.Type {
	case "folder":
		if dirName == "" {
			dirName = "decoy-folder"
		}
		b.WriteString("Forge writes both `" + filename + "` (portable zip) and a materialized directory `" + dirName + "/` under `--out`.\n")
		b.WriteString("Copy the directory (or extract the zip) onto an authorized host.\n")
		b.WriteString("**Recommended sentinel target:** `" + dirName + "/secrets.env` - same open/read/modify behavior as a normal env decoy.\n")
		b.WriteString("Watching the directory path itself is weaker: browse/list detection is tier-dependent and not equivalent to watching a file.\n")
		b.WriteString("Kunari does **not** emit UNC `desktop.ini` IconResource beacons (NTLM risk).\n")
		b.WriteString("For `kunari package agent`, pass the `secrets.env` file path (agent packs require a file decoy today).\n")
	case "stub-exe":
		b.WriteString("Extract `" + filename + "` and run the stub binary for the endpoint OS once in an authorized lab. " +
			"It performs a single HTTPS GET to the beacon URL and exits. No persistence.\n")
	default:
		b.WriteString("Copy the artifact to the intended path on an authorized host. Record the path in your case notes / memo.\n")
	}
	b.WriteString("\n## Sentinel\n\n")
	if m.Detect == "sentinel" || m.Detect == "both" {
		watchPath := "/path/to/" + filename
		if m.Type == "folder" {
			if dirName == "" {
				dirName = "decoy-folder"
			}
			watchPath = "/path/to/" + dirName + "/secrets.env"
		}
		if m.Type == "stub-exe" {
			watchPath = "/path/to/stub-binary"
		}
		b.WriteString("```bash\n")
		b.WriteString("kunari sentinel init-config --path " + shellQuote(watchPath) +
			" --token " + shellQuote(m.TokenID) +
			" --memo " + shellQuote(m.Memo) +
			" --out sentinel.json\n")
		b.WriteString("kunari sentinel install-hints --config sentinel.json\n")
		b.WriteString("kunari sentinel run --config sentinel.json\n")
		b.WriteString("```\n")
		b.WriteString("The sensor prints the armed detection tier at startup. Prefer fanotify (Linux) or win-sacl-4663 (Windows) when privileges allow.\n")
		if m.Detect == "both" {
			b.WriteString("\nDual-layer: for a packaged endpoint install, use `kunari package agent` with this decoy so beacons remain if the sentinel is stopped.\n")
		} else {
			b.WriteString("\nNote: `--detect sentinel` is agent-only. Prefer `--detect both` so HTTPS/DNS beacons can still fire if the process is killed.\n")
		}
	} else {
		b.WriteString("`--detect beacon` only: no host sensor required. Do not use `kunari package agent` for beacon-max deploys.\n")
		if m.Type == "folder" {
			b.WriteString("Folder browse without a sentinel usually will not alert; prefer `--detect both` and watch `secrets.env`.\n")
		}
	}
	b.WriteString("\n## Revoke\n\n`kunari revoke --token " + shellQuote(m.TokenID) + "`\n")
	return b.String()
}

// shellQuote returns a POSIX single-quoted string safe against $, `, !, and spaces.
// strconv.Quote (Go double quotes) is NOT used: bash still expands $(...) inside "...".
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func defaultStr(s, d string) string {
	if s == "" {
		return d
	}
	return s
}
