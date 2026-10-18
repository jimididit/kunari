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

	art, err := buildArtifact(opt.Type, opt.Name, defaultStr(opt.Theme, "devops"), httpsURL, dnsName)
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(opt.OutDir, 0o755); err != nil {
		return nil, err
	}
	artPath := filepath.Join(opt.OutDir, art.Filename)
	if err := os.WriteFile(artPath, art.Content, 0o644); err != nil {
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
	if err := os.WriteFile(manPath, mb, 0o644); err != nil {
		return nil, err
	}

	install := renderInstall(m, art.Filename)
	instPath := filepath.Join(opt.OutDir, sanitizeName(opt.Name)+".INSTALL.md")
	if err := os.WriteFile(instPath, []byte(install), 0o644); err != nil {
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
		TokenID:      tokenID,
	}, nil
}

func renderInstall(m *registry.Manifest, filename string) string {
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
	b.WriteString("\n## Place\n\nCopy the artifact to the intended path on an authorized host. Record the path in your case notes / memo.\n")
	b.WriteString("\n## Sentinel (Phase 2+)\n\nWhen using `--detect sentinel|both`, configure `kunari sentinel` to watch the deployed path. Install commands for SACL/fanotify will be emitted in Phase 2.\n")
	b.WriteString("\n## Revoke\n\n`kunari revoke --token " + m.TokenID + "`\n")
	return b.String()
}

func defaultStr(s, d string) string {
	if s == "" {
		return d
	}
	return s
}
