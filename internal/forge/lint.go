package forge

import (
	"fmt"
	"os"
	"strings"

	"github.com/jimididit/kunari/internal/safepath"
)

// LintResult reports static tells that may fingerprint Kunari artifacts.
type LintResult struct {
	Path     string
	Findings []string
}

func LintFile(path string) (*LintResult, error) {
	path, err := safepath.Clean(path)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path) // path cleaned by safepath.Clean
	if err != nil {
		return nil, err
	}
	r := &LintResult{Path: path}
	s := string(b)
	checks := []struct {
		name string
		bad  string
	}{
		{"thinkst marker", "HONEYDROP_TOKEN_URL"},
		{"canarytokens domain", "canarytokens.com"},
		{"canarytokens org", "canarytokens.org"},
		{"grabify", "grabify"},
		{"embedded slack webhook", "hooks.slack.com/services/"},
		{"embedded discord webhook", "discord.com/api/webhooks/"},
		{"ntlm-ish unc iconresource", "IconResource=\\\\"},
	}
	lower := strings.ToLower(s)
	for _, c := range checks {
		if strings.Contains(lower, strings.ToLower(c.bad)) || strings.Contains(s, c.bad) {
			r.Findings = append(r.Findings, fmt.Sprintf("%s: contains %q", c.name, c.bad))
		}
	}
	// Fake AWS keys in env files are expected decoys; flag only if they look like
	// well-known Thinkst canary prefixes when present without kunari decoy banner.
	if strings.Contains(s, "AKIA") && !strings.Contains(s, "AUTHORIZED TRIPWIRE") && !strings.Contains(s, "decoy") {
		r.Findings = append(r.Findings, "aws-key-shaped string without decoy banner")
	}
	return r, nil
}
