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
	b, err := os.ReadFile(path) // #nosec G304 -- path cleaned by safepath.Clean
	if err != nil {
		return nil, err
	}
	r := &LintResult{Path: path}
	// Match needles against lowercased content so mixed-case banners still hit.
	// bad strings below are stored lowercase on purpose.
	lower := strings.ToLower(string(b))
	checks := []struct {
		name string
		bad  string
	}{
		{"thinkst marker", "honeydrop_token_url"},
		{"canarytokens domain", "canarytokens.com"},
		{"canarytokens org", "canarytokens.org"},
		{"grabify", "grabify"},
		{"embedded slack webhook", "hooks.slack.com/services/"},
		{"embedded discord webhook", "discord.com/api/webhooks/"},
		{"ntlm-ish unc iconresource", `iconresource=\`},
		// In-band banners are endpoint giveaways - forge must not emit these.
		{"tripwire banner", "authorized tripwire"},
		{"decoy credentials banner", "decoy credentials"},
		{"tripwire folder banner", "tripwire folder"},
		{"kunari sentinel hint", "kunari sentinel"},
	}
	for _, c := range checks {
		if strings.Contains(lower, c.bad) {
			r.Findings = append(r.Findings, fmt.Sprintf("%s: contains %q", c.name, c.bad))
		}
	}
	// AKIA-shaped strings are expected in env/folder HTTPS lures and are not
	// flagged. Third-party canary markers above remain the fingerprint checks.
	return r, nil
}
