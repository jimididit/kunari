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
		// In-band banners are endpoint giveaways - forge must not emit these.
		{"tripwire banner", "AUTHORIZED TRIPWIRE"},
		{"decoy credentials banner", "decoy credentials"},
		{"tripwire folder banner", "TRIPWIRE FOLDER"},
		{"kunari sentinel hint", "kunari sentinel"},
	}
	lower := strings.ToLower(s)
	for _, c := range checks {
		if strings.Contains(lower, strings.ToLower(c.bad)) || strings.Contains(s, c.bad) {
			r.Findings = append(r.Findings, fmt.Sprintf("%s: contains %q", c.name, c.bad))
		}
	}
	return r, nil
}
