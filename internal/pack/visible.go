package pack

import (
	"fmt"
	"strings"
	"unicode"
)

// validateVisibleUnder checks a user-relative decoy directory (under Documents).
// Example: "Work/Finance" or "Documents/Work/Finance" (Documents/ prefix optional).
func validateVisibleUnder(goos, rel string) (string, error) {
	rel = strings.TrimSpace(rel)
	if rel == "" {
		return "", nil
	}
	rel = strings.ReplaceAll(rel, `\`, `/`)
	rel = strings.Trim(rel, "/")
	if rel == "" {
		return "", fmt.Errorf("--visible-under is empty")
	}
	parts := strings.Split(rel, "/")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" || p == "." || p == ".." {
			return "", fmt.Errorf("--visible-under has invalid segment %q", p)
		}
		for _, r := range p {
			if r < 32 || r == 127 || r == '/' || r == '\\' || r == ':' || r == '*' || r == '?' || r == '"' || r == '<' || r == '>' || r == '|' {
				return "", fmt.Errorf("--visible-under segment %q has illegal character", p)
			}
			if unicode.IsControl(r) {
				return "", fmt.Errorf("--visible-under segment %q has control character", p)
			}
		}
		out = append(out, p)
	}
	// Normalize: drop leading Documents so install always joins under the real Documents folder.
	if len(out) > 0 && strings.EqualFold(out[0], "Documents") {
		out = out[1:]
	}
	if len(out) == 0 {
		return "", fmt.Errorf("--visible-under needs a path under Documents (e.g. Work/Finance)")
	}
	joined := strings.Join(out, "/")
	switch goos {
	case "windows":
		return strings.ReplaceAll(joined, `/`, `\`), nil
	default:
		return joined, nil
	}
}

// visibleWatchPlaceholder is rewritten by install to the interactive user's Documents path.
func visibleWatchPlaceholder(goos, visibleUnder, decoyBase string) string {
	marker := "__KUNARI_VISIBLE__"
	switch goos {
	case "windows":
		return marker + `\` + visibleUnder + `\` + decoyBase
	default:
		return marker + "/" + visibleUnder + "/" + decoyBase
	}
}
