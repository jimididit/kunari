package pack

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

var (
	unixPrefixRe = regexp.MustCompile(`^(/[A-Za-z0-9._-]+)+$`)
	winPrefixRe  = regexp.MustCompile(`^[A-Za-z]:\\(?:[A-Za-z0-9._-]+\\)*[A-Za-z0-9._-]+$`)
	binNameRe    = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
)

func validatePrefix(goos, prefix string) error {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return fmt.Errorf("install prefix is empty")
	}
	for _, r := range prefix {
		if r < 32 || r == 127 || unicode.IsSpace(r) {
			return fmt.Errorf("install prefix contains control or space characters")
		}
	}
	switch goos {
	case "windows":
		if !winPrefixRe.MatchString(prefix) {
			return fmt.Errorf("windows --prefix must look like C:\\ProgramData\\KunariAgent (letters, digits, ._- only)")
		}
	default:
		if !unixPrefixRe.MatchString(prefix) {
			return fmt.Errorf("unix --prefix must be an absolute path with safe segments (e.g. /opt/kunari-agent)")
		}
	}
	return nil
}

func validateBinName(name string) error {
	if !binNameRe.MatchString(name) {
		return fmt.Errorf("binary name %q is unsafe", name)
	}
	return nil
}

// shQuote returns a single-quoted shell string safe for bash interpolation.
func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}
