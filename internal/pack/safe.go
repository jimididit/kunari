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
	case "linux":
		if !unixPrefixRe.MatchString(prefix) {
			return fmt.Errorf("unix --prefix must be an absolute path with safe segments (e.g. /opt/kunari-agent)")
		}
		// systemd unit runs as user kunari; home dirs are typically 0700 and block exec.
		if prefix == "/home" || strings.HasPrefix(prefix, "/home/") {
			return fmt.Errorf("linux --prefix must not be under /home (service user kunari cannot traverse typical home perms); use /opt/kunari-agent")
		}
		if prefix == "/root" || strings.HasPrefix(prefix, "/root/") {
			return fmt.Errorf("linux --prefix must not be under /root; use /opt/kunari-agent")
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
