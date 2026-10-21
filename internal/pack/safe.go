package pack

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
)

var (
	unixPrefixRe = regexp.MustCompile(`^(/[A-Za-z0-9._-]+)+$`)
	winPrefixRe  = regexp.MustCompile(`^[A-Za-z]:\\(?:[A-Za-z0-9._-]+\\)*[A-Za-z0-9._-]+$`)
	binNameRe    = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	unitNameRe   = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
)

// Well-known OS / shell / EDR-bait process basenames (no extension). Case-insensitive.
// Optional operator renames are allowed; impersonating these is not.
var deniedBinBasenames = map[string]struct{}{
	// Windows
	"svchost": {}, "lsass": {}, "csrss": {}, "smss": {}, "winlogon": {}, "wininit": {},
	"services": {}, "explorer": {}, "conhost": {}, "dllhost": {}, "rundll32": {},
	"regsvr32": {}, "msiexec": {}, "taskhostw": {}, "dwm": {}, "runtimebroker": {},
	"searchhost": {}, "sihost": {}, "fontdrvhost": {}, "ctfmon": {}, "spoolsv": {},
	"lsm": {}, "winlogonui": {}, "powershell": {}, "pwsh": {}, "cmd": {}, "wmic": {},
	"certutil": {}, "bitsadmin": {}, "mshta": {}, "wscript": {}, "cscript": {},
	"schtasks": {}, "taskeng": {}, "system": {}, "idle": {}, "registry": {},
	// Linux / Unix
	"systemd": {}, "init": {}, "udevd": {}, "systemd-udevd": {}, "dbus-daemon": {},
	"cron": {}, "crond": {}, "sshd": {}, "rsyslogd": {}, "syslogd": {}, "auditd": {},
	"polkitd": {}, "networkmanager": {}, "snapd": {}, "containerd": {}, "dockerd": {},
	"kubelet": {}, "bash": {}, "sh": {}, "dash": {}, "zsh": {}, "sudo": {}, "su": {},
	"login": {}, "agetty": {}, "getty": {}, "kthreadd": {},
	// macOS
	"launchd": {}, "kernel_task": {}, "windowserver": {}, "finder": {}, "loginwindow": {},
	"configd": {}, "mds": {}, "mdworker": {}, "opendirectoryd": {}, "securityd": {},
	"syspolicyd": {}, "trustd": {}, "cfprefsd": {}, "distnoted": {},
}

// Well-known persistence / service identifiers operators must not mimic.
var deniedUnitNames = map[string]struct{}{
	"systemd": {}, "dbus": {}, "dbus.service": {}, "sshd": {}, "ssh": {}, "cron": {},
	"crond": {}, "rsyslog": {}, "auditd": {}, "networkmanager": {}, "docker": {},
	"containerd": {}, "kubelet": {}, "launchd": {}, "com.apple.launchd": {},
	"schedule": {}, "at": {}, "svchost": {}, "lsass": {},
}

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

// normalizeBinName applies OS defaults and Windows .exe suffix rules.
func normalizeBinName(goos, name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		if goos == "windows" {
			return "kunari.exe", nil
		}
		return "kunari", nil
	}
	if strings.ContainsAny(name, `/\:`) || name == "." || name == ".." {
		return "", fmt.Errorf("binary name %q must be a single path segment", name)
	}
	if !binNameRe.MatchString(name) {
		return "", fmt.Errorf("binary name %q is unsafe (use letters, digits, ._- only)", name)
	}
	if goos == "windows" {
		if !strings.HasSuffix(strings.ToLower(name), ".exe") {
			name += ".exe"
		}
	} else if strings.HasSuffix(strings.ToLower(name), ".exe") {
		return "", fmt.Errorf("binary name %q must not end with .exe on %s", name, goos)
	}
	if err := denyBinName(name); err != nil {
		return "", err
	}
	return name, nil
}

func denyBinName(name string) error {
	base := strings.ToLower(strings.TrimSuffix(filepath.Base(name), filepath.Ext(name)))
	if base == "" {
		return fmt.Errorf("binary name %q is empty after stripping extension", name)
	}
	if _, denied := deniedBinBasenames[base]; denied {
		return fmt.Errorf("binary name %q is denied (looks like a well-known OS binary; pick a benign org-specific name)", name)
	}
	return nil
}

func validateBinName(name string) error {
	// Kept for callers/tests that pass a fully normalized name.
	if !binNameRe.MatchString(name) {
		return fmt.Errorf("binary name %q is unsafe", name)
	}
	return denyBinName(name)
}

// normalizeUnitName returns the persistence identifier for the target OS.
// Linux: systemd unit base (no .service). Darwin: launchd Label. Windows: task name.
func normalizeUnitName(goos, name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		switch goos {
		case "windows":
			return "KunariSentinel", nil
		case "darwin":
			return "com.jimididit.kunari-sentinel", nil
		default:
			return "kunari-sentinel", nil
		}
	}
	if strings.ContainsAny(name, `/\:`) || name == "." || name == ".." {
		return "", fmt.Errorf("unit name %q must be a single identifier", name)
	}
	if goos == "linux" {
		name = strings.TrimSuffix(name, ".service")
	}
	if !unitNameRe.MatchString(name) {
		return "", fmt.Errorf("unit name %q is unsafe (use letters, digits, ._- only)", name)
	}
	if len(name) < 3 || len(name) > 64 {
		return "", fmt.Errorf("unit name length must be 3..64 characters")
	}
	if goos == "darwin" && !strings.Contains(name, ".") {
		return "", fmt.Errorf("darwin --unit-name should be a reverse-DNS label (e.g. com.example.tripwire)")
	}
	key := strings.ToLower(name)
	if goos == "linux" {
		if _, denied := deniedUnitNames[key]; denied {
			return "", fmt.Errorf("unit name %q is denied (well-known service name)", name)
		}
		if _, denied := deniedUnitNames[key+".service"]; denied {
			return "", fmt.Errorf("unit name %q is denied (well-known service name)", name)
		}
	} else if _, denied := deniedUnitNames[key]; denied {
		return "", fmt.Errorf("unit name %q is denied (well-known service name)", name)
	}
	// Also reject binary denylist as unit names (svchost task, etc.).
	base := strings.ToLower(strings.TrimSuffix(name, filepath.Ext(name)))
	if _, denied := deniedBinBasenames[base]; denied {
		return "", fmt.Errorf("unit name %q is denied (looks like a well-known OS binary)", name)
	}
	return name, nil
}

// shQuote returns a single-quoted shell string safe for bash interpolation.
func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}
