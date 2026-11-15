//go:build linux

package sensor

import (
	"fmt"
	"strings"
)

func OpenBest(targets []Target, preferTiers []string) (Watcher, error) {
	_ = preferTiers
	if len(targets) == 0 {
		return nil, fmt.Errorf("no targets")
	}
	if w, err := newFanotify(targets); err == nil {
		return w, nil
	} else {
		fanErr := err
		if w, err := newInotify(targets); err == nil {
			_ = fanErr
			return w, nil
		} else {
			return nil, fmt.Errorf("fanotify: %v; inotify: %w", fanErr, err)
		}
	}
}

func PlatformInstallHints(targets []Target) string {
	var b strings.Builder
	b.WriteString("# OpenBest arms fanotify when CAP_SYS_ADMIN is available; otherwise inotify (no PID).\n")
	b.WriteString("# auditd is not an OpenBest tier - optional operator rules only (conflicts with -e 2).\n")
	b.WriteString("# OPSEC: audit rules below name watched paths in /etc/audit - restrict root access to that file.\n")
	b.WriteString("# Optional: /etc/audit/rules.d/kunari.rules && augenrules --load\n")
	for _, t := range targets {
		b.WriteString(fmt.Sprintf("-w %s -p rwxa -k kunari\n", t.Path))
	}
	return b.String()
}
