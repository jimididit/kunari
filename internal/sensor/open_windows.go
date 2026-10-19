//go:build windows

package sensor

import (
	"fmt"
	"strings"
)

func OpenBest(targets []Target) (Watcher, error) {
	if len(targets) == 0 {
		return nil, fmt.Errorf("no targets")
	}
	if err := probe4663(); err == nil {
		return newEvent4663(targets)
	}
	w, err := newRDC(targets)
	if err != nil {
		return nil, fmt.Errorf("win-sacl-4663 unavailable; rdc: %w", err)
	}
	return w, nil
}

func PlatformInstallHints(targets []Target) string {
	var b strings.Builder
	b.WriteString("# OPSEC: restrict ACL on sentinel.json, ingest.secret, and data_dir to the service account.\n")
	b.WriteString("# Kunari Windows SACL / audit setup (run elevated PowerShell)\n")
	b.WriteString("# AccessMask: 0x1 ReadData, 0x2 WriteData, 0x10000 DELETE (also rename).\n\n")
	b.WriteString("auditpol /set /subcategory:\"File System\" /success:enable\n\n")
	for _, t := range targets {
		b.WriteString(fmt.Sprintf("# token %s\n", t.TokenID))
		b.WriteString(fmt.Sprintf("$acl = Get-Acl -Path '%s' -Audit\n", t.Path))
		b.WriteString("$rule = New-Object System.Security.AccessControl.FileSystemAuditRule(`\n")
		b.WriteString("  'Everyone','ReadData,WriteData,Delete,ReadAttributes','None','None','Success')\n")
		b.WriteString("$acl.AddAuditRule($rule)\n")
		b.WriteString(fmt.Sprintf("Set-Acl -Path '%s' -AclObject $acl\n\n", t.Path))
	}
	b.WriteString("# Verify: auditpol /get /category:\"Object Access\"\n")
	b.WriteString("# Events: Security log Event ID 4663\n")
	return b.String()
}
