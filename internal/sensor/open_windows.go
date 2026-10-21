//go:build windows

package sensor

import (
	"fmt"
	"strings"
)

func OpenBest(targets []Target, preferTiers []string) (Watcher, error) {
	return openBestWindows(targets, preferTiers)
}

func openBestWindows(targets []Target, prefer []string) (Watcher, error) {
	if len(targets) == 0 {
		return nil, fmt.Errorf("no targets")
	}
	order := append([]string{}, prefer...)
	for _, d := range []string{string(TierWinSACL), string(TierWinETW), string(TierWinRDC)} {
		if !containsTier(order, d) {
			order = append(order, d)
		}
	}
	var errs []string
	for _, name := range order {
		w, err := tryWindowsTier(name, targets)
		if err == nil {
			return w, nil
		}
		errs = append(errs, fmt.Sprintf("%s: %v", name, err))
	}
	return nil, fmt.Errorf("no windows tier available: %s", strings.Join(errs, "; "))
}

func tryWindowsTier(name string, targets []Target) (Watcher, error) {
	switch name {
	case string(TierWinSACL):
		if err := probe4663(); err != nil {
			return nil, err
		}
		return newEvent4663(targets)
	case string(TierWinETW):
		return newETW(targets)
	case string(TierWinRDC):
		return newRDC(targets)
	default:
		return nil, fmt.Errorf("unknown tier %q", name)
	}
}

func containsTier(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func PlatformInstallHints(targets []Target) string {
	var b strings.Builder
	b.WriteString("# OPSEC: restrict ACL on sentinel.json, ingest.secret, and data_dir to the service account.\n")
	b.WriteString("# Kunari Windows detection tiers (run elevated PowerShell where noted)\n\n")
	b.WriteString("## Preferred: win-sacl-4663 (lab-proven)\n")
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
	b.WriteString("# Events: Security log Event ID 4663\n\n")
	b.WriteString("## Experimental: win-etw-kernel-file (lab NV)\n")
	b.WriteString("# OpenBest tries this when SACL/4663 is unavailable. Needs elevation to start an ETW session.\n")
	b.WriteString("# No per-file SACL. Session name: KunariKernelFile (visible via: logman query -ets).\n")
	b.WriteString("# Force with sentinel.json prefer_tiers: [\"win-etw-kernel-file\"]\n")
	b.WriteString("# Fallback: win-rdc (modify/delete/rename only; no open/read).\n")
	return b.String()
}
