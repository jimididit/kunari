package sensor

import (
	"path/filepath"
	"strings"
)

// AllowEntry matches actor process path (and optional substring).
type AllowEntry struct {
	// MatchExe is matched against the process executable basename or full path (case-insensitive).
	MatchExe string `json:"match_exe"`
	// PathContains, when set, also requires the full executable path to contain this
	// substring (case-insensitive; separators normalized to '/'). This stops a renamed
	// attacker binary from silencing alerts merely by sharing a default basename.
	PathContains string `json:"path_contains,omitempty"`
	// Reason is recorded when matched (auditable, never silent).
	Reason string `json:"reason"`
}

// DefaultAllowlist returns known noisy helpers. Operators can extend via config.
func DefaultAllowlist() []AllowEntry {
	return []AllowEntry{
		{MatchExe: "SearchProtocolHost.exe", PathContains: "/windows/", Reason: "windows search indexer"},
		{MatchExe: "SearchIndexer.exe", PathContains: "/windows/", Reason: "windows search indexer"},
		{MatchExe: "MsMpEng.exe", PathContains: "/windows defender/", Reason: "windows defender"},
		{MatchExe: "MpCopyAccelerator.exe", PathContains: "/windows defender/", Reason: "windows defender"},
		{MatchExe: "updatedb", PathContains: "/usr/", Reason: "linux locate db"},
		{MatchExe: "mlocate", PathContains: "/usr/", Reason: "linux locate"},
		{MatchExe: "plocate", PathContains: "/usr/", Reason: "linux locate"},
		{MatchExe: "tracker-miner-fs", PathContains: "/usr/", Reason: "gnome tracker"},
		{MatchExe: "baloo_file", PathContains: "/usr/", Reason: "kde baloo"},
	}
}

func MatchAllowlist(exe string, list []AllowEntry) (matched bool, reason string) {
	if exe == "" {
		return false, ""
	}
	full := strings.ToLower(filepath.Clean(exe))
	norm := strings.ReplaceAll(full, `\`, "/")
	base := crossPlatformBase(full)
	for _, e := range list {
		m := strings.ToLower(strings.TrimSpace(e.MatchExe))
		if m == "" {
			continue
		}
		nameOK := base == m || full == m || strings.HasSuffix(full, "/"+m) || strings.HasSuffix(full, `\`+m)
		if !nameOK {
			continue
		}
		if hint := strings.ToLower(strings.TrimSpace(e.PathContains)); hint != "" {
			hint = strings.ReplaceAll(hint, `\`, "/")
			if !strings.Contains(norm, hint) {
				continue
			}
		}
		return true, e.Reason
	}
	return false, ""
}

// crossPlatformBase returns the final path component for Windows or Unix paths
// even when the host OS separator differs from the recorded process path.
func crossPlatformBase(path string) string {
	path = strings.ReplaceAll(path, `\`, "/")
	path = strings.TrimRight(path, "/")
	if path == "" {
		return ""
	}
	if i := strings.LastIndex(path, "/"); i >= 0 {
		return path[i+1:]
	}
	return path
}
