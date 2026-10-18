package sensor

import (
	"path/filepath"
	"strings"
)

// AllowEntry matches actor process path (and optional substring).
type AllowEntry struct {
	// MatchExe is matched against the process executable basename or full path (case-insensitive).
	MatchExe string `json:"match_exe"`
	// Reason is recorded when matched (auditable, never silent).
	Reason string `json:"reason"`
}

// DefaultAllowlist returns known noisy helpers. Operators can extend via config.
func DefaultAllowlist() []AllowEntry {
	return []AllowEntry{
		{MatchExe: "SearchProtocolHost.exe", Reason: "windows search indexer"},
		{MatchExe: "SearchIndexer.exe", Reason: "windows search indexer"},
		{MatchExe: "MsMpEng.exe", Reason: "windows defender"},
		{MatchExe: "MpCopyAccelerator.exe", Reason: "windows defender"},
		{MatchExe: "updatedb", Reason: "linux locate db"},
		{MatchExe: "mlocate", Reason: "linux locate"},
		{MatchExe: "plocate", Reason: "linux locate"},
		{MatchExe: "tracker-miner-fs", Reason: "gnome tracker"},
		{MatchExe: "baloo_file", Reason: "kde baloo"},
	}
}

func MatchAllowlist(exe string, list []AllowEntry) (matched bool, reason string) {
	if exe == "" {
		return false, ""
	}
	full := strings.ToLower(filepath.Clean(exe))
	base := crossPlatformBase(full)
	for _, e := range list {
		m := strings.ToLower(strings.TrimSpace(e.MatchExe))
		if m == "" {
			continue
		}
		if base == m || full == m || strings.HasSuffix(full, "/"+m) || strings.HasSuffix(full, `\`+m) {
			return true, e.Reason
		}
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
