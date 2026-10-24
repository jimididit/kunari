package sensor

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Microsoft-Windows-Kernel-File event IDs (manifest / PerfView).
const (
	etwIDNameDelete    uint16 = 11
	etwIDCreate        uint16 = 12
	etwIDRead          uint16 = 15
	etwIDWrite         uint16 = 16
	etwIDDeletePath    uint16 = 26
	etwIDRenamePath    uint16 = 27
	etwIDCreateNewFile uint16 = 30
)

// Kernel-File keywords (MatchAnyKeyword bits).
const (
	etwKWFilename   uint64 = 0x10
	etwKWFileIO     uint64 = 0x20
	etwKWCreate     uint64 = 0x80
	etwKWRead       uint64 = 0x100
	etwKWWrite      uint64 = 0x200
	etwKWDeletePath uint64 = 0x400
	etwKWRenamePath uint64 = 0x800
)

func etwMatchAnyKeyword() uint64 {
	return etwKWFilename | etwKWFileIO | etwKWCreate | etwKWRead | etwKWWrite | etwKWDeletePath | etwKWRenamePath
}

func etwEventIDs() []uint16 {
	return []uint16{etwIDNameDelete, etwIDCreate, etwIDRead, etwIDWrite, etwIDDeletePath, etwIDRenamePath, etwIDCreateNewFile}
}

// etwAction maps a Kernel-File event ID to a Kunari Touch.Action.
func etwAction(eventID uint16) (string, bool) {
	switch eventID {
	case etwIDCreate:
		return "open", true
	case etwIDRead:
		return "read", true
	case etwIDWrite, etwIDCreateNewFile:
		return "modify", true
	case etwIDDeletePath, etwIDNameDelete:
		return "delete", true
	case etwIDRenamePath:
		return "rename", true
	default:
		return "", false
	}
}

// etwPathMatches reports whether an event path refers to a watched target.
// eventPath should already be normalized toward a Win32 path when possible.
func etwPathMatches(eventPath, target string) bool {
	ep := etwNormPath(eventPath)
	tp := etwNormPath(target)
	if ep == "" || tp == "" {
		return false
	}
	if ep == tp {
		return true
	}
	// Win32 event paths must match exactly (no cross-drive suffix tricks).
	if len(ep) > 2 && ep[1] == ':' {
		return false
	}
	// NT device paths: compare using the target's path under the drive root
	// (\foo\bar), requiring a leading separator so "\data\x" does not match "\mydata\x".
	if len(tp) > 2 && tp[1] == ':' {
		suffix := strings.ReplaceAll(tp[2:], `/`, `\`)
		if suffix == "" {
			suffix = `\`
		}
		if !strings.HasPrefix(suffix, `\`) {
			suffix = `\` + suffix
		}
		return etwHasPathSuffix(ep, suffix)
	}
	return false
}

func etwNormPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	p = strings.ReplaceAll(p, `/`, `\`)
	return strings.ToLower(filepath.Clean(p))
}

// etwHasPathSuffix reports whether path ends at a separator boundary with suffix.
// suffix should begin with '\' (e.g. \programdata\kunari\bait.env).
func etwHasPathSuffix(path, suffix string) bool {
	if path == "" || suffix == "" {
		return false
	}
	if path == suffix {
		return true
	}
	if !strings.HasSuffix(path, suffix) {
		return false
	}
	// Reject mid-component matches: "...\my" + "\data\file" must not count.
	// With a leading '\' on suffix, HasSuffix alone is usually enough; still
	// require the match to start at a separator when path is longer.
	start := len(path) - len(suffix)
	if start < 0 {
		return false
	}
	if start == 0 {
		return true
	}
	// suffix begins with '\'; the prior rune must end the previous component
	// (i.e. not continue a name into the suffix). Prior char should not be '\';
	// wait - prior char is the last char of the previous component (letter).
	// Mid-component case: path=\vol\mydata\file suffix=\data\file already fails
	// HasSuffix. Remaining risk: suffix without leading sep - rejected above.
	return suffix[0] == '\\' || suffix[0] == '/'
}

func etwPropString(props map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		if v, ok := props[k]; ok && v != nil {
			switch t := v.(type) {
			case string:
				if s := strings.TrimSpace(t); s != "" {
					return s
				}
			default:
				s := strings.TrimSpace(fmt.Sprint(t))
				if s != "" && s != "<nil>" {
					return s
				}
			}
		}
	}
	return ""
}
