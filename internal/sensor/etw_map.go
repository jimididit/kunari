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
	ep := strings.ToLower(filepath.Clean(strings.TrimSpace(eventPath)))
	tp := strings.ToLower(filepath.Clean(strings.TrimSpace(target)))
	if ep == "" || tp == "" {
		return false
	}
	if ep == tp {
		return true
	}
	if strings.HasSuffix(ep, tp) {
		return true
	}
	if len(tp) > 2 && tp[1] == ':' {
		suffix := tp[2:]
		suffix = strings.ReplaceAll(suffix, `/`, `\`)
		if suffix != "" && strings.HasSuffix(ep, suffix) {
			return true
		}
	}
	return false
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
