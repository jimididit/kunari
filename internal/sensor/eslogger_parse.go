package sensor

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"time"
)

// esloggerLine is a tolerant subset of Apple eslogger JSON Lines output.
type esloggerLine struct {
	EventType any            `json:"event_type"`
	Process   esProcess      `json:"process"`
	Event     map[string]any `json:"event"`
	Time      string         `json:"time"`
}

type esProcess struct {
	Executable esFile `json:"executable"`
	PPID       int    `json:"ppid"`
	AuditToken struct {
		PID int `json:"pid"`
	} `json:"audit_token"`
}

type esFile struct {
	Path string `json:"path"`
}

// ParseESLoggerLine maps one eslogger JSON object to a Touch if it hits a watched path.
func ParseESLoggerLine(line []byte, targets []Target) (Touch, bool) {
	var raw esloggerLine
	if err := json.Unmarshal(line, &raw); err != nil {
		return Touch{}, false
	}
	action, path := extractESEvent(raw.Event)
	if path == "" || action == "" {
		return Touch{}, false
	}
	if !pathWatched(path, targets) {
		return Touch{}, false
	}
	pid := raw.Process.AuditToken.PID
	occ := time.Now().UTC()
	if raw.Time != "" {
		if t, err := time.Parse(time.RFC3339Nano, raw.Time); err == nil {
			occ = t.UTC()
		} else if t, err := time.Parse(time.RFC3339, raw.Time); err == nil {
			occ = t.UTC()
		}
	}
	return Touch{
		Path:     path,
		Action:   action,
		PID:      pid,
		Occurred: occ,
		Proven:   true,
		Extra: map[string]string{
			"process_name": raw.Process.Executable.Path,
			"es_event":     action,
		},
	}, true
}

func extractESEvent(ev map[string]any) (action, path string) {
	if ev == nil {
		return "", ""
	}
	type pathSpec struct {
		action string
		keys   []string // nested keys under event.<name>
	}
	specs := []pathSpec{
		{"open", []string{"open", "file", "path"}},
		{"modify", []string{"write", "target", "path"}},
		{"modify", []string{"create", "destination", "path"}},
		{"delete", []string{"unlink", "target", "path"}},
		{"rename", []string{"rename", "destination", "path"}},
		{"rename", []string{"rename", "source", "path"}},
		{"exec", []string{"exec", "target", "executable", "path"}},
	}
	for _, s := range specs {
		if p, ok := digString(ev, s.keys...); ok && p != "" {
			return s.action, p
		}
	}
	return "", ""
}

func digString(m map[string]any, keys ...string) (string, bool) {
	var cur any = m
	for _, k := range keys {
		obj, ok := cur.(map[string]any)
		if !ok {
			return "", false
		}
		cur, ok = obj[k]
		if !ok {
			return "", false
		}
	}
	s, ok := cur.(string)
	return s, ok
}

func pathWatched(path string, targets []Target) bool {
	clean := filepath.Clean(path)
	for _, t := range targets {
		if filepath.Clean(t.Path) == clean {
			return true
		}
		// Directory watch: target is a dir prefix
		tp := filepath.Clean(t.Path)
		if strings.HasPrefix(clean, tp+string(filepath.Separator)) {
			return true
		}
	}
	return false
}
