package sensor

import (
	"encoding/json"
	"path"
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
	action, paths := extractESEvent(raw.Event)
	if action == "" || len(paths) == 0 {
		return Touch{}, false
	}
	// Prefer a watched path so rename-away from a canary still alerts.
	path := ""
	for _, p := range paths {
		if pathWatched(p, targets) {
			path = p
			break
		}
	}
	if path == "" {
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

func extractESEvent(ev map[string]any) (action string, paths []string) {
	if ev == nil {
		return "", nil
	}
	if open := mapField(ev, "open"); open != nil {
		return "open", collectFilePaths(open, "file")
	}
	if write := mapField(ev, "write"); write != nil {
		return "modify", collectFilePaths(write, "target")
	}
	if create := mapField(ev, "create"); create != nil {
		return "modify", destinationPaths(create["destination"])
	}
	if unlink := mapField(ev, "unlink"); unlink != nil {
		return "delete", collectFilePaths(unlink, "target")
	}
	if rename := mapField(ev, "rename"); rename != nil {
		var out []string
		out = append(out, collectFilePaths(rename, "source")...)
		out = append(out, destinationPaths(rename["destination"])...)
		return "rename", uniqPaths(out)
	}
	if execEv := mapField(ev, "exec"); execEv != nil {
		if p, ok := digString(execEv, "target", "executable", "path"); ok {
			return "exec", []string{p}
		}
	}
	return "", nil
}

func mapField(m map[string]any, key string) map[string]any {
	v, ok := m[key]
	if !ok {
		return nil
	}
	obj, _ := v.(map[string]any)
	return obj
}

func collectFilePaths(m map[string]any, key string) []string {
	if m == nil {
		return nil
	}
	if p, ok := digString(m, key, "path"); ok && p != "" {
		return []string{p}
	}
	// Some emitters nest as key: { existing_file: { path } }
	return destinationPaths(m[key])
}

// destinationPaths reads ES destination unions:
// existing_file.path or new_path.dir.path + new_path.filename.
// Also tolerates a bare .path for older/fixture shapes.
func destinationPaths(dest any) []string {
	m, ok := dest.(map[string]any)
	if !ok || m == nil {
		return nil
	}
	var out []string
	if p, ok := digString(m, "path"); ok && p != "" {
		out = append(out, p)
	}
	if p, ok := digString(m, "existing_file", "path"); ok && p != "" {
		out = append(out, p)
	}
	if dir, ok := digString(m, "new_path", "dir", "path"); ok && dir != "" {
		if name, ok := digString(m, "new_path", "filename"); ok && name != "" {
			// ES paths are always POSIX; use path.Join so Windows hosts still parse fixtures.
			out = append(out, path.Join(dir, name))
		} else {
			out = append(out, dir)
		}
	}
	return uniqPaths(out)
}

func uniqPaths(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range in {
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
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
