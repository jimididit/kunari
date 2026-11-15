//go:build windows

package sensor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const event4663SeenCap = 4096
const event4663MaxIDFile = "win-sacl-4663.max_record_id"

type event4663Watcher struct {
	targets   []Target
	hash      string
	seen      map[string]struct{}
	seenQ     []string
	statePath string
	maxID     uint64
	haveMax   bool // true after restore or cold-start seed
}

func newEvent4663(targets []Target) (*event4663Watcher, error) {
	if len(targets) == 0 {
		return nil, fmt.Errorf("no targets")
	}
	var parts []string
	for _, t := range targets {
		if err := ensureFileSystemAuditACE(t.Path); err != nil {
			return nil, fmt.Errorf("SACL on %s: %w", t.Path, err)
		}
		parts = append(parts, normalizeWinPath(t.Path)+"|"+t.TokenID)
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, ";") + "|win-sacl-4663"))
	return &event4663Watcher{
		targets: targets,
		hash:    hex.EncodeToString(sum[:]),
		seen:    map[string]struct{}{},
	}, nil
}

// RestoreSeen loads the last emitted EventRecordID from dataDir so restarts
// re-emit touches that happened while the sensor was down, without replaying
// the entire Security log window.
func (w *event4663Watcher) RestoreSeen(dir string) error {
	if w == nil || strings.TrimSpace(dir) == "" {
		return nil
	}
	w.statePath = filepath.Join(dir, event4663MaxIDFile)
	b, err := os.ReadFile(w.statePath) // #nosec G304 -- path under sentinel data_dir
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	id, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return nil
	}
	w.maxID = id
	w.haveMax = true
	return nil
}

func (w *event4663Watcher) persistMaxID() {
	if w.statePath == "" || !w.haveMax {
		return
	}
	_ = os.WriteFile(w.statePath, []byte(strconv.FormatUint(w.maxID, 10)+"\n"), 0o600)
}

// ensureFileSystemAuditACE enables File System success auditing and attaches a
// per-file success audit ACE. Called from the elevated sentinel at startup so
// package install never Set-Acl's through a user-writable Documents path.
func ensureFileSystemAuditACE(path string) error {
	if !safeObjectName(path) {
		return fmt.Errorf("path not safe for SACL helper")
	}
	// Refuse reparse points, then set audit ACE. Path is single-quoted for PowerShell.
	ps := fmt.Sprintf(`$ErrorActionPreference='Stop'; $p='%s'; $i=Get-Item -LiteralPath $p -Force; if ($i.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'reparse point' }; if ($i.PSIsContainer) { throw 'not a file' }; $null = cmd.exe /c 'auditpol /set /subcategory:"File System" /success:enable >nul'; $acl=Get-Acl -Path $p -Audit; $rule=New-Object System.Security.AccessControl.FileSystemAuditRule('Everyone','ReadData,WriteData,Delete,ReadAttributes','None','None','Success'); $acl.AddAuditRule($rule); Set-Acl -Path $p -AclObject $acl; $i2=Get-Item -LiteralPath $p -Force; if ($i2.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'reparse after SACL' }`, strings.ReplaceAll(path, `'`, `''`))
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps) // #nosec G204 -- argv; path charset-checked + single-quoted
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, truncate(string(out), 240))
	}
	return nil
}

func (w *event4663Watcher) Tier() Tier { return TierWinSACL }
func (w *event4663Watcher) Capabilities() string {
	return "open/read/modify/delete/rename via Security Event 4663; needs audit policy+SACL+admin"
}
func (w *event4663Watcher) ConfigHash() string { return w.hash }
func (w *event4663Watcher) Close() error       { return nil }

func (w *event4663Watcher) rememberRecord(id string) bool {
	if id == "" {
		return false
	}
	if _, ok := w.seen[id]; ok {
		return true
	}
	if len(w.seenQ) >= event4663SeenCap {
		old := w.seenQ[0]
		w.seenQ = w.seenQ[1:]
		delete(w.seen, old)
	}
	w.seen[id] = struct{}{}
	w.seenQ = append(w.seenQ, id)
	return false
}

func (w *event4663Watcher) Run(ctx context.Context, out chan<- Touch) error {
	if err := probe4663(); err != nil {
		return fmt.Errorf("security log 4663 probe: %w", err)
	}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			raw, err := queryRecent4663(w.targets)
			if err != nil {
				continue
			}
			touches := parse4663(raw, w.targets)
			if !w.haveMax {
				// Cold start: advance watermark to the current window without emitting.
				for _, touch := range touches {
					if id, ok := parseRecordID(touch); ok && id > w.maxID {
						w.maxID = id
					}
					if touch.Extra != nil {
						_ = w.rememberRecord(touch.Extra["event_record_id"])
					}
				}
				w.haveMax = true
				w.persistMaxID()
				continue
			}
			baseline := w.maxID
			type pendingTouch struct {
				id    uint64
				touch Touch
			}
			var pending []pendingTouch
			for _, touch := range touches {
				key := ""
				if touch.Extra != nil {
					key = touch.Extra["event_record_id"]
				}
				if key == "" {
					continue
				}
				if w.rememberRecord(key) {
					continue
				}
				id, ok := parseRecordID(touch)
				if !ok || id <= baseline {
					continue
				}
				pending = append(pending, pendingTouch{id: id, touch: touch})
				if id > w.maxID {
					w.maxID = id
				}
			}
			sort.Slice(pending, func(i, j int) bool { return pending[i].id < pending[j].id })
			if len(pending) > 0 {
				w.persistMaxID()
			}
			for _, p := range pending {
				select {
				case out <- p.touch:
				case <-ctx.Done():
					return nil
				}
			}
		}
	}
}

func parseRecordID(t Touch) (uint64, bool) {
	if t.Extra == nil {
		return 0, false
	}
	raw := strings.TrimSpace(t.Extra["event_record_id"])
	if raw == "" {
		return 0, false
	}
	id, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0, false
	}
	return id, true
}

func touchEventTime(t Touch) (time.Time, bool) {
	if t.Extra == nil {
		return time.Time{}, false
	}
	raw := strings.TrimSpace(t.Extra["event_time"])
	if raw == "" {
		return time.Time{}, false
	}
	// wevtutil SystemTime is usually RFC3339 / RFC3339Nano.
	if ts, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return ts.UTC(), true
	}
	if ts, err := time.Parse(time.RFC3339, raw); err == nil {
		return ts.UTC(), true
	}
	return time.Time{}, false
}

func probe4663() error {
	cmd := exec.Command("wevtutil", "qe", "Security", "/q:*[System[(EventID=4663)]]", "/c:1", "/rd:true", "/f:xml")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, truncate(string(out), 200))
	}
	return nil
}

func queryRecent4663(targets []Target) (string, error) {
	// Filter to the decoy path. Machine-wide File System success auditing
	// generates far more than a fixed /c window of unrelated 4663s, and
	// wevtutil's default direction is oldest-first.
	xpath, err := xpath4663(targets)
	if err != nil {
		return "", err
	}
	// exec.Command does not invoke a shell. The XPath is a fixed template plus
	// paths limited to safeObjectName.
	cmd := exec.Command("wevtutil", "qe", "Security", "/q:"+xpath, "/c:100", "/rd:true", "/f:xml") // #nosec G204 -- argv, not a shell; path charset-checked
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%w: %s", err, truncate(string(out), 200))
	}
	return string(out), nil
}

func xpath4663(targets []Target) (string, error) {
	var parts []string
	for _, t := range targets {
		variants := winObjectNameVariants(t.Path)
		for _, p := range variants {
			if !safeObjectName(p) {
				return "", fmt.Errorf("target path %q cannot be embedded in an XPath query", p)
			}
			parts = append(parts, "EventData[Data[@Name='ObjectName']='"+p+"']")
		}
	}
	if len(parts) == 0 {
		return "", fmt.Errorf("no targets")
	}
	return "*[System[(EventID=4663)] and (" + strings.Join(parts, " or ") + ")]", nil
}

func winObjectNameVariants(p string) []string {
	n := strings.TrimSpace(p)
	if strings.HasPrefix(strings.ToUpper(n), `\\?\UNC\`) {
		n = `\\` + n[len(`\\?\UNC\`):]
	} else {
		n = strings.TrimPrefix(n, `\\?\`)
	}
	n = filepath.Clean(n)
	var out []string
	add := func(s string) {
		if s == "" {
			return
		}
		for _, e := range out {
			if e == s {
				return
			}
		}
		out = append(out, s)
	}
	add(n)
	if strings.HasPrefix(n, `\\`) {
		// \\server\share\file -> \\?\UNC\server\share\file
		add(`\\?\UNC\` + strings.TrimPrefix(n, `\\`))
	} else {
		add(`\\?\` + n)
	}
	return out
}

func normalizeWinPath(p string) string {
	p = strings.TrimSpace(p)
	// Keep UNC identity: \\?\UNC\server\share -> \\server\share
	if strings.HasPrefix(strings.ToUpper(p), `\\?\UNC\`) {
		p = `\\` + p[len(`\\?\UNC\`):]
	} else {
		p = strings.TrimPrefix(p, `\\?\`)
	}
	return strings.ToLower(filepath.Clean(p))
}

func isHex(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f')
}

func safeObjectName(p string) bool {
	if p == "" || len(p) > 260 {
		return false
	}
	for _, r := range p {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '\\' || r == ':' || r == '.' || r == '_' || r == '-' || r == ' ' || r == '(' || r == ')' || r == '?':
		default:
			return false
		}
	}
	return true
}

func parse4663(raw string, targets []Target) []Touch {
	if strings.Contains(raw, "<Event") {
		return parse4663XML(raw, targets)
	}
	return parse4663Text(raw, targets)
}

func parse4663XML(raw string, targets []Target) []Touch {
	want := map[string]Target{}
	for _, t := range targets {
		want[normalizeWinPath(t.Path)] = t
	}
	var touches []Touch
	chunks := splitXMLEvents(raw)
	for _, block := range chunks {
		recID := xmlTagText(block, "EventRecordID")
		path := xmlDataNamed(block, "ObjectName")
		if path == "" {
			continue
		}
		key := normalizeWinPath(path)
		if _, ok := want[key]; !ok {
			continue
		}
		mask := xmlDataNamed(block, "AccessMask")
		accesses := xmlDataNamed(block, "AccessList")
		proc := xmlDataNamed(block, "ProcessName")
		eventTime := xmlAttr(block, "SystemTime")
		action := mapAccessMask(mask)
		if action == "open" {
			if fromList := mapAccessList(accesses); fromList != "" {
				action = fromList
			}
		}
		extra := map[string]string{
			"access_mask":     strings.TrimSpace(mask),
			"process_name":    strings.TrimSpace(proc),
			"event_record_id": strings.TrimSpace(recID),
			"event_time":      strings.TrimSpace(eventTime),
		}
		occurred := time.Now().UTC()
		if ts, ok := touchEventTime(Touch{Extra: extra}); ok {
			occurred = ts
		}
		touches = append(touches, Touch{
			Path:     path,
			Action:   action,
			Occurred: occurred,
			Proven:   true,
			Extra:    extra,
		})
	}
	return touches
}

func xmlAttr(block, name string) string {
	for _, q := range []string{`"`, `'`} {
		needle := name + "=" + q
		i := strings.Index(block, needle)
		if i < 0 {
			continue
		}
		rest := block[i+len(needle):]
		end := strings.Index(rest, q)
		if end < 0 {
			continue
		}
		return strings.TrimSpace(rest[:end])
	}
	return ""
}

func splitXMLEvents(raw string) []string {
	const start = "<Event"
	var out []string
	rest := raw
	for {
		i := strings.Index(rest, start)
		if i < 0 {
			break
		}
		rest = rest[i:]
		end := strings.Index(rest, "</Event>")
		if end < 0 {
			out = append(out, rest)
			break
		}
		out = append(out, rest[:end+len("</Event>")])
		rest = rest[end+len("</Event>"):]
	}
	return out
}

func xmlTagText(block, tag string) string {
	open := "<" + tag + ">"
	close := "</" + tag + ">"
	i := strings.Index(block, open)
	if i < 0 {
		return ""
	}
	rest := block[i+len(open):]
	j := strings.Index(rest, close)
	if j < 0 {
		return ""
	}
	return strings.TrimSpace(rest[:j])
}

func xmlDataNamed(block, name string) string {
	// wevtutil may emit Name="ObjectName" or Name='ObjectName'.
	for _, q := range []string{`"`, `'`} {
		needle := "Name=" + q + name + q
		i := strings.Index(block, needle)
		if i < 0 {
			continue
		}
		rest := block[i+len(needle):]
		gt := strings.Index(rest, ">")
		if gt < 0 {
			continue
		}
		rest = rest[gt+1:]
		end := strings.Index(rest, "</Data>")
		if end < 0 {
			continue
		}
		return strings.TrimSpace(rest[:end])
	}
	return ""
}

func parse4663Text(raw string, targets []Target) []Touch {
	want := map[string]Target{}
	for _, t := range targets {
		want[normalizeWinPath(t.Path)] = t
	}
	var touches []Touch
	blocks := strings.Split(raw, "Event[")
	for _, block := range blocks {
		path := findField(block, "Object Name:")
		if path == "" {
			path = findField(block, "ObjectName:")
		}
		if path == "" {
			continue
		}
		path = strings.TrimSpace(path)
		key := normalizeWinPath(path)
		if _, ok := want[key]; !ok {
			continue
		}
		mask := findField(block, "Access Mask:")
		if mask == "" {
			mask = findField(block, "AccessMask:")
		}
		accesses := findField(block, "Accesses:")
		proc := findField(block, "Process Name:")
		if proc == "" {
			proc = findField(block, "ProcessName:")
		}
		recID := findField(block, "Event Record ID:")
		if recID == "" {
			recID = findField(block, "EventRecordID:")
		}
		action := mapAccessMask(mask)
		if action == "open" {
			if fromList := mapAccessList(accesses); fromList != "" {
				action = fromList
			}
		}
		touches = append(touches, Touch{
			Path:     path,
			Action:   action,
			Occurred: time.Now().UTC(),
			Proven:   true,
			Extra: map[string]string{
				"access_mask":     strings.TrimSpace(mask),
				"process_name":    strings.TrimSpace(proc),
				"event_record_id": strings.TrimSpace(recID),
			},
		})
	}
	return touches
}

func findField(block, label string) string {
	idx := strings.Index(block, label)
	if idx < 0 {
		return ""
	}
	rest := block[idx+len(label):]
	line, _, _ := strings.Cut(rest, "\n")
	// wevtutil text sometimes ends the value with a NUL before CRLF.
	return strings.Trim(line, " \t\r\n\x00")
}

func mapAccessList(accesses string) string {
	l := strings.ToLower(accesses)
	switch {
	case strings.Contains(l, "delete"):
		return "delete"
	case strings.Contains(l, "writedata") || strings.Contains(l, "appenddata") || strings.Contains(l, "addfile"):
		return "modify"
	case strings.Contains(l, "readdata") || strings.Contains(l, "listdirectory"):
		return "read"
	default:
		return ""
	}
}

func mapAccessMask(mask string) string {
	m := strings.ToLower(strings.TrimSpace(mask))
	m = strings.TrimPrefix(m, "0x")
	end := 0
	for end < len(m) && isHex(m[end]) {
		end++
	}
	m = m[:end]
	if m == "" {
		return "open"
	}
	v, err := strconv.ParseUint(m, 16, 64)
	if err != nil {
		return "open"
	}
	// Bit tests, not substrings: SYNCHRONIZE is 0x100000 and must not match DELETE 0x10000.
	// 4663 may report either specific FILE_* rights or unmapped GENERIC_* high bits.
	const (
		fileReadData  = 0x1
		fileWriteData = 0x2
		fileAppend    = 0x4
		deleteAccess  = 0x10000
		genericAll    = 0x10000000
		genericWrite  = 0x40000000
		genericRead   = 0x80000000
	)
	switch {
	case v&deleteAccess != 0:
		return "delete"
	case v&fileWriteData != 0 || v&fileAppend != 0 || v&genericWrite != 0 || v&genericAll != 0:
		return "modify"
	case v&fileReadData != 0 || v&genericRead != 0:
		return "read"
	default:
		// FILE_READ_ATTRIBUTES (0x80) and similar probes stay "open".
		return "open"
	}
}
