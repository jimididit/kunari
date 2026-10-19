//go:build windows

package sensor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type event4663Watcher struct {
	targets []Target
	hash    string
	seen    map[string]struct{}
}

func newEvent4663(targets []Target) (*event4663Watcher, error) {
	if len(targets) == 0 {
		return nil, fmt.Errorf("no targets")
	}
	var parts []string
	for _, t := range targets {
		parts = append(parts, strings.ToLower(filepath.Clean(t.Path))+"|"+t.TokenID)
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, ";") + "|win-sacl-4663"))
	return &event4663Watcher{
		targets: targets,
		hash:    hex.EncodeToString(sum[:]),
		seen:    map[string]struct{}{},
	}, nil
}

func (w *event4663Watcher) Tier() Tier { return TierWinSACL }
func (w *event4663Watcher) Capabilities() string {
	return "open/read/modify/delete/rename via Security Event 4663; needs audit policy+SACL+admin"
}
func (w *event4663Watcher) ConfigHash() string { return w.hash }
func (w *event4663Watcher) Close() error       { return nil }

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
			for _, touch := range parse4663(raw, w.targets) {
				key := touch.Path + "|" + touch.Action + "|" + touch.Extra["access_mask"]
				if _, ok := w.seen[key]; ok {
					continue
				}
				w.seen[key] = struct{}{}
				select {
				case out <- touch:
				case <-ctx.Done():
					return nil
				}
			}
		}
	}
}

func probe4663() error {
	cmd := exec.Command("wevtutil", "qe", "Security", "/q:*[System[(EventID=4663)]]", "/c:1", "/rd:true", "/f:text")
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
	cmd := exec.Command("wevtutil", "qe", "Security", "/q:"+xpath, "/c:30", "/rd:true", "/f:text") // #nosec G204 -- argv, not a shell; path charset-checked
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%w: %s", err, truncate(string(out), 200))
	}
	return string(out), nil
}

func xpath4663(targets []Target) (string, error) {
	var parts []string
	for _, t := range targets {
		if !safeObjectName(t.Path) {
			return "", fmt.Errorf("target path %q cannot be embedded in an XPath query", t.Path)
		}
		parts = append(parts, "EventData[Data[@Name='ObjectName']='"+t.Path+"']")
	}
	if len(parts) == 0 {
		return "", fmt.Errorf("no targets")
	}
	return "*[System[(EventID=4663)] and (" + strings.Join(parts, " or ") + ")]", nil
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
		case r == '\\' || r == ':' || r == '.' || r == '_' || r == '-' || r == ' ' || r == '(' || r == ')':
		default:
			return false
		}
	}
	return true
}

func parse4663(raw string, targets []Target) []Touch {
	want := map[string]Target{}
	for _, t := range targets {
		want[strings.ToLower(filepath.Clean(t.Path))] = t
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
		key := strings.ToLower(filepath.Clean(path))
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
				"access_mask":  strings.TrimSpace(mask),
				"process_name": strings.TrimSpace(proc),
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
