//go:build windows

package sensor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os/exec"
	"path/filepath"
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
	if _, err := queryRecent4663(); err != nil {
		return fmt.Errorf("security log 4663 probe: %w", err)
	}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			raw, err := queryRecent4663()
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

func queryRecent4663() (string, error) {
	cmd := exec.Command("wevtutil", "qe", "Security", "/q:*[System[(EventID=4663)]]", "/c:50", "/f:text")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%w: %s", err, truncate(string(out), 200))
	}
	return string(out), nil
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
		proc := findField(block, "Process Name:")
		if proc == "" {
			proc = findField(block, "ProcessName:")
		}
		touches = append(touches, Touch{
			Path:     path,
			Action:   mapAccessMask(mask),
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
	return strings.TrimSpace(line)
}

func mapAccessMask(mask string) string {
	m := strings.ToLower(strings.TrimSpace(mask))
	m = strings.TrimPrefix(m, "0x")
	switch {
	case strings.Contains(m, "10000"):
		return "delete"
	case m == "2":
		return "modify"
	case m == "1":
		return "read"
	default:
		return "open"
	}
}
