package sensor

import (
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const defaultCopyWindow = 5 * time.Second

// copyCorrelator marks confidence.copy_suspected from PID+time patterns.
// Copy is never a single OS event; this flag is always inferred.
type copyCorrelator struct {
	mu     sync.Mutex
	window time.Duration
	recent []copyObs
}

type copyObs struct {
	pid    int
	path   string
	action string
	at     time.Time
}

func newCopyCorrelator(window time.Duration) *copyCorrelator {
	if window <= 0 {
		window = defaultCopyWindow
	}
	return &copyCorrelator{window: window}
}

// Suspect returns true when this touch looks like part of a copy.
// Heuristics (inferred only):
//  1. Same PID open/read of path A then create/modify of different path B within window
//  2. Same PID open/read of two distinct watched paths within window
//  3. open/read by a well-known copy utility basename
func (c *copyCorrelator) Suspect(t Touch, exe string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := t.Occurred
	if now.IsZero() {
		now = time.Now().UTC()
	}
	c.prune(now)

	fromCopyTool := isCopyTool(exe)
	path := filepath.Clean(t.Path)
	action := strings.ToLower(t.Action)

	suspect := false
	if t.PID > 0 {
		for _, prev := range c.recent {
			if prev.pid != t.PID {
				continue
			}
			if filepath.Clean(prev.path) == path {
				continue
			}
			prevOpen := prev.action == "open" || prev.action == "read"
			curOpen := action == "open" || action == "read"
			curWrite := action == "modify" || action == "create" || action == "rename"
			if prevOpen && (curWrite || curOpen) {
				suspect = true
				break
			}
		}
	}
	if !suspect && fromCopyTool && (action == "open" || action == "read") {
		suspect = true
	}

	if action == "open" || action == "read" || action == "modify" || action == "create" {
		c.recent = append(c.recent, copyObs{pid: t.PID, path: path, action: action, at: now})
	}
	return suspect
}

func (c *copyCorrelator) prune(now time.Time) {
	cut := now.Add(-c.window)
	kept := c.recent[:0]
	for _, o := range c.recent {
		if o.at.After(cut) {
			kept = append(kept, o)
		}
	}
	c.recent = kept
}

func isCopyTool(exe string) bool {
	base := strings.ToLower(filepath.Base(strings.ReplaceAll(exe, `\`, `/`)))
	base = strings.TrimSuffix(base, ".exe")
	switch base {
	case "cp", "copy", "xcopy", "robocopy", "ditto", "rsync", "dd", "install", "gcp", "rclone":
		return true
	default:
		return false
	}
}
