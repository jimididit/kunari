//go:build darwin

package sensor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
)

// fseventsWatcher is a change-notification fallback (fsnotify/kqueue on macOS).
// It cannot see reads/opens and has no PID - reported honestly as mac-fsevents.
type fseventsWatcher struct {
	targets []Target
	hash    string
	w       *fsnotify.Watcher
}

func newFSEvents(targets []Target) (*fseventsWatcher, error) {
	fw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	var parts []string
	for _, t := range targets {
		if _, err := os.Stat(t.Path); err != nil {
			_ = fw.Close()
			return nil, fmt.Errorf("stat %s: %w", t.Path, err)
		}
		watchPath := t.Path
		fi, _ := os.Stat(t.Path)
		if fi != nil && !fi.IsDir() {
			watchPath = filepath.Dir(t.Path)
		}
		if err := fw.Add(watchPath); err != nil {
			_ = fw.Close()
			return nil, fmt.Errorf("watch %s: %w", watchPath, err)
		}
		parts = append(parts, t.Path+"|"+t.TokenID)
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, ";") + "|mac-fsevents"))
	return &fseventsWatcher{targets: targets, hash: hex.EncodeToString(sum[:]), w: fw}, nil
}

func (w *fseventsWatcher) Tier() Tier { return TierMacFSEvents }
func (w *fseventsWatcher) Capabilities() string {
	return "modify/delete/rename via fsnotify(kqueue); NO read/open, NO pid"
}
func (w *fseventsWatcher) ConfigHash() string { return w.hash }
func (w *fseventsWatcher) Close() error {
	if w.w != nil {
		return w.w.Close()
	}
	return nil
}

func (w *fseventsWatcher) Run(ctx context.Context, out chan<- Touch) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case err, ok := <-w.w.Errors:
			if !ok {
				return nil
			}
			if ctx.Err() != nil {
				return nil
			}
			return err
		case e, ok := <-w.w.Events:
			if !ok {
				return nil
			}
			if e.Has(fsnotify.Chmod) {
				continue
			}
			if !pathWatched(e.Name, w.targets) {
				// Directory watch may emit sibling names; ignore non-targets.
				continue
			}
			action := "modify"
			switch {
			case e.Has(fsnotify.Remove):
				action = "delete"
			case e.Has(fsnotify.Rename):
				action = "rename"
			case e.Has(fsnotify.Write), e.Has(fsnotify.Create):
				action = "modify"
			}
			touch := Touch{
				Path:     e.Name,
				Action:   action,
				Occurred: time.Now().UTC(),
				Proven:   true,
			}
			select {
			case out <- touch:
			case <-ctx.Done():
				return nil
			}
		}
	}
}
