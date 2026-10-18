//go:build linux

package sensor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

type inotifyWatcher struct {
	targets []Target
	fd      int
	wdPath  map[int]Target
	hash    string
}

func newInotify(targets []Target) (*inotifyWatcher, error) {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return nil, fmt.Errorf("inotify init: %w", err)
	}
	w := &inotifyWatcher{targets: targets, fd: fd, wdPath: map[int]Target{}}
	var parts []string
	mask := uint32(unix.IN_ACCESS | unix.IN_OPEN | unix.IN_MODIFY | unix.IN_CLOSE_WRITE |
		unix.IN_ATTRIB | unix.IN_DELETE_SELF | unix.IN_MOVE_SELF)
	for _, t := range targets {
		wd, err := unix.InotifyAddWatch(fd, t.Path, mask)
		if err != nil {
			_ = unix.Close(fd)
			return nil, fmt.Errorf("inotify watch %s: %w", t.Path, err)
		}
		w.wdPath[wd] = t
		parts = append(parts, t.Path+"|"+t.TokenID)
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, ";") + "|inotify"))
	w.hash = hex.EncodeToString(sum[:])
	return w, nil
}

func (w *inotifyWatcher) Tier() Tier           { return TierInotify }
func (w *inotifyWatcher) Capabilities() string { return "open,read,modify,delete,rename; no pid" }
func (w *inotifyWatcher) ConfigHash() string   { return w.hash }
func (w *inotifyWatcher) Close() error         { return unix.Close(w.fd) }

func (w *inotifyWatcher) Run(ctx context.Context, out chan<- Touch) error {
	buf := make([]byte, unix.SizeofInotifyEvent*64)
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		n, err := unix.Read(w.fd, buf)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				select {
				case <-ctx.Done():
					return nil
				case <-time.After(50 * time.Millisecond):
				}
				continue
			}
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		offset := 0
		for offset+unix.SizeofInotifyEvent <= n {
			ev := (*unix.InotifyEvent)(unsafe.Pointer(&buf[offset]))
			t, ok := w.wdPath[int(ev.Wd)]
			path := ""
			if ok {
				path = t.Path
			}
			touch := Touch{
				Path:     path,
				Action:   mapInMask(ev.Mask),
				Occurred: time.Now().UTC(),
				Proven:   true,
			}
			select {
			case out <- touch:
			case <-ctx.Done():
				return nil
			}
			offset += unix.SizeofInotifyEvent + int(ev.Len)
		}
	}
}

func mapInMask(mask uint32) string {
	switch {
	case mask&unix.IN_OPEN != 0:
		return "open"
	case mask&unix.IN_ACCESS != 0:
		return "read"
	case mask&unix.IN_MODIFY != 0 || mask&unix.IN_CLOSE_WRITE != 0:
		return "modify"
	case mask&unix.IN_DELETE_SELF != 0:
		return "delete"
	case mask&unix.IN_MOVE_SELF != 0:
		return "rename"
	case mask&unix.IN_ATTRIB != 0:
		return "attrib"
	default:
		return "open"
	}
}
