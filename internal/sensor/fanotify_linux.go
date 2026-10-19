//go:build linux

package sensor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

type fanotifyWatcher struct {
	targets []Target
	fd      int
	hash    string
}

func newFanotify(targets []Target) (*fanotifyWatcher, error) {
	fd, err := unix.FanotifyInit(unix.FAN_CLASS_NOTIF|unix.FAN_CLOEXEC|unix.FAN_NONBLOCK, unix.O_RDONLY)
	if err != nil {
		return nil, fmt.Errorf("fanotify init: %w", err)
	}
	w := &fanotifyWatcher{targets: targets, fd: fd}
	var hashParts []string
	for _, t := range targets {
		mask := uint64(unix.FAN_ACCESS | unix.FAN_OPEN | unix.FAN_MODIFY | unix.FAN_CLOSE_WRITE | unix.FAN_OPEN_EXEC)
		if err := unix.FanotifyMark(fd, unix.FAN_MARK_ADD, mask, unix.AT_FDCWD, t.Path); err != nil {
			_ = unix.Close(fd)
			return nil, fmt.Errorf("fanotify mark %s: %w", t.Path, err)
		}
		hashParts = append(hashParts, t.Path+"|"+t.TokenID)
	}
	sum := sha256.Sum256([]byte(strings.Join(hashParts, ";") + "|fanotify"))
	w.hash = hex.EncodeToString(sum[:])
	return w, nil
}

func (w *fanotifyWatcher) Tier() Tier             { return TierFanotify }
func (w *fanotifyWatcher) Capabilities() string   { return "open,read,modify,exec(+pid); no FAN_*_PERM" }
func (w *fanotifyWatcher) ConfigHash() string     { return w.hash }
func (w *fanotifyWatcher) Close() error           { return unix.Close(w.fd) }

func (w *fanotifyWatcher) Run(ctx context.Context, out chan<- Touch) error {
	buf := make([]byte, 4096*4)
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
		for offset < n {
			if offset+24 > n {
				break
			}
			// Kernel fanotify wire format; Event_len bounds checked below.
			meta := (*unix.FanotifyEventMetadata)(unsafe.Pointer(&buf[offset])) // #nosec G103
			if int(meta.Event_len) == 0 || offset+int(meta.Event_len) > n {
				break
			}
			path := fdPath(int(meta.Fd))
			t := Touch{
				Path:     path,
				Action:   mapFanMask(meta.Mask),
				PID:      int(meta.Pid),
				Occurred: time.Now().UTC(),
				Proven:   true,
			}
			_ = unix.Close(int(meta.Fd))
			select {
			case out <- t:
			case <-ctx.Done():
				return nil
			}
			offset += int(meta.Event_len)
		}
	}
}

func mapFanMask(mask uint64) string {
	// Prefer the most specific bit when the kernel ORs multiple into one event.
	// Checking FAN_OPEN first would hide ACCESS/MODIFY on multi-bit masks.
	switch {
	case mask&unix.FAN_OPEN_EXEC != 0:
		return "exec"
	case mask&unix.FAN_MODIFY != 0 || mask&unix.FAN_CLOSE_WRITE != 0:
		return "modify"
	case mask&unix.FAN_ACCESS != 0:
		return "read"
	case mask&unix.FAN_OPEN != 0:
		return "open"
	default:
		return "open"
	}
}

func fdPath(fd int) string {
	if fd < 0 {
		return ""
	}
	p, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		return ""
	}
	return p
}
