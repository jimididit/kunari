//go:build windows

package sensor

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

type rdcWatcher struct {
	targets []Target
	hash    string
}

func newRDC(targets []Target) (*rdcWatcher, error) {
	if len(targets) == 0 {
		return nil, fmt.Errorf("no targets")
	}
	var parts []string
	for _, t := range targets {
		if _, err := os.Stat(t.Path); err != nil {
			return nil, fmt.Errorf("stat %s: %w", t.Path, err)
		}
		parts = append(parts, t.Path+"|"+t.TokenID)
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, ";") + "|win-rdc"))
	return &rdcWatcher{targets: targets, hash: hex.EncodeToString(sum[:])}, nil
}

func (w *rdcWatcher) Tier() Tier { return TierWinRDC }
func (w *rdcWatcher) Capabilities() string {
	return "modify,delete,rename via ReadDirectoryChangesW; NO read/open (use win-sacl-4663)"
}
func (w *rdcWatcher) ConfigHash() string { return w.hash }
func (w *rdcWatcher) Close() error       { return nil }

func (w *rdcWatcher) Run(ctx context.Context, out chan<- Touch) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errCh := make(chan error, len(w.targets))
	for _, t := range w.targets {
		t := t
		go func() {
			errCh <- watchRDCOne(ctx, t, out)
		}()
	}
	select {
	case <-ctx.Done():
		return nil
	case err := <-errCh:
		cancel()
		if err != nil && ctx.Err() == nil {
			return err
		}
		return nil
	}
}

func watchRDCOne(ctx context.Context, t Target, out chan<- Touch) error {
	dir := t.Path
	watchFile := ""
	fi, err := os.Stat(t.Path)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		dir = filepath.Dir(t.Path)
		watchFile = strings.ToLower(filepath.Base(t.Path))
	}
	h, err := windows.CreateFile(
		windows.StringToUTF16Ptr(dir),
		windows.FILE_LIST_DIRECTORY,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return fmt.Errorf("CreateFile %s: %w", dir, err)
	}
	defer windows.CloseHandle(h)

	buf := make([]byte, 64*1024)
	mask := uint32(windows.FILE_NOTIFY_CHANGE_FILE_NAME |
		windows.FILE_NOTIFY_CHANGE_DIR_NAME |
		windows.FILE_NOTIFY_CHANGE_SIZE |
		windows.FILE_NOTIFY_CHANGE_LAST_WRITE |
		windows.FILE_NOTIFY_CHANGE_ATTRIBUTES)

	for {
		if ctx.Err() != nil {
			return nil
		}
		var bytesReturned uint32
		bufLen := len(buf)
		if bufLen == 0 || bufLen > int(^uint32(0)) {
			return fmt.Errorf("invalid notify buffer size %d", bufLen)
		}
		err := windows.ReadDirectoryChanges(h, &buf[0], uint32(bufLen), false, mask, &bytesReturned, nil, 0) //nosec G602
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		emitRDC(buf[:bytesReturned], dir, watchFile, t, out)
	}
}

func emitRDC(buf []byte, dir, watchFile string, t Target, out chan<- Touch) {
	offset := 0
	for offset+12 <= len(buf) {
		next := binary.LittleEndian.Uint32(buf[offset:])
		actionCode := binary.LittleEndian.Uint32(buf[offset+4:])
		nameLen := binary.LittleEndian.Uint32(buf[offset+8:])
		nameStart := offset + 12
		nameEnd := nameStart + int(nameLen)
		if nameEnd > len(buf) {
			return
		}
		u16 := make([]uint16, nameLen/2)
		for i := range u16 {
			u16[i] = binary.LittleEndian.Uint16(buf[nameStart+i*2:])
		}
		name := string(utf16.Decode(u16))
		if watchFile != "" && strings.ToLower(name) != watchFile {
			if next == 0 {
				return
			}
			offset += int(next)
			continue
		}
		full := filepath.Join(dir, name)
		if watchFile != "" {
			full = t.Path
		}
		touch := Touch{
			Path:     full,
			Action:   mapRDCAction(actionCode),
			Occurred: time.Now().UTC(),
			Proven:   true,
		}
		select {
		case out <- touch:
		default:
		}
		if next == 0 {
			return
		}
		offset += int(next)
	}
}

func mapRDCAction(code uint32) string {
	switch code {
	case windows.FILE_ACTION_REMOVED:
		return "delete"
	case windows.FILE_ACTION_MODIFIED, windows.FILE_ACTION_ADDED:
		return "modify"
	case windows.FILE_ACTION_RENAMED_OLD_NAME, windows.FILE_ACTION_RENAMED_NEW_NAME:
		return "rename"
	default:
		return "modify"
	}
}
