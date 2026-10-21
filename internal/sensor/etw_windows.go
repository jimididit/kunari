//go:build windows

package sensor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fredwangwang/etw"
	"golang.org/x/sys/windows"
)

// Microsoft-Windows-Kernel-File
var kernelFileProviderGUID = windows.GUID{
	Data1: 0xedd08927,
	Data2: 0x9cc4,
	Data3: 0x4e65,
	Data4: [8]byte{0xb9, 0x70, 0xc2, 0x56, 0x0f, 0xb5, 0xc2, 0x89},
}

const etwSessionName = "KunariKernelFile"

type etwWatcher struct {
	targets []Target
	hash    string
	session *etw.Session
	paths   *ntPathResolver

	mu     sync.Mutex
	byObj  map[string]string // FileObject/FileKey -> last known path
	closed bool
}

func newETW(targets []Target) (*etwWatcher, error) {
	if len(targets) == 0 {
		return nil, fmt.Errorf("no targets")
	}
	for _, t := range targets {
		if strings.TrimSpace(t.Path) == "" {
			return nil, fmt.Errorf("empty target path")
		}
	}
	session, err := openKernelFileSession()
	if err != nil {
		return nil, err
	}
	var parts []string
	for _, t := range targets {
		parts = append(parts, strings.ToLower(filepath.Clean(t.Path))+"|"+t.TokenID)
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, ";") + "|win-etw-kernel-file"))
	return &etwWatcher{
		targets: targets,
		hash:    hex.EncodeToString(sum[:]),
		session: session,
		paths:   newNTPathResolver(),
		byObj:   map[string]string{},
	}, nil
}

func openKernelFileSession() (*etw.Session, error) {
	opts := []etw.Option{
		etw.WithName(etwSessionName),
		etw.WithLevel(etw.TRACE_LEVEL_INFORMATION),
		etw.WithMatchKeywords(etwMatchAnyKeyword(), 0),
		etw.WithEventIDs(etwEventIDs()...),
	}
	session, err := etw.NewSession(kernelFileProviderGUID, opts...)
	if err == nil {
		return session, nil
	}
	var exists etw.ExistsError
	if errors.As(err, &exists) {
		_ = etw.KillSession(exists.SessionName)
		session, err = etw.NewSession(kernelFileProviderGUID, opts...)
		if err == nil {
			return session, nil
		}
	}
	return nil, fmt.Errorf("start Kernel-File ETW session (usually needs elevation): %w", err)
}

func (w *etwWatcher) Tier() Tier { return TierWinETW }
func (w *etwWatcher) Capabilities() string {
	return "experimental Microsoft-Windows-Kernel-File ETW; open/read/modify/delete/rename candidate; admin session; lab NV (no per-file SACL)"
}
func (w *etwWatcher) ConfigHash() string { return w.hash }

func (w *etwWatcher) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	if w.session != nil {
		_ = w.session.Close()
		w.session = nil
	}
	return nil
}

func (w *etwWatcher) Run(ctx context.Context, out chan<- Touch) error {
	if w.session == nil {
		return fmt.Errorf("etw session not started")
	}
	errCh := make(chan error, 1)
	go func() {
		err := w.session.Process(func(e *etw.Event) {
			touch, ok := w.touchFromEvent(e)
			if !ok {
				return
			}
			select {
			case out <- touch:
			case <-ctx.Done():
			}
		})
		errCh <- err
	}()

	select {
	case <-ctx.Done():
		_ = w.Close()
		// Process returns after Close; ignore close races.
		select {
		case <-errCh:
		case <-time.After(2 * time.Second):
		}
		return nil
	case err := <-errCh:
		_ = w.Close()
		if err != nil && ctx.Err() == nil {
			return err
		}
		return nil
	}
}

func (w *etwWatcher) touchFromEvent(e *etw.Event) (Touch, bool) {
	action, ok := etwAction(e.Header.ID)
	if !ok {
		return Touch{}, false
	}
	props, err := e.EventProperties()
	if err != nil {
		props = map[string]interface{}{}
	}

	obj := etwObjectKey(props["FileObject"])
	if obj == "" {
		obj = etwObjectKey(props["FileKey"])
	}
	rawName := etwPropString(props, "FileName", "OpenPath", "SourceFileName")
	path := ""
	if rawName != "" {
		path = w.paths.toWin32(rawName)
		if obj != "" {
			w.mu.Lock()
			w.byObj[obj] = path
			w.mu.Unlock()
		}
	} else if obj != "" {
		w.mu.Lock()
		path = w.byObj[obj]
		w.mu.Unlock()
	}
	if path == "" {
		return Touch{}, false
	}

	matched := ""
	for _, t := range w.targets {
		if etwPathMatches(path, t.Path) {
			matched = t.Path
			break
		}
	}
	if matched == "" {
		return Touch{}, false
	}

	extra := map[string]string{
		"etw_event_id": fmt.Sprintf("%d", e.Header.ID),
		"etw_provider": "Microsoft-Windows-Kernel-File",
	}
	if rawName != "" && rawName != path {
		extra["etw_raw_path"] = rawName
	}
	return Touch{
		Path:     matched,
		Action:   action,
		PID:      int(e.Header.ProcessID),
		Occurred: time.Now().UTC(),
		Extra:    extra,
		// Lab has not proven action correctness yet - keep inferred until re-proof.
		Proven: false,
	}, true
}
