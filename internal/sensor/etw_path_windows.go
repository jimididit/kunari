//go:build windows

package sensor

import (
	"fmt"
	"strings"
	"sync"

	"golang.org/x/sys/windows"
)

// ntPathResolver maps \Device\HarddiskVolumeN\... to Win32 paths (C:\...).
type ntPathResolver struct {
	mu   sync.RWMutex
	devs map[string]string // lower device path prefix -> "C:"
}

func newNTPathResolver() *ntPathResolver {
	r := &ntPathResolver{devs: map[string]string{}}
	r.refresh()
	return r
}

func (r *ntPathResolver) refresh() {
	buf := make([]uint16, 512)
	n, err := windows.GetLogicalDriveStrings(uint32(len(buf)), &buf[0])
	if err != nil || n == 0 {
		return
	}
	next := map[string]string{}
	for i := 0; i < int(n); {
		if buf[i] == 0 {
			i++
			continue
		}
		end := i
		for end < int(n) && buf[end] != 0 {
			end++
		}
		drive := windows.UTF16ToString(buf[i:end]) // e.g. "C:\"
		i = end + 1
		letter := strings.TrimRight(drive, `\`)
		if letter == "" {
			continue
		}
		name, err := windows.UTF16PtrFromString(letter)
		if err != nil {
			continue
		}
		out := make([]uint16, 512)
		m, err := windows.QueryDosDevice(name, &out[0], uint32(len(out)))
		if err != nil || m == 0 {
			continue
		}
		// First NUL-terminated string only.
		device := windows.UTF16ToString(out[:m])
		if device == "" {
			continue
		}
		next[strings.ToLower(device)] = letter
	}
	r.mu.Lock()
	r.devs = next
	r.mu.Unlock()
}

func (r *ntPathResolver) toWin32(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if len(path) >= 2 && path[1] == ':' {
		return path
	}
	if strings.HasPrefix(path, `\??\`) {
		return path[4:]
	}
	if strings.HasPrefix(path, `\\?\`) {
		return path[4:]
	}
	lower := strings.ToLower(path)
	r.mu.RLock()
	devs := r.devs
	r.mu.RUnlock()
	bestDev, bestDrive := "", ""
	for dev, drive := range devs {
		if !strings.HasPrefix(lower, dev) || len(dev) <= len(bestDev) {
			continue
		}
		// Path-component boundary: reject HarddiskVolume3 matching HarddiskVolume30.
		rest := lower[len(dev):]
		if rest != "" && !strings.HasPrefix(rest, `\`) {
			continue
		}
		bestDev, bestDrive = dev, drive
	}
	if bestDrive == "" {
		return path
	}
	rest := path[len(bestDev):]
	if rest == "" {
		return bestDrive + `\`
	}
	if !strings.HasPrefix(rest, `\`) {
		// Should be unreachable after boundary check; keep path unchanged.
		return path
	}
	return bestDrive + rest
}

func etwObjectKey(v interface{}) string {
	if v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	default:
		return fmt.Sprintf("%v", t)
	}
}
