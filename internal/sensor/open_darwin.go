//go:build darwin

package sensor

import "fmt"

func OpenBest(targets []Target) (Watcher, error) {
	if len(targets) == 0 {
		return nil, fmt.Errorf("no targets")
	}
	w, esErr := newESLogger(targets)
	if esErr == nil {
		return w, nil
	}
	fw, fsErr := newFSEvents(targets)
	if fsErr == nil {
		return fw, nil
	}
	return nil, fmt.Errorf("eslogger: %v; fsevents: %w", esErr, fsErr)
}

func PlatformInstallHints(targets []Target) string {
	return `# Kunari macOS sentinel setup

# OPSEC: chmod 0600 sentinel.json + secrets; chmod 0700 data_dir; dedicated user when possible.

## Preferred tier: mac-eslogger (macOS 13+)

1. Grant Terminal/kunari Full Disk Access (System Settings > Privacy & Security).
2. Run elevated: sudo kunari sentinel run --config sentinel.json
3. eslogger must be present (ships with macOS Ventura+).
4. OpenBest only selects this tier when running as root; otherwise it uses mac-fsevents.

## Fallback tier: mac-fsevents
Used automatically when eslogger is missing, not root, or cannot start.
Sees modify/delete/rename only - not reads/opens, and no process attribution.

## Endpoint Security system extension
Shipping a notarized ES client is out of scope for v0.1 (Phase 3 uses eslogger CLI).

## WebDAV canary filesystem
Evaluated as a later enhancement (see internal research notes); not armed in this release.
`
}
