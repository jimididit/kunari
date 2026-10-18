package sensor

import (
	"context"
	"time"
)

// Tier is the detection mechanism actually armed. Always report honestly.
type Tier string

const (
	TierFanotify    Tier = "fanotify"
	TierInotify     Tier = "inotify"
	TierAuditd      Tier = "auditd"
	TierWinSACL     Tier = "win-sacl-4663"
	TierWinRDC      Tier = "win-rdc" // ReadDirectoryChangesW - no read/open
	TierMacESLogger Tier = "mac-eslogger"
	TierMacFSEvents Tier = "mac-fsevents"
	TierNone        Tier = "none"
)

// Touch is a raw filesystem observation before enrichment into kunari.event/1.
type Touch struct {
	Path      string
	Action    string // open|read|modify|delete|rename|exec|attrib|list
	PID       int
	Occurred  time.Time
	Extra     map[string]string
	Proven    bool // false => confidence.action=inferred
}

// Watcher watches configured paths and emits touches until ctx is done.
type Watcher interface {
	Tier() Tier
	// Capabilities describes what this tier can prove (for logging/heartbeat).
	Capabilities() string
	// ConfigHash is a stable hash of watch rules / SACL / audit config for drift.
	ConfigHash() string
	Run(ctx context.Context, out chan<- Touch) error
	Close() error
}

// Target is a path (file or directory) to watch, with optional token metadata.
type Target struct {
	Path    string
	TokenID string
	Memo    string
}
