package sink

import (
	"sync"
	"time"

	"github.com/jimididit/kunari/internal/event"
)

type dedupeKey struct {
	Token  string
	Actor  string
	Action string
}

// Throttle suppresses duplicate alerts while still counting suppressions.
type Throttle struct {
	mu      sync.Mutex
	window  time.Duration
	last    map[dedupeKey]time.Time
	suppressed map[dedupeKey]int
}

func NewThrottle(window time.Duration) *Throttle {
	return &Throttle{
		window:     window,
		last:       map[dedupeKey]time.Time{},
		suppressed: map[dedupeKey]int{},
	}
}

// Allow returns whether to emit an alert, and how many similar events were suppressed since last emit.
func (t *Throttle) Allow(ev *event.Event) (allow bool, suppressed int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	actor := ""
	if ev.Actor != nil {
		actor = ev.Actor.Exe
	}
	k := dedupeKey{Token: ev.TokenID, Actor: actor, Action: ev.Action}
	now := time.Now()
	if prev, ok := t.last[k]; ok && now.Sub(prev) < t.window {
		t.suppressed[k]++
		return false, t.suppressed[k]
	}
	suppressed = t.suppressed[k]
	t.suppressed[k] = 0
	t.last[k] = now
	return true, suppressed
}
