package sink

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"math/rand"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/jimididit/kunari/internal/event"
	"github.com/jimididit/kunari/internal/safepath"
)

// Queue is a disk-backed store-and-forward fan-out. Sink failures are logged and
// retried; sinks are never silently disabled.
type Queue struct {
	dir    string
	sinks  []Sink
	log    *slog.Logger
	mu     sync.Mutex
	closed bool
	wake   chan struct{}
}

func NewQueue(dir string, log *slog.Logger, sinks ...Sink) (*Queue, error) {
	if log == nil {
		log = slog.Default()
	}
	dir, err := safepath.Clean(dir)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	q := &Queue{dir: dir, sinks: sinks, log: log, wake: make(chan struct{}, 1)}
	return q, nil
}

func (q *Queue) Enqueue(ev *event.Event) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return errors.New("queue closed")
	}
	b, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	name := filepath.Join(q.dir, ev.EventID+".json")
	tmp := name + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, name); err != nil {
		return err
	}
	select {
	case q.wake <- struct{}{}:
	default:
	}
	return nil
}

func (q *Queue) Run(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		q.drain(ctx)
		select {
		case <-ctx.Done():
			return
		case <-q.wake:
		case <-ticker.C:
		}
	}
}

func (q *Queue) Close() {
	q.mu.Lock()
	q.closed = true
	q.mu.Unlock()
}

func (q *Queue) drain(ctx context.Context) {
	entries, err := os.ReadDir(q.dir)
	if err != nil {
		q.log.Error("queue read", "err", err)
		return
	}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		// Queue entries are only files we created under q.dir (basename from ReadDir).
		name := filepath.Base(e.Name())
		if name == "." || name == ".." || name != e.Name() {
			continue
		}
		path := filepath.Join(q.dir, name)
		b, err := os.ReadFile(path) // path confined to q.dir + basename
		if err != nil {
			continue
		}
		var ev event.Event
		if err := json.Unmarshal(b, &ev); err != nil {
			q.log.Error("queue corrupt event", "path", path, "err", err)
			_ = os.Remove(path)
			continue
		}
		if err := q.deliverAll(ctx, &ev); err != nil {
			q.log.Error("sink delivery incomplete - will retry; sink NOT disabled",
				"event_id", ev.EventID, "err", err)
			continue
		}
		_ = os.Remove(path)
	}
}

func (q *Queue) deliverAll(ctx context.Context, ev *event.Event) error {
	var first error
	for _, s := range q.sinks {
		if err := deliverWithBackoff(ctx, s, ev); err != nil {
			q.log.Error("sink failure surfaced", "sink", s.Name(), "err", err)
			if first == nil {
				first = err
			}
		}
	}
	return first
}

func deliverWithBackoff(ctx context.Context, s Sink, ev *event.Event) error {
	var err error
	for attempt := 0; attempt < 5; attempt++ {
		err = s.Deliver(ctx, ev)
		if err == nil {
			return nil
		}
		d := time.Duration(100*(1<<attempt))*time.Millisecond + time.Duration(rand.Intn(50))*time.Millisecond
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(d):
		}
	}
	return err
}
