package event

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"

	"github.com/jimididit/kunari/internal/safepath"
)

const maxReadLine = 2 << 20 // 2 MiB per event line

// ReadAfter returns up to limit events with Integrity.Seq > afterSeq.
// nextSeq is the last returned seq (or afterSeq when empty).
func ReadAfter(path string, afterSeq uint64, limit int) (events []Event, nextSeq uint64, err error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	path, err = safepath.Clean(path)
	if err != nil {
		return nil, afterSeq, err
	}
	f, err := os.Open(path) // #nosec G304 -- path cleaned by safepath.Clean
	if err != nil {
		if os.IsNotExist(err) {
			return nil, afterSeq, nil
		}
		return nil, afterSeq, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, maxReadLine)
	nextSeq = afterSeq
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var ev Event
		if err := json.Unmarshal(line, &ev); err != nil {
			return events, nextSeq, fmt.Errorf("corrupt event log: %w", err)
		}
		if ev.Integrity.Seq <= afterSeq {
			continue
		}
		events = append(events, ev)
		nextSeq = ev.Integrity.Seq
		if len(events) >= limit {
			break
		}
	}
	if err := sc.Err(); err != nil {
		return events, nextSeq, err
	}
	return events, nextSeq, nil
}

// FilePath returns the on-disk jsonl path.
func (c *Chain) FilePath() string { return c.path }

// LastSeq returns the last appended sequence number.
func (c *Chain) LastSeq() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.seq
}
