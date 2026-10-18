package event

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/jimididit/kunari/internal/safepath"
)

const maxReadLine = 2 << 20 // 2 MiB per event line

// ReadAfter returns up to limit events with Integrity.Seq > afterSeq.
// nextSeq is the last returned seq (or afterSeq when empty).
// A truncated trailing line (concurrent Append mid-write) is skipped, not fatal.
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

	r := bufio.NewReaderSize(f, 64*1024)
	nextSeq = afterSeq
	for len(events) < limit {
		line, readErr := r.ReadBytes('\n')
		truncated := false
		if readErr != nil {
			if readErr != io.EOF {
				return events, nextSeq, readErr
			}
			if len(line) == 0 {
				break
			}
			// Last chunk without a trailing newline - may be an in-progress append.
			truncated = true
		}
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			if truncated {
				break
			}
			continue
		}
		if len(line) > maxReadLine {
			return events, nextSeq, fmt.Errorf("event line exceeds %d bytes", maxReadLine)
		}
		var ev Event
		if err := json.Unmarshal(line, &ev); err != nil {
			if truncated {
				// Incomplete JSON at EOF while hub is appending - try again next page.
				break
			}
			return events, nextSeq, fmt.Errorf("corrupt event log: %w", err)
		}
		if ev.Integrity.Seq <= afterSeq {
			if truncated {
				break
			}
			continue
		}
		events = append(events, ev)
		nextSeq = ev.Integrity.Seq
		if truncated {
			break
		}
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
