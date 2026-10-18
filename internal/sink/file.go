package sink

import (
	"context"
	"os"
	"sync"

	"github.com/jimididit/kunari/internal/event"
)

type FileSink struct {
	path string
	mu   sync.Mutex
}

func NewFileSink(path string) *FileSink {
	return &FileSink{path: path}
}

func (f *FileSink) Name() string { return "file:" + f.path }

func (f *FileSink) Deliver(_ context.Context, ev *event.Event) error {
	b, err := MarshalEvent(ev)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	fh, err := os.OpenFile(f.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer fh.Close()
	_, err = fh.Write(append(b, '\n'))
	return err
}
