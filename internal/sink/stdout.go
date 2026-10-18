package sink

import (
	"context"
	"fmt"
	"os"

	"github.com/jimididit/kunari/internal/event"
)

type StdoutSink struct{}

func NewStdoutSink() *StdoutSink { return &StdoutSink{} }

func (s *StdoutSink) Name() string { return "stdout" }

func (s *StdoutSink) Deliver(_ context.Context, ev *event.Event) error {
	b, err := MarshalEvent(ev)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(os.Stdout, string(b))
	return err
}
