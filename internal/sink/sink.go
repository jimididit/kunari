package sink

import (
	"context"
	"encoding/json"

	"github.com/jimididit/kunari/internal/event"
)

// Sink delivers an event. Implementations must treat event_id as idempotent.
type Sink interface {
	Name() string
	Deliver(ctx context.Context, ev *event.Event) error
}

type Envelope struct {
	Event *event.Event `json:"event"`
}

func MarshalEvent(ev *event.Event) ([]byte, error) {
	return json.Marshal(ev)
}
