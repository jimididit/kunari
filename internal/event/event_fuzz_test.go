package event

import (
	"encoding/json"
	"testing"
	"time"
)

func FuzzCanonicalPayload(f *testing.F) {
	seed, _ := json.Marshal(Event{
		Schema: Schema, EventID: "id", TokenID: "tok",
		ObservedAt: time.Unix(0, 0).UTC(), Detector: "d", DetectionTier: "t", Action: "open",
	})
	f.Add(seed)
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		var ev Event
		if err := json.Unmarshal(raw, &ev); err != nil {
			return
		}
		_, _ = ev.CanonicalPayload()
	})
}
