package hub

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/jimididit/kunari/internal/event"
)

func (h *Hub) handleEventStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	after := uint64(0)
	if s := r.URL.Query().Get("after_seq"); s != "" {
		n, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			http.Error(w, "invalid after_seq", http.StatusBadRequest)
			return
		}
		after = n
	}
	// Default: skip heartbeats in backfill so the live table is not flooded.
	includeHeartbeats := r.URL.Query().Get("include_heartbeats") == "1" ||
		r.URL.Query().Get("include_heartbeats") == "true"

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	// Subscribe before backfill so live events during the read are not missed
	// (duplicates filtered by seq). Drain the buffer between pages so Broadcast
	// does not fill the channel during a long catch-up.
	sub := h.subs.Subscribe()
	defer h.subs.Unsubscribe(sub)

	for {
		drainSub(sub)
		events, _, err := event.ReadAfter(h.chain.FilePath(), after, 1000)
		if err != nil {
			h.log.Error("sse backfill", "err", err)
			return
		}
		if len(events) == 0 {
			break
		}
		for i := range events {
			after = events[i].Integrity.Seq
			if !includeHeartbeats && events[i].TokenID == "heartbeat" {
				continue
			}
			if err := writeSSEEvent(w, &events[i]); err != nil {
				return
			}
			flusher.Flush()
		}
		if len(events) < 1000 {
			break
		}
	}
	drainSub(sub)

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			if _, err := fmt.Fprintf(w, ": ping\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case ev, ok := <-sub:
			if !ok {
				return
			}
			if ev.Integrity.Seq <= after {
				continue
			}
			after = ev.Integrity.Seq
			if !includeHeartbeats && ev.TokenID == "heartbeat" {
				continue
			}
			if err := writeSSEEvent(w, ev); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func drainSub(ch <-chan *event.Event) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}

func writeSSEEvent(w http.ResponseWriter, ev *event.Event) error {
	b, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "id: %d\nevent: kunari.event\ndata: %s\n\n", ev.Integrity.Seq, b)
	return err
}
