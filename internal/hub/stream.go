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

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	// Subscribe before backfill so live events during the read are not missed
	// (duplicates filtered by seq).
	sub := h.subs.Subscribe()
	defer h.subs.Unsubscribe(sub)

	events, _, err := event.ReadAfter(h.chain.FilePath(), after, 1000)
	if err != nil {
		h.log.Error("sse backfill", "err", err)
		return
	}
	for i := range events {
		if err := writeSSEEvent(w, &events[i]); err != nil {
			return
		}
		flusher.Flush()
		after = events[i].Integrity.Seq
	}

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
			if err := writeSSEEvent(w, ev); err != nil {
				return
			}
			flusher.Flush()
			after = ev.Integrity.Seq
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
