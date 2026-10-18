package hub

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/jimididit/kunari/internal/event"
)

// apiSubs fans out live events to SSE clients.
type apiSubs struct {
	mu   sync.Mutex
	subs map[chan *event.Event]struct{}
}

func newAPISubs() *apiSubs {
	return &apiSubs{subs: make(map[chan *event.Event]struct{})}
}

func (a *apiSubs) Subscribe() chan *event.Event {
	ch := make(chan *event.Event, 256)
	a.mu.Lock()
	a.subs[ch] = struct{}{}
	a.mu.Unlock()
	return ch
}

func (a *apiSubs) Unsubscribe(ch chan *event.Event) {
	a.mu.Lock()
	delete(a.subs, ch)
	a.mu.Unlock()
	close(ch)
}

func (a *apiSubs) Broadcast(ev *event.Event) {
	if ev == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for ch := range a.subs {
		select {
		case ch <- ev:
		default:
			// Slow consumer: drop rather than block ingest/beacon path.
		}
	}
}

func (h *Hub) requireAPIAuth(allowQuery bool, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.checkAPIAuth(r, allowQuery) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="kunari"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func (h *Hub) checkAPIAuth(r *http.Request, allowQuery bool) bool {
	if len(h.apiToken) == 0 {
		return false
	}
	got := apiTokenFromRequest(r, allowQuery)
	if got == "" {
		return false
	}
	return tokenEqual(h.apiToken, got)
}

func apiTokenFromRequest(r *http.Request, allowQuery bool) string {
	if auth := r.Header.Get("Authorization"); auth != "" {
		const p = "Bearer "
		if strings.HasPrefix(auth, p) {
			return strings.TrimSpace(auth[len(p):])
		}
	}
	if v := r.Header.Get("X-Kunari-API-Key"); v != "" {
		return strings.TrimSpace(v)
	}
	// EventSource cannot set Authorization headers. Query tokens may appear in
	// reverse-proxy access logs - prefer Bearer when the client can set headers.
	if allowQuery {
		return strings.TrimSpace(r.URL.Query().Get("token"))
	}
	return ""
}

func tokenEqual(secret []byte, presented string) bool {
	// Compare against hex encoding of secret (file format) and raw secret bytes.
	wantHex := hex.EncodeToString(secret)
	a := sha256.Sum256([]byte(wantHex))
	b := sha256.Sum256([]byte(presented))
	if subtle.ConstantTimeCompare(a[:], b[:]) == 1 {
		return true
	}
	c := sha256.Sum256(secret)
	d := sha256.Sum256([]byte(presented))
	return subtle.ConstantTimeCompare(c[:], d[:]) == 1
}

func (h *Hub) handleListEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	after := uint64(0)
	if s := q.Get("after_seq"); s != "" {
		n, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			http.Error(w, "invalid after_seq", http.StatusBadRequest)
			return
		}
		after = n
	}
	limit := 100
	if s := q.Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 {
			http.Error(w, "invalid limit", http.StatusBadRequest)
			return
		}
		limit = n
	}
	events, next, err := event.ReadAfter(h.chain.FilePath(), after, limit)
	if err != nil {
		h.log.Error("list events", "err", err)
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	if events == nil {
		events = []event.Event{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"events":   events,
		"count":    len(events),
		"next_seq": next,
		"last_seq": h.chain.LastSeq(),
	})
}
