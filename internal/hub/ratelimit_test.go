package hub

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestIPRateLimiterAllowAndDeny(t *testing.T) {
	lim := newIPRateLimiter(2) // 2/min burst 2
	if lim == nil {
		t.Fatal("expected limiter")
	}
	base := time.Unix(1_700_000_000, 0).UTC()
	lim.now = func() time.Time { return base }

	if ok, _ := lim.allow("1.2.3.4"); !ok {
		t.Fatal("first allow")
	}
	if ok, _ := lim.allow("1.2.3.4"); !ok {
		t.Fatal("second allow (burst)")
	}
	ok, retry := lim.allow("1.2.3.4")
	if ok {
		t.Fatal("third must deny")
	}
	if retry < time.Second {
		t.Fatalf("retry-after too small: %v", retry)
	}
	// Other IP unaffected.
	if ok, _ := lim.allow("9.9.9.9"); !ok {
		t.Fatal("other IP must allow")
	}
	// Refill after 60s at 2/min -> +2 tokens.
	lim.now = func() time.Time { return base.Add(60 * time.Second) }
	if ok, _ := lim.allow("1.2.3.4"); !ok {
		t.Fatal("expected allow after refill")
	}
}

func TestIPRateLimiterDisabled(t *testing.T) {
	if newIPRateLimiter(0) != nil {
		t.Fatal("0 must disable")
	}
	if newIPRateLimiter(-1) != nil {
		t.Fatal("negative must disable")
	}
}

func TestLimitPublicReturns429(t *testing.T) {
	h := &Hub{beaconLimit: newIPRateLimiter(1)}
	h.beaconLimit.now = func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }
	var hits int
	handler := h.limitPublic(h.beaconLimit, func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/b/tok", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rr := httptest.NewRecorder()
	handler(rr, req)
	if rr.Code != http.StatusOK || hits != 1 {
		t.Fatalf("first: code=%d hits=%d", rr.Code, hits)
	}
	rr2 := httptest.NewRecorder()
	handler(rr2, req)
	if rr2.Code != http.StatusTooManyRequests {
		t.Fatalf("second want 429, got %d", rr2.Code)
	}
	if rr2.Header().Get("Retry-After") == "" {
		t.Fatal("missing Retry-After")
	}
	if hits != 1 {
		t.Fatalf("handler must not run on 429: hits=%d", hits)
	}
}
