package hub

import (
	"net/http"
	"testing"
)

func TestClientIPDefaultIgnoresXFF(t *testing.T) {
	h := &Hub{cfg: Config{}}
	r := httptestReq("203.0.113.50:443")
	r.Header.Set("X-Forwarded-For", "198.51.100.1")
	if got := h.clientIP(r); got != "203.0.113.50" {
		t.Fatalf("got %q want peer", got)
	}
}

func TestClientIPTrustedProxyUsesXFF(t *testing.T) {
	nets, err := parseTrustedProxies([]string{"10.0.0.0/8", "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	h := &Hub{
		cfg:            Config{ClientIPHeader: "X-Forwarded-For"},
		trustedProxies: nets,
	}
	r := httptestReq("10.1.2.3:8443")
	r.Header.Set("X-Forwarded-For", "198.51.100.7, 10.1.2.3")
	if got := h.clientIP(r); got != "198.51.100.7" {
		t.Fatalf("got %q want original client", got)
	}
}

func TestClientIPUntrustedPeerIgnoresXFF(t *testing.T) {
	nets, err := parseTrustedProxies([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	h := &Hub{
		cfg:            Config{ClientIPHeader: "X-Forwarded-For"},
		trustedProxies: nets,
	}
	r := httptestReq("198.51.100.9:1234")
	r.Header.Set("X-Forwarded-For", "203.0.113.1")
	if got := h.clientIP(r); got != "198.51.100.9" {
		t.Fatalf("got %q; spoofed XFF must be ignored", got)
	}
}

func TestClientIPRealIPHeader(t *testing.T) {
	nets, err := parseTrustedProxies([]string{"127.0.0.1/32"})
	if err != nil {
		t.Fatal(err)
	}
	h := &Hub{
		cfg:            Config{ClientIPHeader: "X-Real-IP"},
		trustedProxies: nets,
	}
	r := httptestReq("127.0.0.1:9")
	r.Header.Set("X-Real-IP", "203.0.113.44")
	if got := h.clientIP(r); got != "203.0.113.44" {
		t.Fatalf("got %q", got)
	}
}

func TestParseTrustedProxiesRejectsJunk(t *testing.T) {
	if _, err := parseTrustedProxies([]string{"not-an-ip"}); err == nil {
		t.Fatal("expected error")
	}
}

func httptestReq(remoteAddr string) *http.Request {
	r, _ := http.NewRequest(http.MethodGet, "http://hub/b/x", nil)
	r.RemoteAddr = remoteAddr
	return r
}
