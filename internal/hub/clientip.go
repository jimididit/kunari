package hub

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

// parseTrustedProxies parses CIDR or bare IP strings into nets.
func parseTrustedProxies(cidrs []string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, raw := range cidrs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if !strings.Contains(raw, "/") {
			ip := net.ParseIP(raw)
			if ip == nil {
				return nil, fmt.Errorf("invalid trusted-proxy IP %q", raw)
			}
			if ip.To4() != nil {
				raw = ip.String() + "/32"
			} else {
				raw = ip.String() + "/128"
			}
		}
		_, n, err := net.ParseCIDR(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid trusted-proxy CIDR %q: %w", raw, err)
		}
		out = append(out, n)
	}
	return out, nil
}

func (h *Hub) isTrustedProxy(ip net.IP) bool {
	if ip == nil || len(h.trustedProxies) == 0 {
		return false
	}
	for _, n := range h.trustedProxies {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func remoteIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return net.ParseIP(r.RemoteAddr)
	}
	return net.ParseIP(host)
}

// clientIP returns the peer address, or a forwarded client IP when the peer
// is in the configured trusted-proxy set. Spoofed X-Forwarded-For from
// untrusted peers is ignored.
func (h *Hub) clientIP(r *http.Request) string {
	peer := remoteIP(r)
	peerStr := ""
	if peer != nil {
		peerStr = peer.String()
	} else {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			return r.RemoteAddr
		}
		return host
	}

	if !h.isTrustedProxy(peer) {
		return peerStr
	}

	header := h.cfg.ClientIPHeader
	if header == "" {
		header = "X-Forwarded-For"
	}
	raw := strings.TrimSpace(r.Header.Get(header))
	if raw == "" {
		return peerStr
	}
	// X-Forwarded-For: client, proxy1, proxy2 — leftmost is the original client
	// when the immediate peer (our TLS terminator) is trusted.
	first := strings.TrimSpace(strings.Split(raw, ",")[0])
	first = strings.Trim(first, "[]")
	if i := strings.IndexByte(first, '%'); i >= 0 {
		first = first[:i]
	}
	if ip := net.ParseIP(first); ip != nil {
		return ip.String()
	}
	return peerStr
}
