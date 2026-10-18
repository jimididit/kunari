package hub

import (
	"context"
	"net"
	"strings"

	"github.com/jimididit/kunari/internal/event"
	"github.com/miekg/dns"
)

func (h *Hub) serveDNS(ctx context.Context) error {
	zone := dns.Fqdn(strings.ToLower(h.cfg.DNSZone))
	mux := dns.NewServeMux()
	mux.HandleFunc(zone, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		if len(r.Question) == 0 {
			_ = w.WriteMsg(m)
			return
		}
		q := r.Question[0]
		name := strings.ToLower(q.Name)
		if strings.HasSuffix(name, zone) {
			token := extractTokenFromDNS(name, zone)
			if token != "" {
				resolverIP := ""
				if a := w.RemoteAddr(); a != nil {
					host, _, _ := net.SplitHostPort(a.String())
					resolverIP = host
				}
				_ = h.recordBeacon(token, "beacon-dns", &event.Network{
					DNSResolverIP: resolverIP,
					SrcIP:         resolverIP,
				})
			}
		}
		// Answer with NXDOMAIN-looking success via empty A? Return NODATA / SOA-less empty answer.
		// For lab simplicity return A 127.0.0.1 so clients resolve.
		if q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA {
			rr, _ := dns.NewRR(q.Name + " 60 IN A 127.0.0.1")
			if rr != nil {
				m.Answer = append(m.Answer, rr)
			}
		}
		_ = w.WriteMsg(m)
	})

	server := &dns.Server{Addr: h.cfg.DNSListen, Net: "udp", Handler: mux}
	go func() {
		<-ctx.Done()
		_ = server.Shutdown()
	}()
	return server.ListenAndServe()
}

// extractTokenFromDNS expects labels like <salt>-<tokenid>.zone
func extractTokenFromDNS(name, zone string) string {
	name = strings.TrimSuffix(name, ".")
	zone = strings.TrimSuffix(zone, ".")
	if !strings.HasSuffix(name, zone) {
		return ""
	}
	left := strings.TrimSuffix(name, "."+zone)
	parts := strings.Split(left, ".")
	if len(parts) == 0 {
		return ""
	}
	label := parts[len(parts)-1]
	_, token, ok := strings.Cut(label, "-")
	if !ok {
		return ""
	}
	if len(token) < 16 {
		return ""
	}
	return token
}
