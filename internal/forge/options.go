package forge

import (
	"fmt"
	"strings"
	"time"
)

type Options struct {
	Platforms   []string
	Type        string
	Name        string
	Theme       string
	Detect      string
	Collector   string
	CollectorDNS string
	Collect     string
	Memo        string
	AuthzRef    string
	Expire      time.Duration
	Tags        map[string]string
	OutDir      string
	RegistryDB  string
	KeyPath     string
}

func ParsePlatforms(s string) ([]string, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" || s == "all" {
		return []string{"windows", "linux", "macos"}, nil
	}
	parts := strings.Split(s, ",")
	var out []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		switch p {
		case "windows", "linux", "macos":
			out = append(out, p)
		default:
			return nil, fmt.Errorf("unknown platform %q", p)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no platforms selected")
	}
	return out, nil
}

func ParseTags(ss []string) map[string]string {
	m := map[string]string{}
	for _, s := range ss {
		k, v, ok := strings.Cut(s, ":")
		if !ok {
			k, v, ok = strings.Cut(s, "=")
		}
		if ok {
			m[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return m
}
