package beacon

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
)

// NewTokenID returns an opaque unguessable token identifier (128-bit hex).
func NewTokenID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// HTTPSURL builds a beacon URL that embeds only the opaque token.
func HTTPSURL(collector string, tokenID string) (string, error) {
	collector = strings.TrimSpace(collector)
	if collector == "" {
		return "", fmt.Errorf("collector URL is required")
	}
	if !strings.Contains(collector, "://") {
		collector = "https://" + collector
	}
	u, err := url.Parse(collector)
	if err != nil {
		return "", err
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return "", fmt.Errorf("collector scheme must be https (or http for local lab)")
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/b/" + tokenID
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), nil
}

// DNSName builds a unique DNS beacon name under the operator-controlled zone.
func DNSName(zone, tokenID string) (string, error) {
	zone = strings.Trim(strings.ToLower(strings.TrimSpace(zone)), ".")
	if zone == "" {
		return "", fmt.Errorf("collector DNS zone is required")
	}
	if tokenID == "" {
		return "", fmt.Errorf("token id is required")
	}
	// Unique left-label per artifact to defeat resolver caching of repeats.
	var salt [4]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return "", err
	}
	label := hex.EncodeToString(salt[:]) + "-" + tokenID
	return label + "." + zone, nil
}
