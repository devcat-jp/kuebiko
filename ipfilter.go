package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
)

// ipFilter wraps a handler and rejects requests from IPs not in the allowed list.
// It reads allowed networks from the APP_ALLOWED_IPS environment variable first,
// then falls back to the database config key "allowed_ips". If both are empty,
// it allows all requests.
func ipFilter(next http.Handler, db *DB) http.Handler {
	allowed := os.Getenv("APP_ALLOWED_IPS")
	if allowed == "" && db != nil {
		allowed, _ = db.GetConfig("allowed_ips")
	}
	if allowed == "" {
		return next
	}

	nets, err := parseAllowedNetworks(allowed)
	if err != nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		})
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		ip := net.ParseIP(host)
		if ip == nil {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		for _, n := range nets {
			if n.Contains(ip) {
				next.ServeHTTP(w, r)
				return
			}
		}
		http.Error(w, "Forbidden", http.StatusForbidden)
	})
}

func parseAllowedNetworks(s string) ([]*net.IPNet, error) {
	var nets []*net.IPNet
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		part = expandIPWildcard(part)
		if !strings.Contains(part, "/") {
			// Treat a bare IP as a /32 or /128 host route.
			part = part + "/32"
		}
		_, ipnet, err := net.ParseCIDR(part)
		if err != nil {
			return nil, fmt.Errorf("invalid network %q: %w", part, err)
		}
		nets = append(nets, ipnet)
	}
	return nets, nil
}

// expandIPWildcard converts patterns like "192.168.11.*" into CIDR "192.168.11.0/24".
// IPv6 "fe80::*" is converted to "fe80::/16". Only a single trailing "*" is supported.
func expandIPWildcard(s string) string {
	if !strings.HasSuffix(s, ".*") && !strings.HasSuffix(s, ":*") {
		return s
	}
	if strings.Count(s, "*") != 1 {
		return s
	}
	if strings.Contains(s, ":") {
		return strings.TrimSuffix(s, ":*") + ":/16"
	}
	return strings.TrimSuffix(s, ".*") + ".0/24"
}
