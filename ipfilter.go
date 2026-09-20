package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
)

// ipFilter wraps a handler and rejects requests from IPs not in the allowed list.
// The list is resolved for every request so that changes saved from the settings
// page take effect immediately, without restarting the application. The
// APP_ALLOWED_IPS environment variable takes precedence over the database
// config key "allowed_ips". If neither is set, all requests are allowed.
func ipFilter(next http.Handler, db *DB) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		allowed := strings.TrimSpace(os.Getenv("APP_ALLOWED_IPS"))
		if allowed == "" && db != nil {
			value, err := db.GetConfig("allowed_ips")
			if err != nil {
				// Fail closed: never widen access because the stored
				// restriction could not be read.
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
			allowed = strings.TrimSpace(value)
		}
		if allowed == "" {
			next.ServeHTTP(w, r)
			return
		}

		nets, err := parseAllowedNetworksCached(allowed)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

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

// ipNetCache memoizes the parsed networks for the most recently used allowed
// list so the configuration is not re-parsed on every request. The cache is
// keyed by the exact configuration string, so a settings change is picked up
// immediately without a restart.
var (
	ipNetCacheMu    sync.Mutex
	ipNetCacheKey   string
	ipNetCacheValid bool
	ipNetCacheNets  []*net.IPNet
	ipNetCacheErr   error
)

func parseAllowedNetworksCached(s string) ([]*net.IPNet, error) {
	ipNetCacheMu.Lock()
	defer ipNetCacheMu.Unlock()
	if ipNetCacheValid && ipNetCacheKey == s {
		return ipNetCacheNets, ipNetCacheErr
	}
	nets, err := parseAllowedNetworks(s)
	ipNetCacheKey, ipNetCacheValid, ipNetCacheNets, ipNetCacheErr = s, true, nets, err
	return nets, err
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
			// Treat a bare IP as a host route: /32 for IPv4, /128 for IPv6.
			bits := 32
			if ip := net.ParseIP(part); ip != nil && ip.To4() == nil {
				bits = 128
			}
			part = fmt.Sprintf("%s/%d", part, bits)
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
