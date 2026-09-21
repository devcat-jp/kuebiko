package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"
	"time"
)

// cookieSecure is set at startup and controls the Secure attribute on all
// cookies. It is true when the server terminates TLS itself or when an
// explicit HTTPS public URL is configured (reverse proxy deployment).
var cookieSecure bool

const (
	csrfCookieName = "app_csrf"
	csrfFormField  = "csrf_token"
	csrfHeaderName = "X-CSRF-Token"

	// maxRequestBody bounds the size of request bodies parsed by handlers.
	maxRequestBody = 1 << 20 // 1 MiB
)

type contextKey string

const cspNonceContextKey contextKey = "csp-nonce"

// randomToken returns a hex-encoded 256-bit random token.
func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// securityHeaders applies defense-in-depth HTTP response headers to every
// response and stores a per-request CSP nonce in the request context.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce, err := randomToken()
		if err != nil {
			nonce = ""
		}
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		csp := "default-src 'self'; " +
			"script-src 'self' 'nonce-" + nonce + "'; " +
			"style-src 'self' 'unsafe-inline'; " +
			"img-src 'self' data:; " +
			"connect-src 'self'; " +
			"object-src 'none'; " +
			"base-uri 'self'; " +
			"form-action 'self'; " +
			"frame-ancestors 'none'"
		h.Set("Content-Security-Policy", csp)
		if cookieSecure {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		// Authenticated pages must never be cached by shared or local caches.
		// Static assets are excluded so browsers can still cache them.
		if !strings.HasPrefix(r.URL.Path, "/static/") {
			h.Set("Cache-Control", "no-store")
		}
		ctx := context.WithValue(r.Context(), cspNonceContextKey, nonce)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// cspNonceFromContext returns the request's CSP nonce (empty if absent).
func cspNonceFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(cspNonceContextKey).(string); ok {
		return v
	}
	return ""
}

// limitBody bounds the size of request bodies for state-changing methods.
func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil && r.Method != http.MethodGet && r.Method != http.MethodHead {
			if r.ContentLength > maxRequestBody {
				http.Error(w, "Request entity too large", http.StatusRequestEntityTooLarge)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
		}
		next.ServeHTTP(w, r)
	})
}

// csrfToken returns the current CSRF token, creating a cookie-backed token
// when none is present.
func csrfToken(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(csrfCookieName); err == nil && len(c.Value) >= 32 {
		return c.Value
	}
	token, err := randomToken()
	if err != nil {
		return ""
	}
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   cookieSecure,
	})
	return token
}

// validCSRF implements the double-submit cookie check. The token may be sent
// either as a form field or as a request header (for fetch-based requests).
func validCSRF(r *http.Request) bool {
	cookie, err := r.Cookie(csrfCookieName)
	if err != nil || cookie.Value == "" {
		return false
	}
	sent := r.FormValue(csrfFormField)
	if sent == "" {
		sent = r.Header.Get(csrfHeaderName)
	}
	if sent == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(sent), []byte(cookie.Value)) == 1
}

// csrfMiddleware rejects unsafe requests that do not carry a valid CSRF token.
func csrfMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		if !validCSRF(r) {
			http.Error(w, "Forbidden: invalid CSRF token", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

const (
	loginMaxFailures   = 5
	loginWindow        = 15 * time.Minute
	loginBlockDuration = 15 * time.Minute
	minPasswordLength  = 8
)

type loginRecord struct {
	failures     int
	firstFailure time.Time
	blockedUntil time.Time
	lastSeen     time.Time
}

var loginLimiter = struct {
	mu sync.Mutex
	m  map[string]*loginRecord
}{m: make(map[string]*loginRecord)}

// loginBlocked reports whether an IP is currently locked out.
func loginBlocked(key string) bool {
	loginLimiter.mu.Lock()
	defer loginLimiter.mu.Unlock()
	rec := loginLimiter.m[key]
	if rec == nil {
		return false
	}
	return time.Now().Before(rec.blockedUntil)
}

// registerLoginFailure records a failed login attempt for an IP.
func registerLoginFailure(key string) {
	now := time.Now()
	loginLimiter.mu.Lock()
	defer loginLimiter.mu.Unlock()
	// Opportunistically prune stale entries to bound memory usage.
	if len(loginLimiter.m) > 1024 {
		for k, v := range loginLimiter.m {
			if now.Sub(v.lastSeen) > loginWindow {
				delete(loginLimiter.m, k)
			}
		}
	}
	rec := loginLimiter.m[key]
	if rec == nil || now.Sub(rec.firstFailure) > loginWindow {
		rec = &loginRecord{firstFailure: now}
		loginLimiter.m[key] = rec
	}
	rec.lastSeen = now
	rec.failures++
	if rec.failures >= loginMaxFailures {
		rec.blockedUntil = now.Add(loginBlockDuration)
	}
}

// resetLoginFailures clears the failure state after a successful login.
func resetLoginFailures(key string) {
	loginLimiter.mu.Lock()
	defer loginLimiter.mu.Unlock()
	delete(loginLimiter.m, key)
}

// validatePassword enforces a minimum password length.
func validatePassword(password string) bool {
	return len([]rune(password)) >= minPasswordLength
}

// safeReturnPath validates a redirect target coming from user input. It only
// accepts absolute paths on this host, rejecting schemes, protocol-relative
// URLs, backslashes and control characters.
func safeReturnPath(p string) string {
	if p == "" || !strings.HasPrefix(p, "/") {
		return "/"
	}
	if strings.HasPrefix(p, "//") || strings.HasPrefix(p, "/\\") {
		return "/"
	}
	for _, r := range p {
		if r <= 0x20 || r == 0x7f || r == '\\' {
			return "/"
		}
	}
	return p
}
