package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := NewDB(filepath.Join(t.TempDir(), "app.db"), "test-encryption-key")
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestForeignKeysEnforcedAndFilesRestricted(t *testing.T) {
	db := newTestDB(t)

	var fk int
	if err := db.conn.QueryRow("PRAGMA foreign_keys").Scan(&fk); err != nil {
		t.Fatalf("PRAGMA foreign_keys: %v", err)
	}
	if fk != 1 {
		t.Fatalf("foreign_keys = %d, want 1", fk)
	}

	res, err := db.conn.Exec("INSERT INTO recipients (email, name, sort_order) VALUES ('a@example.com', 'a', 0)")
	if err != nil {
		t.Fatalf("insert recipient: %v", err)
	}
	rid, _ := res.LastInsertId()
	if err := db.CreateViewerLink(rid, "token-abc"); err != nil {
		t.Fatalf("CreateViewerLink: %v", err)
	}
	if err := db.DeleteRecipient(rid); err != nil {
		t.Fatalf("DeleteRecipient: %v", err)
	}
	var orphans int
	if err := db.conn.QueryRow("SELECT COUNT(*) FROM viewer_links").Scan(&orphans); err != nil {
		t.Fatalf("count viewer_links: %v", err)
	}
	if orphans != 0 {
		t.Fatalf("orphan viewer_links = %d, want 0", orphans)
	}
}

func TestDatabaseFilePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.db")
	db, err := NewDB(path, "test-encryption-key")
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := fi.Mode().Perm(); got != 0600 {
		t.Fatalf("db perms = %04o, want 0600", got)
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if fi, err := os.Stat(path + suffix); err == nil {
			if got := fi.Mode().Perm(); got != 0600 {
				t.Fatalf("%s perms = %04o, want 0600", suffix, got)
			}
		}
	}
}

func TestAllowedNetworksHostRoutes(t *testing.T) {
	nets, err := parseAllowedNetworks("::1")
	if err != nil {
		t.Fatalf("parseAllowedNetworks(::1): %v", err)
	}
	if len(nets) != 1 || nets[0].String() != "::1/128" {
		t.Fatalf("::1 -> %v, want ::1/128", nets)
	}
	nets, err = parseAllowedNetworks("10.0.0.5")
	if err != nil {
		t.Fatalf("parseAllowedNetworks(10.0.0.5): %v", err)
	}
	if len(nets) != 1 || nets[0].String() != "10.0.0.5/32" {
		t.Fatalf("10.0.0.5 -> %v, want 10.0.0.5/32", nets)
	}
	if _, err := parseAllowedNetworks("not-an-ip"); err == nil {
		t.Fatal("expected error for invalid network")
	}
}

func TestIPFilterPicksUpConfigChangeWithoutRestart(t *testing.T) {
	os.Unsetenv("APP_ALLOWED_IPS")
	db := newTestDB(t)
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	h := ipFilter(ok, db)

	call := func() int {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "127.0.0.1:12345"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	if err := db.SetConfig("allowed_ips", "10.99.99.0/24"); err != nil {
		t.Fatal(err)
	}
	if code := call(); code != http.StatusForbidden {
		t.Fatalf("blocked request code = %d, want 403", code)
	}
	if err := db.SetConfig("allowed_ips", "127.0.0.0/8"); err != nil {
		t.Fatal(err)
	}
	if code := call(); code != http.StatusOK {
		t.Fatalf("allowed request code = %d, want 200 (config must apply without restart)", code)
	}
}

func TestRenderMarkdownSanitizesScriptAndSchemes(t *testing.T) {
	out := string(renderMarkdown("hello <script>alert(1)</script>\n\n[x](javascript:alert(1)) [y](https://ok.example)\n\n![i](data:text/html;base64,PHNjcmlwdD4=)"))
	lower := strings.ToLower(out)
	if strings.Contains(lower, "<script") || strings.Contains(lower, "javascript:") || strings.Contains(lower, "data:text/html") {
		t.Fatalf("unsafe markdown output: %s", out)
	}
	if !strings.Contains(out, "https://ok.example") {
		t.Fatalf("safe link was dropped: %s", out)
	}
}

func TestSafeReturnPath(t *testing.T) {
	cases := map[string]string{
		"/settings":        "/settings",
		"/a?b=1":           "/a?b=1",
		"":                 "/",
		"//evil.example":   "/",
		"/\\evil.example":  "/",
		"https://evil/":    "/",
		"javascript:alert": "/",
		"/a\nb":            "/",
		"/a\\b":            "/",
	}
	for in, want := range cases {
		if got := safeReturnPath(in); got != want {
			t.Errorf("safeReturnPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValidatePassword(t *testing.T) {
	if validatePassword("short") {
		t.Fatal("short password accepted")
	}
	if !validatePassword("longenough") {
		t.Fatal("valid password rejected")
	}
}

func TestCSRFMiddleware(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	h := csrfMiddleware(ok)

	// GET is always allowed.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET code = %d, want 200", rec.Code)
	}

	// POST without a token is rejected.
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("a=1"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("POST without token code = %d, want 403", rec.Code)
	}

	// POST with a matching cookie and form field is accepted.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/", strings.NewReader("csrf_token=secret-token"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "secret-token"})
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST with valid token code = %d, want 200", rec.Code)
	}

	// POST with a matching cookie and header is accepted (fetch requests).
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/", strings.NewReader("id=1"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set(csrfHeaderName, "secret-token")
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "secret-token"})
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST with valid header code = %d, want 200", rec.Code)
	}

	// A mismatching token is rejected.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/", strings.NewReader("csrf_token=wrong"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "secret-token"})
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("POST with wrong token code = %d, want 403", rec.Code)
	}
}

func TestSecurityHeaders(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	h := securityHeaders(ok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/settings", nil))
	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'self' 'nonce-") || !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Fatalf("unexpected CSP: %q", csp)
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("missing nosniff header")
	}
	if rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatal("missing frame denial header")
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("authenticated pages must not be cached")
	}
	if rec.Header().Get("Strict-Transport-Security") != "" {
		t.Fatal("HSTS must not be sent over plain HTTP")
	}

	old := cookieSecure
	cookieSecure = true
	defer func() { cookieSecure = old }()
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/settings", nil))
	if rec.Header().Get("Strict-Transport-Security") == "" {
		t.Fatal("HSTS missing when TLS is enabled")
	}
}

func TestLoginLimiterLocksOut(t *testing.T) {
	key := "test-" + t.Name()
	resetLoginFailures(key)
	for i := 0; i < loginMaxFailures; i++ {
		if loginBlocked(key) && i < loginMaxFailures-1 {
			t.Fatalf("locked out early at attempt %d", i)
		}
		registerLoginFailure(key)
	}
	if !loginBlocked(key) {
		t.Fatal("expected lockout after repeated failures")
	}
	resetLoginFailures(key)
	if loginBlocked(key) {
		t.Fatal("reset did not clear lockout")
	}
}

func TestDeleteViewerLinksUpToKeepsLatest(t *testing.T) {
	db := newTestDB(t)
	res, err := db.conn.Exec("INSERT INTO recipients (email, name, sort_order) VALUES ('a@example.com', 'a', 0)")
	if err != nil {
		t.Fatal(err)
	}
	rid, _ := res.LastInsertId()
	if err := db.CreateViewerLink(rid, "old-token"); err != nil {
		t.Fatal(err)
	}
	watermark, err := db.MaxViewerLinkID()
	if err != nil {
		t.Fatal(err)
	}
	if err := db.CreateViewerLink(rid, "new-token"); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateViewerLinkWithExpiry(rid, "test-token", time.Now().Add(time.Hour), true); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteViewerLinksUpTo(watermark); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.conn.QueryRow("SELECT COUNT(*) FROM viewer_links").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("viewer_links = %d, want 2 (latest + test link)", count)
	}
	if ok, err := db.ValidateViewerToken("old-token"); err != nil || ok {
		t.Fatalf("pruned token still valid: ok=%v err=%v", ok, err)
	}
	if ok, err := db.ValidateViewerToken("new-token"); err != nil || !ok {
		t.Fatalf("latest token was invalidated: ok=%v err=%v", ok, err)
	}
}
