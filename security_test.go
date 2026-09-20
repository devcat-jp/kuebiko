package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
