package main

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gomarkdown/markdown"
	"github.com/gomarkdown/markdown/ast"
	"github.com/gomarkdown/markdown/html"
	"github.com/gomarkdown/markdown/parser"
)

//go:embed templates/*
var templatesFS embed.FS

//go:embed static/*
var staticFS embed.FS

// App holds application state.
type App struct {
	db        *DB
	templates *template.Template
}

func main() {
	if err := initTranslations(); err != nil {
		log.Fatalf("failed to load translations: %v", err)
	}
	// Load optional .env file before reading environment variables.
	if err := loadEnvFile(".env"); err != nil {
		log.Fatalf("failed to load .env file: %v", err)
	}

	dataDir := os.Getenv("APP_DATA_DIR")
	if dataDir == "" {
		dataDir = "data"
	}
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		log.Fatalf("failed to create data directory: %v", err)
	}
	// The directory holds the encryption key, the database (with the SMTP
	// password and session token) and the TLS private key, so keep it private
	// to the owner even if it already existed with looser permissions.
	if err := os.Chmod(dataDir, 0700); err != nil {
		log.Fatalf("failed to restrict data directory permissions: %v", err)
	}

	key, err := loadOrGenerateEncryptionKey(dataDir)
	if err != nil {
		log.Fatalf("failed to load encryption key: %v", err)
	}

	dbPath := filepath.Join(dataDir, "app.db")
	db, err := NewDB(dbPath, key)
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	tmpl, err := template.New("").Funcs(template.FuncMap{
		"md":          renderMarkdown,
		"appName":     func() string { return applicationName },
		"languageURL": languageURL,
		"t":           translate,
	}).ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		log.Fatalf("failed to parse templates: %v", err)
	}

	app := &App{db: db, templates: tmpl}

	// Start the overdue watcher.
	checkInterval := 1 * time.Hour
	if d, err := time.ParseDuration(os.Getenv("APP_CHECK_INTERVAL")); err == nil && d > 0 {
		checkInterval = d
	}
	go app.watchOverdue(checkInterval)

	mux := http.NewServeMux()
	mux.Handle("/static/", http.FileServerFS(staticFS))
	mux.HandleFunc("/language", app.languageHandler)

	mux.HandleFunc("/", app.authMiddleware(app.dashboardHandler))
	mux.HandleFunc("/setup", app.setupHandler)
	mux.HandleFunc("/login", app.loginHandler)
	mux.HandleFunc("/logout", app.logoutHandler)
	mux.HandleFunc("/checkin", app.authMiddleware(app.checkInHandler))
	// The tokenized path is intentionally not protected by the login middleware.
	// Possession of the unguessable URL is the authentication mechanism.
	mux.HandleFunc("/checkin/", app.secretCheckInHandler)
	mux.HandleFunc("/view/", app.viewerHandler)
	mux.HandleFunc("/settings", app.authMiddleware(app.settingsHandler))
	mux.HandleFunc("/settings/checkin", app.authMiddleware(app.settingsCheckInHandler))

	mux.HandleFunc("/recipients", app.authMiddleware(app.recipientsHandler))
	mux.HandleFunc("/recipients/new", app.authMiddleware(app.recipientNewHandler))
	mux.HandleFunc("/recipients/edit", app.authMiddleware(app.recipientEditHandler))
	mux.HandleFunc("/recipients/delete", app.authMiddleware(app.recipientDeleteHandler))
	mux.HandleFunc("/recipients/reorder", app.authMiddleware(app.recipientsReorderHandler))
	mux.HandleFunc("/recipients/test-email", app.authMiddleware(app.recipientsTestEmailHandler))
	mux.HandleFunc("/recipients/test-email/clear", app.authMiddleware(app.recipientsTestEmailClearHandler))

	mux.HandleFunc("/secrets", app.authMiddleware(app.secretsHandler))
	mux.HandleFunc("/secrets/new", app.authMiddleware(app.secretNewHandler))
	mux.HandleFunc("/secrets/edit", app.authMiddleware(app.secretEditHandler))
	mux.HandleFunc("/secrets/delete", app.authMiddleware(app.secretDeleteHandler))
	mux.HandleFunc("/secrets/view", app.authMiddleware(app.secretViewHandler))
	mux.HandleFunc("/secrets/reorder", app.authMiddleware(app.secretsReorderHandler))
	mux.HandleFunc("/insurance", app.authMiddleware(app.insuranceHandler))
	mux.HandleFunc("/insurance/new", app.authMiddleware(app.insuranceNewHandler))
	mux.HandleFunc("/insurance/edit", app.authMiddleware(app.insuranceEditHandler))
	mux.HandleFunc("/insurance/delete", app.authMiddleware(app.insuranceDeleteHandler))
	mux.HandleFunc("/insurance/view", app.authMiddleware(app.insuranceViewHandler))
	mux.HandleFunc("/insurance/reorder", app.authMiddleware(app.insuranceReorderHandler))
	mux.HandleFunc("/subscriptions", app.authMiddleware(app.subscriptionHandler))
	mux.HandleFunc("/subscriptions/new", app.authMiddleware(app.subscriptionNewHandler))
	mux.HandleFunc("/subscriptions/edit", app.authMiddleware(app.subscriptionEditHandler))
	mux.HandleFunc("/subscriptions/delete", app.authMiddleware(app.subscriptionDeleteHandler))
	mux.HandleFunc("/subscriptions/view", app.authMiddleware(app.subscriptionViewHandler))
	mux.HandleFunc("/subscriptions/reorder", app.authMiddleware(app.subscriptionReorderHandler))

	mux.HandleFunc("/documents", app.authMiddleware(app.documentsHandler))
	mux.HandleFunc("/documents/new", app.authMiddleware(app.documentNewHandler))
	mux.HandleFunc("/documents/edit", app.authMiddleware(app.documentEditHandler))
	mux.HandleFunc("/documents/delete", app.authMiddleware(app.documentDeleteHandler))
	mux.HandleFunc("/documents/preview", app.authMiddleware(app.documentPreviewHandler))
	mux.HandleFunc("/documents/reorder", app.authMiddleware(app.documentsReorderHandler))

	var handler http.Handler = mux
	handler = csrfMiddleware(handler)
	handler = limitBody(handler)
	handler = ipFilter(handler, db)
	handler = languageMiddleware(handler)
	handler = securityHeaders(handler)

	host := os.Getenv("APP_HOST")
	if host == "" {
		host = "127.0.0.1"
	}
	port := os.Getenv("APP_PORT")
	if port == "" {
		port = "8080"
	}

	certFile, keyFile, useTLS, err := ensureTLSCertificate(dataDir)
	if err != nil {
		log.Fatalf("failed to setup TLS: %v", err)
	}

	addr := host + ":" + port
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	// Cookies marked Secure require TLS; also honour an explicit HTTPS public
	// URL so proxied deployments get hardened cookies.
	cookieSecure = useTLS || strings.HasPrefix(strings.ToLower(os.Getenv("APP_PUBLIC_URL")), "https://")

	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}
	log.Printf("Application server starting on %s://%s", scheme, addr)
	if useTLS {
		if err := srv.ListenAndServeTLS(certFile, keyFile); err != nil {
			log.Fatalf("server error: %v", err)
		}
	} else {
		if err := srv.ListenAndServe(); err != nil {
			log.Fatalf("server error: %v", err)
		}
	}
}

// loadOrGenerateEncryptionKey loads the encryption key from the
// APP_ENCRYPTION_KEY environment variable or the configured key file.
// If neither is available, a new key is generated and written to the file.
func loadOrGenerateEncryptionKey(dataDir string) (string, error) {
	if key := os.Getenv("APP_ENCRYPTION_KEY"); key != "" {
		return key, nil
	}

	keyPath := os.Getenv("APP_ENCRYPTION_KEY_FILE")
	if keyPath == "" {
		keyPath = filepath.Join(dataDir, "encryption.key")
	}

	if _, err := os.Stat(keyPath); err == nil {
		b, err := os.ReadFile(keyPath)
		if err != nil {
			return "", fmt.Errorf("read encryption key file: %w", err)
		}
		key := strings.TrimSpace(string(b))
		if key == "" {
			return "", fmt.Errorf("encryption key file is empty")
		}
		return key, nil
	}

	key, err := generateKey()
	if err != nil {
		return "", fmt.Errorf("generate encryption key: %w", err)
	}

	if err := os.WriteFile(keyPath, []byte(key), 0600); err != nil {
		return "", fmt.Errorf("write encryption key file: %w", err)
	}

	log.Printf("Generated new encryption key at %s", keyPath)
	return key, nil
}

func (app *App) renderViewer(w http.ResponseWriter, r *http.Request, name string, data *AppData) {
	if data == nil {
		data = &AppData{}
	}
	data.Lang = languageFromRequest(r)
	data.RequestPath = r.URL.RequestURI()
	data.AppName = applicationName
	data.ClientIP = clientIP(r)
	data.CSPNonce = cspNonceFromContext(r.Context())
	base := strings.TrimSuffix(name, ".html")
	var titleBuf, contentBuf bytes.Buffer
	if err := app.templates.ExecuteTemplate(&titleBuf, base+"_title", data); err != nil {
		log.Printf("viewer template title error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if err := app.templates.ExecuteTemplate(&contentBuf, base+"_content", data); err != nil {
		log.Printf("viewer template content error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	data.Title = template.HTML(titleBuf.String())
	data.Content = template.HTML(contentBuf.String())
	if err := app.templates.ExecuteTemplate(w, "viewer_layout", data); err != nil {
		log.Printf("viewer layout error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func (app *App) render(w http.ResponseWriter, r *http.Request, name string, data *AppData) {
	if data == nil {
		data = &AppData{}
	}
	user, _ := app.currentUser(r)
	data.User = user
	data.Lang = languageFromRequest(r)
	data.RequestPath = r.URL.RequestURI()
	data.AppName = applicationName
	data.ClientIP = clientIP(r)
	data.CSPNonce = cspNonceFromContext(r.Context())
	data.CSRFToken = csrfToken(w, r)
	flash, flashType := getFlash(w, r)
	if parts := strings.SplitN(flash, "|", 2); len(parts) == 2 {
		data.Flash = translate(data.Lang, parts[0]) + parts[1]
	} else {
		data.Flash = translate(data.Lang, flash)
	}
	data.FlashType = flashType

	base := strings.TrimSuffix(name, ".html")
	var titleBuf, contentBuf bytes.Buffer
	if err := app.templates.ExecuteTemplate(&titleBuf, base+"_title", data); err != nil {
		log.Printf("template title error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if err := app.templates.ExecuteTemplate(&contentBuf, base+"_content", data); err != nil {
		log.Printf("template content error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	data.Title = template.HTML(titleBuf.String())
	data.Content = template.HTML(contentBuf.String())
	if err := app.templates.ExecuteTemplate(w, "layout", data); err != nil {
		log.Printf("template layout error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// urlSchemePattern matches the scheme of an absolute URL.
var urlSchemePattern = regexp.MustCompile(`^([a-zA-Z][a-zA-Z0-9+.\-]*):`)

// renderMarkdown converts admin-authored Markdown to HTML.
//
// Raw HTML is dropped entirely (html.SkipHTML) and link/image destinations are
// restricted to harmless schemes, because the result is embedded in the viewer
// pages with template.HTML (unescaped) and would otherwise allow stored XSS in
// the recipient's browser.
func renderMarkdown(s string) template.HTML {
	extensions := parser.CommonExtensions | parser.AutoHeadingIDs | parser.NoEmptyLineBeforeBlock
	p := parser.NewWithExtensions(extensions)
	doc := p.Parse([]byte(s))
	ast.WalkFunc(doc, sanitizeMarkdownNode)
	opts := html.RendererOptions{Flags: html.CommonFlags | html.HrefTargetBlank |
		html.NoreferrerLinks | html.NoopenerLinks | html.SkipHTML}
	renderer := html.NewRenderer(opts)
	return template.HTML(markdown.Render(doc, renderer))
}

// sanitizeMarkdownNode rewrites link and image destinations whose scheme could
// execute script (javascript:, data:, vbscript:, file:, ...).
func sanitizeMarkdownNode(node ast.Node, entering bool) ast.WalkStatus {
	if !entering {
		return ast.GoToNext
	}
	switch n := node.(type) {
	case *ast.Link:
		if !isSafeURL(n.Destination, false) {
			n.Destination = []byte("#")
			n.AdditionalAttributes = nil
		}
	case *ast.Image:
		if !isSafeURL(n.Destination, true) {
			n.Destination = nil
		}
	}
	return ast.GoToNext
}

// isSafeURL reports whether a link or image destination is safe to render.
// Characters that browsers ignore inside a URL (control characters and spaces)
// are removed before the scheme is inspected, so "java\tscript:" cannot bypass
// the check.
func isSafeURL(dest []byte, isImage bool) bool {
	var b strings.Builder
	for _, c := range dest {
		if c <= 0x20 || c == 0x7f {
			continue
		}
		b.WriteByte(c)
	}
	s := b.String()
	if s == "" || strings.HasPrefix(s, "#") {
		return true
	}
	m := urlSchemePattern.FindStringSubmatch(s)
	if m == nil {
		// Relative URL (including protocol-relative); safe to render.
		return true
	}
	switch strings.ToLower(m[1]) {
	case "http", "https", "mailto", "tel":
		return true
	case "data":
		if !isImage {
			return false
		}
		lower := strings.ToLower(s)
		for _, prefix := range []string{"data:image/png", "data:image/jpeg", "data:image/jpg", "data:image/gif", "data:image/webp"} {
			if strings.HasPrefix(lower, prefix) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

// Setup handler (first run only).
func (app *App) setupHandler(w http.ResponseWriter, r *http.Request) {
	user, _ := app.db.GetUser()
	if user != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if r.Method == http.MethodGet {
		app.render(w, r, "setup.html", nil)
		return
	}
	if r.Method == http.MethodPost {
		password := r.FormValue("password")
		confirm := r.FormValue("confirm")
		if password == "" {
			setFlash(w, "password_required", "error")
			app.render(w, r, "setup.html", nil)
			return
		}
		if !validatePassword(password) {
			setFlash(w, "password_too_short", "error")
			app.render(w, r, "setup.html", nil)
			return
		}
		if password != confirm {
			setFlash(w, "password_mismatch", "error")
			app.render(w, r, "setup.html", nil)
			return
		}
		hash, err := hashPassword(password)
		if err != nil {
			setFlash(w, "generic_error", "error")
			app.render(w, r, "setup.html", nil)
			return
		}
		if err := app.db.CreateUser(hash); err != nil {
			setFlash(w, "user_create_failed", "error")
			app.render(w, r, "setup.html", nil)
			return
		}
		// Initialize check-in time to now with default 7-day interval.
		_ = app.db.UpdateCheckIn(168, time.Now())
		if token, err := generateCheckInToken(); err == nil {
			if err := app.db.SetCheckInToken(token); err != nil {
				log.Printf("failed to create initial check-in URL: %v", err)
			}
		} else {
			log.Printf("failed to generate initial check-in URL: %v", err)
		}
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
}

// Login handler.
func (app *App) loginHandler(w http.ResponseWriter, r *http.Request) {
	user, _ := app.db.GetUser()
	if user == nil {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	if r.Method == http.MethodGet {
		app.render(w, r, "login.html", nil)
		return
	}
	if r.Method == http.MethodPost {
		ipKey := clientIP(r)
		if loginBlocked(ipKey) {
			setFlash(w, "too_many_attempts", "error")
			w.Header().Set("Retry-After", strconv.Itoa(int(loginBlockDuration.Seconds())))
			w.WriteHeader(http.StatusTooManyRequests)
			app.render(w, r, "login.html", nil)
			return
		}
		password := r.FormValue("password")
		if !checkPassword(password, user.PasswordHash) {
			registerLoginFailure(ipKey)
			setFlash(w, "incorrect_password", "error")
			app.render(w, r, "login.html", nil)
			return
		}
		resetLoginFailures(ipKey)
		token, err := generateSessionToken()
		if err != nil {
			setFlash(w, "generic_error", "error")
			app.render(w, r, "login.html", nil)
			return
		}
		expires := time.Now().Add(24 * time.Hour)
		if err := app.db.UpdateUserSession(token, expires); err != nil {
			setFlash(w, "generic_error", "error")
			app.render(w, r, "login.html", nil)
			return
		}
		setSessionCookie(w, token, expires)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
}

func (app *App) logoutHandler(w http.ResponseWriter, r *http.Request) {
	// Logout is a state-changing action and must not be triggerable by a
	// cross-site GET (e.g. <img src="/logout">).
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	_ = app.db.ClearSession()
	clearSessionCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// Dashboard handler.
func (app *App) dashboardHandler(w http.ResponseWriter, r *http.Request) {
	user, _ := app.db.GetUser()
	if user == nil {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	data := &AppData{User: user}
	if user.LastCheckInAt != nil {
		deadline := user.LastCheckInAt.Add(time.Duration(user.CheckInIntervalHours) * time.Hour)
		data.Deadline = &deadline
		data.IsOverdue = time.Now().After(deadline) && !user.IsTriggered
		data.TriggerAt = &deadline
	}
	app.render(w, r, "dashboard.html", data)
}

// Check-in handler.
func (app *App) checkInHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	user, _ := app.db.GetUser()
	interval := user.CheckInIntervalHours
	if iv, err := strconv.Atoi(r.FormValue("interval")); err == nil && iv > 0 {
		interval = iv
	}
	if err := app.db.UpdateCheckIn(interval, time.Now()); err != nil {
		setFlash(w, "checkin_update_failed", "error")
	} else {
		_ = app.db.ClearViewerLinks()
		setFlash(w, "checkin_updated", "success")
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// checkInURL builds the private URL from the request's origin. The token is
// only passed to this function from an authenticated settings request.
// clientIP returns the remote address without its port.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func publicBaseURL(r *http.Request) string {
	if base := strings.TrimRight(os.Getenv("APP_PUBLIC_URL"), "/"); base != "" {
		return base
	}
	scheme := "http"
	if r != nil && r.TLS != nil {
		scheme = "https"
	}
	if r == nil {
		port := os.Getenv("APP_PORT")
		if port == "" {
			port = "8080"
		}
		return scheme + "://localhost:" + port
	}
	return scheme + "://" + r.Host
}

func checkInURL(r *http.Request, token string) string {
	if token == "" {
		return ""
	}
	// Reuse publicBaseURL so an explicit APP_PUBLIC_URL wins over the request
	// Host header (avoids Host-header injection in the displayed URL).
	return publicBaseURL(r) + "/checkin/" + token
}

// viewerHandler serves the token-authenticated read-only portal. A viewer
// must first open the root URL (the message page); category pages then use a
// short-lived browser cookie so a direct deep link cannot skip the message.
func (app *App) viewerHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow, noarchive")
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/view/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 || parts[0] == "" || strings.Contains(parts[0], "?") {
		http.NotFound(w, r)
		return
	}
	token := parts[0]
	// The special preview token is never stored in viewer_links. It is
	// available only to an authenticated administrator from the settings page.
	// Every request is checked, including category navigation, so a forged
	// viewer_seen cookie cannot expose the preview to an unauthenticated user.
	isPreview := token == "preview"
	if isPreview {
		if user, _ := app.currentUser(r); user == nil {
			http.NotFound(w, r)
			return
		}
	} else {
		valid, err := app.db.ValidateViewerToken(token)
		if err != nil {
			log.Printf("failed to validate viewer token: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		if !valid {
			http.NotFound(w, r)
			return
		}
	}
	base := "/view/" + token
	if len(parts) == 1 {
		http.SetCookie(w, &http.Cookie{Name: "viewer_seen", Value: token, Path: base, HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: cookieSecure})
		message, _ := app.db.GetViewerMessage()
		app.renderViewer(w, r, "viewer_message.html", &AppData{ViewerMode: true, ViewerToken: token, ViewerMessage: message})
		return
	}
	seen, _ := r.Cookie("viewer_seen")
	if !isPreview && (seen == nil || seen.Value != token) {
		http.Redirect(w, r, base, http.StatusSeeOther)
		return
	}
	category := parts[1]
	switch category {
	case "financial", "insurance", "subscriptions":
		categoryDB := map[string]string{"financial": "financial", "insurance": "insurance", "subscriptions": "subscription"}[category]
		if len(parts) == 2 {
			list, _ := app.db.ListSecretsByCategory(categoryDB)
			app.renderViewer(w, r, "viewer_secrets.html", &AppData{ViewerMode: true, ViewerToken: token, Secrets: list, Category: categoryDB})
			return
		}
		if len(parts) == 3 && parts[2] == "view" {
			id, _ := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
			secret, _ := app.db.GetSecretByCategory(id, categoryDB)
			if secret == nil {
				http.NotFound(w, r)
				return
			}
			payload, _ := secret.ParseSecretPayload()
			app.renderViewer(w, r, "viewer_secret_view.html", &AppData{ViewerMode: true, ViewerToken: token, Secret: secret, SecretPayload: payload, Category: categoryDB})
			return
		}
	case "documents":
		if len(parts) == 2 {
			list, _ := app.db.ListDocuments()
			app.renderViewer(w, r, "viewer_documents.html", &AppData{ViewerMode: true, ViewerToken: token, Documents: list})
			return
		}
		if len(parts) == 3 && parts[2] == "preview" {
			id, _ := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
			doc, _ := app.db.GetDocument(id)
			if doc == nil {
				http.NotFound(w, r)
				return
			}
			app.renderViewer(w, r, "viewer_document_preview.html", &AppData{ViewerMode: true, ViewerToken: token, Document: doc})
			return
		}
	}
	http.NotFound(w, r)
}

// secretCheckInHandler authenticates solely by possession of the unguessable
// URL and updates the existing interval without exposing application data.
func (app *App) secretCheckInHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow, noarchive")
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	token := strings.TrimPrefix(r.URL.Path, "/checkin/")
	if token == "" || strings.Contains(token, "/") {
		http.NotFound(w, r)
		return
	}
	valid, err := app.db.ValidateCheckInToken(token)
	if err != nil {
		log.Printf("failed to validate check-in token: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if !valid {
		http.NotFound(w, r)
		return
	}
	user, err := app.db.GetUser()
	if err != nil || user == nil {
		http.NotFound(w, r)
		return
	}
	if err := app.db.UpdateCheckIn(user.CheckInIntervalHours, time.Now()); err != nil {
		log.Printf("failed to update check-in from private URL: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	_ = app.db.ClearViewerLinks()
	app.render(w, r, "checkin.html", nil)
}

// settingsCheckInHandler manages the private check-in URL. Regenerating the
// token immediately invalidates the old URL.
func (app *App) settingsCheckInHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	action := r.FormValue("action")
	switch action {
	case "regenerate":
		token, err := generateCheckInToken()
		if err != nil {
			setFlash(w, "private_page_generate_failed", "error")
		} else if err := app.db.SetCheckInToken(token); err != nil {
			setFlash(w, "private_page_save_failed", "error")
		} else {
			setFlash(w, "private_page_regenerated", "success")
		}
	case "disable":
		if err := app.db.ClearCheckInToken(); err != nil {
			setFlash(w, "private_page_disable_failed", "error")
		} else {
			setFlash(w, "private_page_disabled", "success")
		}
	default:
		setFlash(w, "invalid_operation", "error")
	}
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

// Settings handler (SMTP, email toggle, and IP restrictions).
func (app *App) settingsHandler(w http.ResponseWriter, r *http.Request) {
	user, _ := app.db.GetUser()
	viewerMessage, _ := app.db.GetViewerMessage()
	settings, _ := app.db.GetSMTPSettings()
	if settings == nil {
		settings = &SMTPSettings{Host: "smtp.gmail.com", Port: 587, UseTLS: true}
	}
	allowedIPs, _ := app.db.GetConfig("allowed_ips")
	allowedIPsEnv := os.Getenv("APP_ALLOWED_IPS")
	// The effective value is what the filter actually applies: the environment
	// variable wins over the database value when both are set.
	effectiveAllowedIPs := allowedIPs
	if allowedIPsEnv != "" {
		effectiveAllowedIPs = allowedIPsEnv
	}
	checkInToken, _ := app.db.GetCheckInToken()
	checkInURLValue := checkInURL(r, checkInToken)
	if r.Method == http.MethodGet {
		app.render(w, r, "settings.html", &AppData{User: user, SMTPSettings: settings, AllowedIPs: allowedIPs, EffectiveAllowedIPs: effectiveAllowedIPs, AllowedIPsEnv: allowedIPsEnv != "", CheckInURL: checkInURLValue, ViewerMessage: viewerMessage})
		return
	}
	if r.Method == http.MethodPost {
		action := r.FormValue("action")
		if action == "save_viewer_message" {
			if err := app.db.SetViewerMessage(r.FormValue("viewer_message")); err != nil {
				setFlash(w, "viewer_message_save_failed", "error")
			} else {
				setFlash(w, "viewer_message_saved", "success")
			}
			http.Redirect(w, r, "/settings", http.StatusSeeOther)
			return
		}
		if action == "change_password" {
			currentPassword := r.FormValue("current_password")
			newPassword := r.FormValue("new_password")
			confirmPassword := r.FormValue("confirm_password")
			if currentPassword == "" || newPassword == "" || confirmPassword == "" {
				setFlash(w, "password_fields_required", "error")
				app.render(w, r, "settings.html", &AppData{User: user, SMTPSettings: settings, AllowedIPs: allowedIPs, AllowedIPsEnv: allowedIPsEnv != "", CheckInURL: checkInURLValue})
				return
			}
			if !validatePassword(newPassword) {
				setFlash(w, "password_too_short", "error")
				app.render(w, r, "settings.html", &AppData{User: user, SMTPSettings: settings, AllowedIPs: allowedIPs, AllowedIPsEnv: allowedIPsEnv != "", CheckInURL: checkInURLValue})
				return
			}
			if !checkPassword(currentPassword, user.PasswordHash) {
				setFlash(w, "current_password_incorrect", "error")
				app.render(w, r, "settings.html", &AppData{User: user, SMTPSettings: settings, AllowedIPs: allowedIPs, AllowedIPsEnv: allowedIPsEnv != "", CheckInURL: checkInURLValue})
				return
			}
			if newPassword != confirmPassword {
				setFlash(w, "new_password_mismatch", "error")
				app.render(w, r, "settings.html", &AppData{User: user, SMTPSettings: settings, AllowedIPs: allowedIPs, AllowedIPsEnv: allowedIPsEnv != "", CheckInURL: checkInURLValue})
				return
			}
			hash, err := hashPassword(newPassword)
			if err != nil {
				setFlash(w, "password_hash_failed", "error")
				app.render(w, r, "settings.html", &AppData{User: user, SMTPSettings: settings, AllowedIPs: allowedIPs, AllowedIPsEnv: allowedIPsEnv != "", CheckInURL: checkInURLValue})
				return
			}
			if err := app.db.UpdateUserPassword(hash); err != nil {
				setFlash(w, "password_change_failed", "error")
				app.render(w, r, "settings.html", &AppData{User: user, SMTPSettings: settings, AllowedIPs: allowedIPs, AllowedIPsEnv: allowedIPsEnv != "", CheckInURL: checkInURLValue})
				return
			}
			// Invalidate every existing session so a stolen cookie cannot
			// survive a password change. The user must log in again.
			_ = app.db.ClearSession()
			clearSessionCookie(w)
			setFlash(w, "password_changed_relogin", "success")
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		host := strings.TrimSpace(r.FormValue("host"))
		port, _ := strconv.Atoi(r.FormValue("port"))
		username := strings.TrimSpace(r.FormValue("username"))
		password := r.FormValue("password")
		from := strings.TrimSpace(r.FormValue("from_address"))
		useTLS := r.FormValue("use_tls") == "1"
		enabled := r.FormValue("email_enabled") == "1"
		newAllowedIPs := strings.TrimSpace(r.FormValue("allowed_ips"))
		if host == "" || port == 0 || from == "" {
			setFlash(w, "smtp_required", "error")
			app.render(w, r, "settings.html", &AppData{User: user, SMTPSettings: settings, AllowedIPs: newAllowedIPs, AllowedIPsEnv: allowedIPsEnv != "", CheckInURL: checkInURLValue})
			return
		}
		if !validEmail(from) {
			setFlash(w, "from_address_invalid", "error")
			app.render(w, r, "settings.html", &AppData{User: user, SMTPSettings: settings, AllowedIPs: newAllowedIPs, AllowedIPsEnv: allowedIPsEnv != "", CheckInURL: checkInURLValue})
			return
		}
		if newAllowedIPs != "" {
			if _, err := parseAllowedNetworks(newAllowedIPs); err != nil {
				setFlash(w, "allowed_ip_invalid|"+err.Error(), "error")
				app.render(w, r, "settings.html", &AppData{User: user, SMTPSettings: settings, AllowedIPs: newAllowedIPs, AllowedIPsEnv: allowedIPsEnv != "", CheckInURL: checkInURLValue})
				return
			}
		}

		newSettings := &SMTPSettings{
			Host:        host,
			Port:        port,
			Username:    username,
			Password:    password,
			FromAddress: from,
			UseTLS:      useTLS,
		}
		if err := app.db.SaveSMTPSettings(newSettings); err != nil {
			setFlash(w, "settings_save_failed", "error")
		} else {
			_ = app.db.SetEmailEnabled(enabled)
			if err := app.db.SetConfig("allowed_ips", newAllowedIPs); err != nil {
				setFlash(w, "allowed_ips_save_failed", "error")
			} else {
				setFlash(w, "settings_saved", "success")
			}
		}
		// Redirect after a successful save so the reloaded page shows the
		// value that is now actually enforced by the IP filter.
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
}

// Recipients handlers.
func (app *App) recipientsHandler(w http.ResponseWriter, r *http.Request) {
	list, _ := app.db.ListRecipients()
	app.render(w, r, "recipients.html", &AppData{Recipients: list})
}

func (app *App) recipientNewHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		app.render(w, r, "recipient_form.html", nil)
		return
	}
	email := strings.TrimSpace(r.FormValue("email"))
	name := strings.TrimSpace(r.FormValue("name"))
	if email == "" {
		setFlash(w, "email_required", "error")
		app.render(w, r, "recipient_form.html", nil)
		return
	}
	if !validEmail(email) {
		setFlash(w, "email_invalid", "error")
		app.render(w, r, "recipient_form.html", nil)
		return
	}
	if err := app.db.CreateRecipient(email, name); err != nil {
		setFlash(w, "add_failed", "error")
		app.render(w, r, "recipient_form.html", nil)
		return
	}
	setFlash(w, "recipient_added", "success")
	http.Redirect(w, r, "/recipients", http.StatusSeeOther)
}

func (app *App) recipientEditHandler(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	recipient, _ := app.db.GetRecipient(id)
	if recipient == nil {
		http.Redirect(w, r, "/recipients", http.StatusSeeOther)
		return
	}
	if r.Method == http.MethodGet {
		app.render(w, r, "recipient_form.html", &AppData{Recipient: recipient})
		return
	}
	email := strings.TrimSpace(r.FormValue("email"))
	name := strings.TrimSpace(r.FormValue("name"))
	if email == "" {
		setFlash(w, "email_required", "error")
		app.render(w, r, "recipient_form.html", &AppData{Recipient: recipient})
		return
	}
	if !validEmail(email) {
		setFlash(w, "email_invalid", "error")
		app.render(w, r, "recipient_form.html", &AppData{Recipient: recipient})
		return
	}
	if err := app.db.UpdateRecipient(id, email, name); err != nil {
		setFlash(w, "update_failed", "error")
	} else {
		setFlash(w, "recipient_updated", "success")
	}
	http.Redirect(w, r, "/recipients", http.StatusSeeOther)
}

func (app *App) recipientDeleteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	id, _ := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	if err := app.db.DeleteRecipient(id); err != nil {
		setFlash(w, "delete_failed", "error")
	} else {
		setFlash(w, "recipient_deleted", "success")
	}
	http.Redirect(w, r, "/recipients", http.StatusSeeOther)
}

// testViewerLinkValidity limits how long an email test link stays usable.
const testViewerLinkValidity = time.Hour

// recipientsTestEmailHandler sends the real trigger message to one recipient
// (or all of them) with a short-lived test link so SMTP delivery and the
// viewer portal can be verified without waiting for an actual overdue event.
func (app *App) recipientsTestEmailHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	settings, err := app.db.GetSMTPSettings()
	if err != nil || settings == nil || strings.TrimSpace(settings.Host) == "" {
		setFlash(w, "test_email_smtp_required", "error")
		http.Redirect(w, r, "/recipients", http.StatusSeeOther)
		return
	}

	list, err := app.db.ListRecipients()
	if err != nil || len(list) == 0 {
		setFlash(w, "test_email_no_recipients", "error")
		http.Redirect(w, r, "/recipients", http.StatusSeeOther)
		return
	}

	targets := list
	if idStr := r.URL.Query().Get("id"); idStr != "" && idStr != "all" {
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			setFlash(w, "test_email_failed", "error")
			http.Redirect(w, r, "/recipients", http.StatusSeeOther)
			return
		}
		targets = nil
		for _, recipient := range list {
			if recipient.ID == id {
				targets = append(targets, recipient)
				break
			}
		}
		if len(targets) == 0 {
			setFlash(w, "test_email_failed", "error")
			http.Redirect(w, r, "/recipients", http.StatusSeeOther)
			return
		}
	}

	// Discard links from previous tests before issuing fresh, short-lived ones.
	if err := app.db.DeleteTestViewerLinks(); err != nil {
		log.Printf("failed to clear previous test viewer links: %v", err)
	}

	base := publicBaseURL(r)
	sent := 0
	var lastErr error
	for _, recipient := range targets {
		token, err := generateViewerToken()
		if err != nil {
			lastErr = err
			continue
		}
		expiresAt := time.Now().Add(testViewerLinkValidity)
		if err := app.db.CreateViewerLinkWithExpiry(recipient.ID, token, expiresAt, true); err != nil {
			lastErr = err
			continue
		}
		viewerURL := base + "/view/" + token
		if err := app.sendTestViewerEmail(recipient, viewerURL, testViewerLinkValidity); err != nil {
			lastErr = err
			log.Printf("failed to send test viewer email to recipient %d: %v", recipient.ID, err)
			continue
		}
		sent++
	}

	switch {
	case sent == 0:
		if lastErr != nil {
			log.Printf("test email failed: %v", lastErr)
		}
		setFlash(w, "test_email_failed", "error")
	case sent < len(targets):
		log.Printf("test viewer email: sent %d of %d", sent, len(targets))
		setFlash(w, "test_email_partial", "error")
	default:
		setFlash(w, "test_email_sent", "success")
	}
	http.Redirect(w, r, "/recipients", http.StatusSeeOther)
}

// recipientsTestEmailClearHandler revokes every outstanding test link.
func (app *App) recipientsTestEmailClearHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := app.db.DeleteTestViewerLinks(); err != nil {
		setFlash(w, "test_email_clear_failed", "error")
	} else {
		setFlash(w, "test_email_cleared", "success")
	}
	http.Redirect(w, r, "/recipients", http.StatusSeeOther)
}

func (app *App) recipientsReorderHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	ids := r.Form["id"]
	for i, idStr := range ids {
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			continue
		}
		_ = app.db.UpdateRecipientSortOrder(id, i)
	}
	w.WriteHeader(http.StatusNoContent)
}

// Secrets handlers.
func (app *App) secretsHandler(w http.ResponseWriter, r *http.Request) {
	app.secretsByCategoryHandler(w, r, "financial")
}

func (app *App) secretCategoryPath(category string) string {
	switch category {
	case "insurance":
		return "/insurance"
	case "subscription":
		return "/subscriptions"
	default:
		return "/secrets"
	}
}

func secretCategory(r *http.Request) string {
	if strings.HasPrefix(r.URL.Path, "/insurance") {
		return "insurance"
	}
	if strings.HasPrefix(r.URL.Path, "/subscriptions") {
		return "subscription"
	}
	return "financial"
}

func (app *App) secretsByCategoryHandler(w http.ResponseWriter, r *http.Request, category string) {
	list, _ := app.db.ListSecretsByCategory(category)
	app.render(w, r, "secrets.html", &AppData{Secrets: list, Category: category})
}

func (app *App) insuranceHandler(w http.ResponseWriter, r *http.Request) {
	app.secretsByCategoryHandler(w, r, "insurance")
}
func (app *App) subscriptionHandler(w http.ResponseWriter, r *http.Request) {
	app.secretsByCategoryHandler(w, r, "subscription")
}
func (app *App) insuranceNewHandler(w http.ResponseWriter, r *http.Request) {
	app.secretNewByCategoryHandler(w, r, "insurance")
}
func (app *App) subscriptionNewHandler(w http.ResponseWriter, r *http.Request) {
	app.secretNewByCategoryHandler(w, r, "subscription")
}
func (app *App) insuranceEditHandler(w http.ResponseWriter, r *http.Request) {
	app.secretEditByCategoryHandler(w, r, "insurance")
}
func (app *App) subscriptionEditHandler(w http.ResponseWriter, r *http.Request) {
	app.secretEditByCategoryHandler(w, r, "subscription")
}
func (app *App) insuranceDeleteHandler(w http.ResponseWriter, r *http.Request) {
	app.secretDeleteByCategoryHandler(w, r, "insurance")
}
func (app *App) subscriptionDeleteHandler(w http.ResponseWriter, r *http.Request) {
	app.secretDeleteByCategoryHandler(w, r, "subscription")
}
func (app *App) insuranceViewHandler(w http.ResponseWriter, r *http.Request) {
	app.secretViewByCategoryHandler(w, r, "insurance")
}
func (app *App) subscriptionViewHandler(w http.ResponseWriter, r *http.Request) {
	app.secretViewByCategoryHandler(w, r, "subscription")
}
func (app *App) insuranceReorderHandler(w http.ResponseWriter, r *http.Request) {
	app.secretsReorderByCategoryHandler(w, r, "insurance")
}
func (app *App) subscriptionReorderHandler(w http.ResponseWriter, r *http.Request) {
	app.secretsReorderByCategoryHandler(w, r, "subscription")
}

func parseSecretForm(r *http.Request) (*SecretPayload, error) {
	_ = r.ParseForm()
	payload := &SecretPayload{
		ID:       strings.TrimSpace(r.FormValue("id")),
		URL:      strings.TrimSpace(r.FormValue("url")),
		Password: r.FormValue("password"),
		Memo:     r.FormValue("memo"),
	}
	names := r.Form["field_name"]
	values := r.Form["field_value"]
	hiddens := r.Form["field_hidden"]
	for i := range names {
		name := strings.TrimSpace(names[i])
		if name == "" {
			continue
		}
		val := ""
		if i < len(values) {
			val = values[i]
		}
		hidden := false
		if i < len(hiddens) && hiddens[i] == "1" {
			hidden = true
		}
		payload.Fields = append(payload.Fields, SecretField{Name: name, Value: val, Hidden: hidden})
	}
	return payload, nil
}

func (app *App) secretNewHandler(w http.ResponseWriter, r *http.Request) {
	app.secretNewByCategoryHandler(w, r, "financial")
}

func (app *App) secretNewByCategoryHandler(w http.ResponseWriter, r *http.Request, category string) {
	if r.Method == http.MethodGet {
		app.render(w, r, "secret_form.html", &AppData{Category: category})
		return
	}
	title := strings.TrimSpace(r.FormValue("title"))
	if title == "" {
		setFlash(w, "title_required", "error")
		app.render(w, r, "secret_form.html", &AppData{Category: category})
		return
	}
	payload, err := parseSecretForm(r)
	if err != nil {
		setFlash(w, "input_invalid", "error")
		app.render(w, r, "secret_form.html", &AppData{Category: category})
		return
	}
	content, err := json.Marshal(payload)
	if err != nil {
		setFlash(w, "add_failed", "error")
		app.render(w, r, "secret_form.html", &AppData{Category: category})
		return
	}
	if err := app.db.CreateSecretInCategory(category, title, string(content)); err != nil {
		setFlash(w, "add_failed", "error")
		app.render(w, r, "secret_form.html", &AppData{Category: category})
		return
	}
	setFlash(w, "secret_added", "success")
	http.Redirect(w, r, app.secretCategoryPath(category), http.StatusSeeOther)
}

func (app *App) secretEditHandler(w http.ResponseWriter, r *http.Request) {
	app.secretEditByCategoryHandler(w, r, "financial")
}

func (app *App) secretEditByCategoryHandler(w http.ResponseWriter, r *http.Request, category string) {
	id, _ := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	secret, _ := app.db.GetSecretByCategory(id, category)
	if secret == nil {
		http.Redirect(w, r, app.secretCategoryPath(category), http.StatusSeeOther)
		return
	}
	if r.Method == http.MethodGet {
		payload, _ := secret.ParseSecretPayload()
		app.render(w, r, "secret_form.html", &AppData{Secret: secret, SecretPayload: payload, Category: category})
		return
	}
	title := strings.TrimSpace(r.FormValue("title"))
	if title == "" {
		setFlash(w, "title_required", "error")
		app.render(w, r, "secret_form.html", &AppData{Secret: secret, Category: category})
		return
	}
	payload, err := parseSecretForm(r)
	if err != nil {
		setFlash(w, "input_invalid", "error")
		app.render(w, r, "secret_form.html", &AppData{Secret: secret, Category: category})
		return
	}
	content, err := json.Marshal(payload)
	if err != nil {
		setFlash(w, "update_failed", "error")
		app.render(w, r, "secret_form.html", &AppData{Secret: secret, Category: category})
		return
	}
	if err := app.db.UpdateSecretInCategory(id, category, title, string(content)); err != nil {
		setFlash(w, "update_failed", "error")
	} else {
		setFlash(w, "secret_updated", "success")
	}
	http.Redirect(w, r, app.secretCategoryPath(category), http.StatusSeeOther)
}

func (app *App) secretViewHandler(w http.ResponseWriter, r *http.Request) {
	app.secretViewByCategoryHandler(w, r, "financial")
}

func (app *App) secretViewByCategoryHandler(w http.ResponseWriter, r *http.Request, category string) {
	id, _ := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	secret, _ := app.db.GetSecretByCategory(id, category)
	if secret == nil {
		http.Redirect(w, r, app.secretCategoryPath(category), http.StatusSeeOther)
		return
	}
	payload, _ := secret.ParseSecretPayload()
	app.render(w, r, "secret_view.html", &AppData{Secret: secret, SecretPayload: payload, Category: category})
}

func (app *App) secretDeleteHandler(w http.ResponseWriter, r *http.Request) {
	app.secretDeleteByCategoryHandler(w, r, "financial")
}

func (app *App) secretDeleteByCategoryHandler(w http.ResponseWriter, r *http.Request, category string) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	id, _ := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	if err := app.db.DeleteSecretInCategory(id, category); err != nil {
		setFlash(w, "delete_failed", "error")
	} else {
		setFlash(w, "secret_deleted", "success")
	}
	http.Redirect(w, r, app.secretCategoryPath(category), http.StatusSeeOther)
}

func (app *App) secretsReorderHandler(w http.ResponseWriter, r *http.Request) {
	app.secretsReorderByCategoryHandler(w, r, "financial")
}

func (app *App) secretsReorderByCategoryHandler(w http.ResponseWriter, r *http.Request, category string) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	ids := r.Form["id"]
	for i, idStr := range ids {
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			continue
		}
		_ = app.db.UpdateSecretSortOrderInCategory(id, category, i)
	}
	w.WriteHeader(http.StatusNoContent)
}

// Documents handlers.
func (app *App) documentsHandler(w http.ResponseWriter, r *http.Request) {
	list, _ := app.db.ListDocuments()
	app.render(w, r, "documents.html", &AppData{Documents: list})
}

func (app *App) documentNewHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		app.render(w, r, "document_form.html", nil)
		return
	}
	title := strings.TrimSpace(r.FormValue("title"))
	content := r.FormValue("content")
	if title == "" {
		setFlash(w, "title_required", "error")
		app.render(w, r, "document_form.html", nil)
		return
	}
	if err := app.db.CreateDocument(title, content); err != nil {
		setFlash(w, "add_failed", "error")
		app.render(w, r, "document_form.html", nil)
		return
	}
	setFlash(w, "document_added", "success")
	http.Redirect(w, r, "/documents", http.StatusSeeOther)
}

func (app *App) documentEditHandler(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	doc, _ := app.db.GetDocument(id)
	if doc == nil {
		http.Redirect(w, r, "/documents", http.StatusSeeOther)
		return
	}
	if r.Method == http.MethodGet {
		app.render(w, r, "document_form.html", &AppData{Document: doc})
		return
	}
	title := strings.TrimSpace(r.FormValue("title"))
	content := r.FormValue("content")
	if title == "" {
		setFlash(w, "title_required", "error")
		app.render(w, r, "document_form.html", &AppData{Document: doc})
		return
	}
	if err := app.db.UpdateDocument(id, title, content); err != nil {
		setFlash(w, "update_failed", "error")
	} else {
		setFlash(w, "document_updated", "success")
	}
	http.Redirect(w, r, "/documents", http.StatusSeeOther)
}

func (app *App) documentDeleteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	id, _ := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	if err := app.db.DeleteDocument(id); err != nil {
		setFlash(w, "delete_failed", "error")
	} else {
		setFlash(w, "document_deleted", "success")
	}
	http.Redirect(w, r, "/documents", http.StatusSeeOther)
}

func (app *App) documentsReorderHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	ids := r.Form["id"]
	for i, idStr := range ids {
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			continue
		}
		_ = app.db.UpdateDocumentSortOrder(id, i)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (app *App) documentPreviewHandler(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	doc, _ := app.db.GetDocument(id)
	if doc == nil {
		http.NotFound(w, r)
		return
	}
	app.render(w, r, "document_preview.html", &AppData{Document: doc})
}

// Overdue watcher.
func (app *App) watchOverdue(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	// Run immediately on startup too.
	app.checkTrigger()
	app.db.DeleteExpiredViewerLinks()
	for range ticker.C {
		app.checkTrigger()
		app.db.DeleteExpiredViewerLinks()
	}
}

func (app *App) checkTrigger() {
	user, err := app.db.GetUser()
	if err != nil || user == nil {
		return
	}
	if !user.EmailEnabled || user.IsTriggered || user.LastCheckInAt == nil {
		return
	}
	deadline := user.LastCheckInAt.Add(time.Duration(user.CheckInIntervalHours) * time.Hour)
	if time.Now().Before(deadline) {
		return
	}
	recipients, err := app.db.ListRecipients()
	if err != nil || len(recipients) == 0 {
		log.Println("overdue check-in detected but no recipients configured")
		return
	}
	// Record the id watermark so that a later successful attempt can prune
	// links left over from incomplete attempts. Links already delivered by an
	// earlier partial attempt stay valid until then, so a retry no longer
	// invalidates a URL a recipient has already received.
	watermark, err := app.db.MaxViewerLinkID()
	if err != nil {
		log.Printf("failed to read viewer link watermark: %v", err)
		return
	}
	log.Printf("Overdue action triggered, sending viewer links to %d recipient(s)", len(recipients))
	allSent := true
	for _, recipient := range recipients {
		token, err := generateViewerToken()
		if err != nil {
			log.Printf("failed to generate viewer token: %v", err)
			allSent = false
			continue
		}
		if err := app.db.CreateViewerLink(recipient.ID, token); err != nil {
			log.Printf("failed to save viewer link: %v", err)
			allSent = false
			continue
		}
		viewerURL := publicBaseURL(nil) + "/view/" + token
		if err := app.sendViewerEmail(recipient, viewerURL); err != nil {
			log.Printf("failed to send viewer email to recipient %d: %v", recipient.ID, err)
			allSent = false
		}
	}
	if !allSent {
		// Keep every link valid (including ones already delivered) so the
		// next attempt can retry the failed recipients.
		return
	}
	// The full generation is delivered; drop the earlier partial attempts.
	if err := app.db.DeleteViewerLinksUpTo(watermark); err != nil {
		log.Printf("failed to prune old viewer links: %v", err)
	}
	if err := app.db.MarkTriggered(); err != nil {
		log.Printf("failed to mark triggered: %v", err)
	}
}
