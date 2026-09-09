package main

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gomarkdown/markdown"
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
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		log.Fatalf("failed to create data directory: %v", err)
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
	mux.HandleFunc("/settings", app.authMiddleware(app.settingsHandler))
	mux.HandleFunc("/settings/checkin", app.authMiddleware(app.settingsCheckInHandler))

	mux.HandleFunc("/recipients", app.authMiddleware(app.recipientsHandler))
	mux.HandleFunc("/recipients/new", app.authMiddleware(app.recipientNewHandler))
	mux.HandleFunc("/recipients/edit", app.authMiddleware(app.recipientEditHandler))
	mux.HandleFunc("/recipients/delete", app.authMiddleware(app.recipientDeleteHandler))
	mux.HandleFunc("/recipients/reorder", app.authMiddleware(app.recipientsReorderHandler))

	mux.HandleFunc("/secrets", app.authMiddleware(app.secretsHandler))
	mux.HandleFunc("/secrets/new", app.authMiddleware(app.secretNewHandler))
	mux.HandleFunc("/secrets/edit", app.authMiddleware(app.secretEditHandler))
	mux.HandleFunc("/secrets/delete", app.authMiddleware(app.secretDeleteHandler))
	mux.HandleFunc("/secrets/view", app.authMiddleware(app.secretViewHandler))
	mux.HandleFunc("/secrets/reorder", app.authMiddleware(app.secretsReorderHandler))

	mux.HandleFunc("/documents", app.authMiddleware(app.documentsHandler))
	mux.HandleFunc("/documents/new", app.authMiddleware(app.documentNewHandler))
	mux.HandleFunc("/documents/edit", app.authMiddleware(app.documentEditHandler))
	mux.HandleFunc("/documents/delete", app.authMiddleware(app.documentDeleteHandler))
	mux.HandleFunc("/documents/preview", app.authMiddleware(app.documentPreviewHandler))
	mux.HandleFunc("/documents/reorder", app.authMiddleware(app.documentsReorderHandler))

	handler := languageMiddleware(ipFilter(mux, db))

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
	log.Printf("Application server starting on %s://%s", scheme, addr)
	if useTLS {
		if err := http.ListenAndServeTLS(addr, certFile, keyFile, handler); err != nil {
			log.Fatalf("server error: %v", err)
		}
	} else {
		if err := http.ListenAndServe(addr, handler); err != nil {
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

func (app *App) render(w http.ResponseWriter, r *http.Request, name string, data *AppData) {
	if data == nil {
		data = &AppData{}
	}
	user, _ := app.currentUser(r)
	data.User = user
	data.Lang = languageFromRequest(r)
	data.RequestPath = r.URL.RequestURI()
	data.AppName = applicationName
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

func renderMarkdown(s string) template.HTML {
	extensions := parser.CommonExtensions | parser.AutoHeadingIDs | parser.NoEmptyLineBeforeBlock
	p := parser.NewWithExtensions(extensions)
	doc := p.Parse([]byte(s))
	opts := html.RendererOptions{Flags: html.CommonFlags | html.HrefTargetBlank}
	renderer := html.NewRenderer(opts)
	return template.HTML(markdown.Render(doc, renderer))
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
		password := r.FormValue("password")
		if !checkPassword(password, user.PasswordHash) {
			setFlash(w, "incorrect_password", "error")
			app.render(w, r, "login.html", nil)
			return
		}
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
		http.SetCookie(w, &http.Cookie{
			Name:     sessionCookieName,
			Value:    token,
			Expires:  expires,
			HttpOnly: true,
			Path:     "/",
		})
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
}

func (app *App) logoutHandler(w http.ResponseWriter, r *http.Request) {
	_ = app.db.ClearSession()
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Path:     "/",
	})
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
		setFlash(w, "checkin_updated", "success")
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// checkInURL builds the private URL from the request's origin. The token is
// only passed to this function from an authenticated settings request.
func checkInURL(r *http.Request, token string) string {
	if token == "" {
		return ""
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + "/checkin/" + token
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
	settings, _ := app.db.GetSMTPSettings()
	if settings == nil {
		settings = &SMTPSettings{Host: "smtp.gmail.com", Port: 587, UseTLS: true}
	}
	allowedIPs, _ := app.db.GetConfig("allowed_ips")
	checkInToken, _ := app.db.GetCheckInToken()
	checkInURLValue := checkInURL(r, checkInToken)
	if r.Method == http.MethodGet {
		app.render(w, r, "settings.html", &AppData{User: user, SMTPSettings: settings, AllowedIPs: allowedIPs, CheckInURL: checkInURLValue})
		return
	}
	if r.Method == http.MethodPost {
		action := r.FormValue("action")
		if action == "change_password" {
			currentPassword := r.FormValue("current_password")
			newPassword := r.FormValue("new_password")
			confirmPassword := r.FormValue("confirm_password")
			if currentPassword == "" || newPassword == "" || confirmPassword == "" {
				setFlash(w, "password_fields_required", "error")
				app.render(w, r, "settings.html", &AppData{User: user, SMTPSettings: settings, AllowedIPs: allowedIPs, CheckInURL: checkInURLValue})
				return
			}
			if !checkPassword(currentPassword, user.PasswordHash) {
				setFlash(w, "current_password_incorrect", "error")
				app.render(w, r, "settings.html", &AppData{User: user, SMTPSettings: settings, AllowedIPs: allowedIPs, CheckInURL: checkInURLValue})
				return
			}
			if newPassword != confirmPassword {
				setFlash(w, "new_password_mismatch", "error")
				app.render(w, r, "settings.html", &AppData{User: user, SMTPSettings: settings, AllowedIPs: allowedIPs, CheckInURL: checkInURLValue})
				return
			}
			hash, err := hashPassword(newPassword)
			if err != nil {
				setFlash(w, "password_hash_failed", "error")
				app.render(w, r, "settings.html", &AppData{User: user, SMTPSettings: settings, AllowedIPs: allowedIPs, CheckInURL: checkInURLValue})
				return
			}
			if err := app.db.UpdateUserPassword(hash); err != nil {
				setFlash(w, "password_change_failed", "error")
				app.render(w, r, "settings.html", &AppData{User: user, SMTPSettings: settings, AllowedIPs: allowedIPs, CheckInURL: checkInURLValue})
				return
			}
			setFlash(w, "password_changed", "success")
			http.Redirect(w, r, "/settings", http.StatusSeeOther)
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
		if host == "" || port == 0 || username == "" || from == "" {
			setFlash(w, "smtp_required", "error")
			app.render(w, r, "settings.html", &AppData{User: user, SMTPSettings: settings, AllowedIPs: newAllowedIPs, CheckInURL: checkInURLValue})
			return
		}
		if newAllowedIPs != "" {
			if _, err := parseAllowedNetworks(newAllowedIPs); err != nil {
				setFlash(w, "allowed_ip_invalid|"+err.Error(), "error")
				app.render(w, r, "settings.html", &AppData{User: user, SMTPSettings: settings, AllowedIPs: newAllowedIPs, CheckInURL: checkInURLValue})
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
		app.render(w, r, "settings.html", &AppData{User: user, SMTPSettings: newSettings, AllowedIPs: newAllowedIPs, CheckInURL: checkInURLValue})
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
	list, _ := app.db.ListSecrets()
	app.render(w, r, "secrets.html", &AppData{Secrets: list})
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
	if r.Method == http.MethodGet {
		app.render(w, r, "secret_form.html", nil)
		return
	}
	title := strings.TrimSpace(r.FormValue("title"))
	if title == "" {
		setFlash(w, "title_required", "error")
		app.render(w, r, "secret_form.html", nil)
		return
	}
	payload, err := parseSecretForm(r)
	if err != nil {
		setFlash(w, "input_invalid", "error")
		app.render(w, r, "secret_form.html", nil)
		return
	}
	content, err := json.Marshal(payload)
	if err != nil {
		setFlash(w, "add_failed", "error")
		app.render(w, r, "secret_form.html", nil)
		return
	}
	if err := app.db.CreateSecret(title, string(content)); err != nil {
		setFlash(w, "add_failed", "error")
		app.render(w, r, "secret_form.html", nil)
		return
	}
	setFlash(w, "secret_added", "success")
	http.Redirect(w, r, "/secrets", http.StatusSeeOther)
}

func (app *App) secretEditHandler(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	secret, _ := app.db.GetSecret(id)
	if secret == nil {
		http.Redirect(w, r, "/secrets", http.StatusSeeOther)
		return
	}
	if r.Method == http.MethodGet {
		payload, _ := secret.ParseSecretPayload()
		app.render(w, r, "secret_form.html", &AppData{Secret: secret, SecretPayload: payload})
		return
	}
	title := strings.TrimSpace(r.FormValue("title"))
	if title == "" {
		setFlash(w, "title_required", "error")
		app.render(w, r, "secret_form.html", &AppData{Secret: secret})
		return
	}
	payload, err := parseSecretForm(r)
	if err != nil {
		setFlash(w, "input_invalid", "error")
		app.render(w, r, "secret_form.html", &AppData{Secret: secret})
		return
	}
	content, err := json.Marshal(payload)
	if err != nil {
		setFlash(w, "update_failed", "error")
		app.render(w, r, "secret_form.html", &AppData{Secret: secret})
		return
	}
	if err := app.db.UpdateSecret(id, title, string(content)); err != nil {
		setFlash(w, "update_failed", "error")
	} else {
		setFlash(w, "secret_updated", "success")
	}
	http.Redirect(w, r, "/secrets", http.StatusSeeOther)
}

func (app *App) secretViewHandler(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	secret, _ := app.db.GetSecret(id)
	if secret == nil {
		http.Redirect(w, r, "/secrets", http.StatusSeeOther)
		return
	}
	payload, _ := secret.ParseSecretPayload()
	app.render(w, r, "secret_view.html", &AppData{Secret: secret, SecretPayload: payload})
}

func (app *App) secretDeleteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	id, _ := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	if err := app.db.DeleteSecret(id); err != nil {
		setFlash(w, "delete_failed", "error")
	} else {
		setFlash(w, "secret_deleted", "success")
	}
	http.Redirect(w, r, "/secrets", http.StatusSeeOther)
}

func (app *App) secretsReorderHandler(w http.ResponseWriter, r *http.Request) {
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
		_ = app.db.UpdateSecretSortOrder(id, i)
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
	for range ticker.C {
		app.checkTrigger()
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
	secrets, err := app.db.ListSecrets()
	if err != nil {
		log.Printf("failed to list secrets: %v", err)
	}
	documents, err := app.db.ListDocuments()
	if err != nil {
		log.Printf("failed to list documents: %v", err)
	}
	log.Printf("Overdue action triggered, sending to %d recipient(s)", len(recipients))
	if err := app.sendTriggerEmail(recipients, secrets, documents); err != nil {
		log.Printf("failed to send trigger email: %v", err)
		return
	}
	if err := app.db.MarkTriggered(); err != nil {
		log.Printf("failed to mark triggered: %v", err)
	}
}
