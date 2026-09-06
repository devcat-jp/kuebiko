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
	// Load optional .env file before reading environment variables.
	if err := loadEnvFile(".env"); err != nil {
		log.Fatalf("failed to load .env file: %v", err)
	}

	dataDir := os.Getenv("KUEBIKO_DATA_DIR")
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

	dbPath := filepath.Join(dataDir, "kuebiko.db")
	db, err := NewDB(dbPath, key)
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	tmpl, err := template.New("").Funcs(template.FuncMap{
		"md": renderMarkdown,
	}).ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		log.Fatalf("failed to parse templates: %v", err)
	}

	app := &App{db: db, templates: tmpl}

	// Start the kuebiko watcher.
	checkInterval := 1 * time.Hour
	if d, err := time.ParseDuration(os.Getenv("KUEBIKO_CHECK_INTERVAL")); err == nil && d > 0 {
		checkInterval = d
	}
	go app.watchKuebiko(checkInterval)

	mux := http.NewServeMux()
	mux.Handle("/static/", http.FileServerFS(staticFS))

	mux.HandleFunc("/", app.authMiddleware(app.dashboardHandler))
	mux.HandleFunc("/setup", app.setupHandler)
	mux.HandleFunc("/login", app.loginHandler)
	mux.HandleFunc("/logout", app.logoutHandler)
	mux.HandleFunc("/checkin", app.authMiddleware(app.checkInHandler))
	mux.HandleFunc("/settings", app.authMiddleware(app.settingsHandler))

	mux.HandleFunc("/recipients", app.authMiddleware(app.recipientsHandler))
	mux.HandleFunc("/recipients/new", app.authMiddleware(app.recipientNewHandler))
	mux.HandleFunc("/recipients/edit", app.authMiddleware(app.recipientEditHandler))
	mux.HandleFunc("/recipients/delete", app.authMiddleware(app.recipientDeleteHandler))

	mux.HandleFunc("/secrets", app.authMiddleware(app.secretsHandler))
	mux.HandleFunc("/secrets/new", app.authMiddleware(app.secretNewHandler))
	mux.HandleFunc("/secrets/edit", app.authMiddleware(app.secretEditHandler))
	mux.HandleFunc("/secrets/delete", app.authMiddleware(app.secretDeleteHandler))
	mux.HandleFunc("/secrets/view", app.authMiddleware(app.secretViewHandler))

	mux.HandleFunc("/documents", app.authMiddleware(app.documentsHandler))
	mux.HandleFunc("/documents/new", app.authMiddleware(app.documentNewHandler))
	mux.HandleFunc("/documents/edit", app.authMiddleware(app.documentEditHandler))
	mux.HandleFunc("/documents/delete", app.authMiddleware(app.documentDeleteHandler))
	mux.HandleFunc("/documents/preview", app.authMiddleware(app.documentPreviewHandler))

	handler := ipFilter(mux, db)

	host := os.Getenv("KUEBIKO_HOST")
	if host == "" {
		host = "127.0.0.1"
	}
	port := os.Getenv("KUEBIKO_PORT")
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
	log.Printf("Kuebiko server starting on %s://%s", scheme, addr)
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
// KUEBIKO_ENCRYPTION_KEY environment variable or the configured key file.
// If neither is available, a new key is generated and written to the file.
func loadOrGenerateEncryptionKey(dataDir string) (string, error) {
	if key := os.Getenv("KUEBIKO_ENCRYPTION_KEY"); key != "" {
		return key, nil
	}

	keyPath := os.Getenv("KUEBIKO_ENCRYPTION_KEY_FILE")
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
	flash, flashType := getFlash(w, r)
	data.Flash = flash
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
		username := strings.TrimSpace(r.FormValue("username"))
		password := r.FormValue("password")
		confirm := r.FormValue("confirm")
		if username == "" || password == "" {
			setFlash(w, "ユーザー名とパスワードを入力してください", "error")
			app.render(w, r, "setup.html", nil)
			return
		}
		if password != confirm {
			setFlash(w, "パスワードが一致しません", "error")
			app.render(w, r, "setup.html", nil)
			return
		}
		hash, err := hashPassword(password)
		if err != nil {
			setFlash(w, "エラーが発生しました", "error")
			app.render(w, r, "setup.html", nil)
			return
		}
		if err := app.db.CreateUser(username, hash); err != nil {
			setFlash(w, "ユーザー作成に失敗しました", "error")
			app.render(w, r, "setup.html", nil)
			return
		}
		// Initialize check-in time to now with default 7-day interval.
		_ = app.db.UpdateCheckIn(168, time.Now())
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
		username := strings.TrimSpace(r.FormValue("username"))
		password := r.FormValue("password")
		if username != user.Username || !checkPassword(password, user.PasswordHash) {
			setFlash(w, "ユーザー名またはパスワードが違います", "error")
			app.render(w, r, "login.html", nil)
			return
		}
		token, err := generateSessionToken()
		if err != nil {
			setFlash(w, "エラーが発生しました", "error")
			app.render(w, r, "login.html", nil)
			return
		}
		expires := time.Now().Add(24 * time.Hour)
		if err := app.db.UpdateUserSession(token, expires); err != nil {
			setFlash(w, "エラーが発生しました", "error")
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
		setFlash(w, "生存確認の更新に失敗しました", "error")
	} else {
		setFlash(w, "生存確認を更新しました", "success")
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// Settings handler (SMTP, email toggle, and IP restrictions).
func (app *App) settingsHandler(w http.ResponseWriter, r *http.Request) {
	user, _ := app.db.GetUser()
	settings, _ := app.db.GetSMTPSettings()
	if settings == nil {
		settings = &SMTPSettings{Host: "smtp.gmail.com", Port: 587, UseTLS: true}
	}
	allowedIPs, _ := app.db.GetConfig("allowed_ips")
	if r.Method == http.MethodGet {
		app.render(w, r, "settings.html", &AppData{User: user, SMTPSettings: settings, AllowedIPs: allowedIPs})
		return
	}
	if r.Method == http.MethodPost {
		host := strings.TrimSpace(r.FormValue("host"))
		port, _ := strconv.Atoi(r.FormValue("port"))
		username := strings.TrimSpace(r.FormValue("username"))
		password := r.FormValue("password")
		from := strings.TrimSpace(r.FormValue("from_address"))
		useTLS := r.FormValue("use_tls") == "1"
		enabled := r.FormValue("email_enabled") == "1"
		newAllowedIPs := strings.TrimSpace(r.FormValue("allowed_ips"))
		if host == "" || port == 0 || username == "" || from == "" {
			setFlash(w, "SMTP 設定を入力してください", "error")
			app.render(w, r, "settings.html", &AppData{User: user, SMTPSettings: settings, AllowedIPs: newAllowedIPs})
			return
		}
		if newAllowedIPs != "" {
			if _, err := parseAllowedNetworks(newAllowedIPs); err != nil {
				setFlash(w, "許可 IP の形式が正しくありません: "+err.Error(), "error")
				app.render(w, r, "settings.html", &AppData{User: user, SMTPSettings: settings, AllowedIPs: newAllowedIPs})
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
			setFlash(w, "設定の保存に失敗しました", "error")
		} else {
			_ = app.db.SetEmailEnabled(enabled)
			if err := app.db.SetConfig("allowed_ips", newAllowedIPs); err != nil {
				setFlash(w, "許可 IP の保存に失敗しました", "error")
			} else {
				setFlash(w, "設定を保存しました", "success")
			}
		}
		app.render(w, r, "settings.html", &AppData{User: user, SMTPSettings: newSettings, AllowedIPs: newAllowedIPs})
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
		setFlash(w, "メールアドレスを入力してください", "error")
		app.render(w, r, "recipient_form.html", nil)
		return
	}
	if err := app.db.CreateRecipient(email, name); err != nil {
		setFlash(w, "追加に失敗しました", "error")
		app.render(w, r, "recipient_form.html", nil)
		return
	}
	setFlash(w, "受信者を追加しました", "success")
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
		setFlash(w, "メールアドレスを入力してください", "error")
		app.render(w, r, "recipient_form.html", &AppData{Recipient: recipient})
		return
	}
	if err := app.db.UpdateRecipient(id, email, name); err != nil {
		setFlash(w, "更新に失敗しました", "error")
	} else {
		setFlash(w, "受信者を更新しました", "success")
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
		setFlash(w, "削除に失敗しました", "error")
	} else {
		setFlash(w, "受信者を削除しました", "success")
	}
	http.Redirect(w, r, "/recipients", http.StatusSeeOther)
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
		setFlash(w, "タイトルを入力してください", "error")
		app.render(w, r, "secret_form.html", nil)
		return
	}
	payload, err := parseSecretForm(r)
	if err != nil {
		setFlash(w, "入力内容を確認してください", "error")
		app.render(w, r, "secret_form.html", nil)
		return
	}
	content, err := json.Marshal(payload)
	if err != nil {
		setFlash(w, "追加に失敗しました", "error")
		app.render(w, r, "secret_form.html", nil)
		return
	}
	if err := app.db.CreateSecret(title, string(content)); err != nil {
		setFlash(w, "追加に失敗しました", "error")
		app.render(w, r, "secret_form.html", nil)
		return
	}
	setFlash(w, "ログイン情報を追加しました", "success")
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
		setFlash(w, "タイトルを入力してください", "error")
		app.render(w, r, "secret_form.html", &AppData{Secret: secret})
		return
	}
	payload, err := parseSecretForm(r)
	if err != nil {
		setFlash(w, "入力内容を確認してください", "error")
		app.render(w, r, "secret_form.html", &AppData{Secret: secret})
		return
	}
	content, err := json.Marshal(payload)
	if err != nil {
		setFlash(w, "更新に失敗しました", "error")
		app.render(w, r, "secret_form.html", &AppData{Secret: secret})
		return
	}
	if err := app.db.UpdateSecret(id, title, string(content)); err != nil {
		setFlash(w, "更新に失敗しました", "error")
	} else {
		setFlash(w, "ログイン情報を更新しました", "success")
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
		setFlash(w, "削除に失敗しました", "error")
	} else {
		setFlash(w, "ログイン情報を削除しました", "success")
	}
	http.Redirect(w, r, "/secrets", http.StatusSeeOther)
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
		setFlash(w, "タイトルを入力してください", "error")
		app.render(w, r, "document_form.html", nil)
		return
	}
	if err := app.db.CreateDocument(title, content); err != nil {
		setFlash(w, "追加に失敗しました", "error")
		app.render(w, r, "document_form.html", nil)
		return
	}
	setFlash(w, "ドキュメントを追加しました", "success")
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
		setFlash(w, "タイトルを入力してください", "error")
		app.render(w, r, "document_form.html", &AppData{Document: doc})
		return
	}
	if err := app.db.UpdateDocument(id, title, content); err != nil {
		setFlash(w, "更新に失敗しました", "error")
	} else {
		setFlash(w, "ドキュメントを更新しました", "success")
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
		setFlash(w, "削除に失敗しました", "error")
	} else {
		setFlash(w, "ドキュメントを削除しました", "success")
	}
	http.Redirect(w, r, "/documents", http.StatusSeeOther)
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

// Kuebiko watcher.
func (app *App) watchKuebiko(interval time.Duration) {
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
		log.Println("kuebiko overdue but no recipients configured")
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
	log.Printf("Kuebiko triggered for user %s, sending to %d recipient(s)", user.Username, len(recipients))
	if err := app.sendTriggerEmail(recipients, secrets, documents); err != nil {
		log.Printf("failed to send trigger email: %v", err)
		return
	}
	if err := app.db.MarkTriggered(); err != nil {
		log.Printf("failed to mark triggered: %v", err)
	}
}
