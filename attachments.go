package main

import (
	"database/sql"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
)

// maxAttachmentSize is the per-file upload size limit.
const maxAttachmentSize = 30 << 20 // 30 MB

// maxAttachmentsPerSecret limits the number of files per secret.
const maxAttachmentsPerSecret = 20

// Attachment is a file attached to a Secret. The binary data is encrypted at
// rest with the same AES-GCM key as the secret contents.
type Attachment struct {
	ID        int64
	SecretID  int64
	Filename  string
	MimeType  string
	Size      int64
	CreatedAt time.Time
}

// sanitizeAttachmentFilename makes a filename safe for storage and headers.
func sanitizeAttachmentFilename(name string) string {
	name = path.Base(strings.ReplaceAll(strings.TrimSpace(name), "\\", "/"))
	if name == "." || name == "/" || name == "" {
		return "unnamed"
	}
	var b strings.Builder
	for _, r := range name {
		if r < 32 || r == 127 {
			continue
		}
		b.WriteRune(r)
	}
	name = strings.TrimSpace(b.String())
	if name == "" {
		name = "unnamed"
	}
	if len(name) > 150 {
		name = name[len(name)-150:]
	}
	return name
}

// --- DB helpers -------------------------------------------------------------

func (db *DB) ListAttachments(secretID int64) ([]Attachment, error) {
	rows, err := db.conn.Query("SELECT id, secret_id, filename, mime_type, size, created_at FROM attachments WHERE secret_id = ? ORDER BY sort_order, id", secretID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []Attachment
	for rows.Next() {
		a := Attachment{}
		if err := rows.Scan(&a.ID, &a.SecretID, &a.Filename, &a.MimeType, &a.Size, &a.CreatedAt); err != nil {
			return nil, err
		}
		list = append(list, a)
	}
	return list, rows.Err()
}

func (db *DB) CountAttachments(secretID int64) (int, error) {
	var n int
	err := db.conn.QueryRow("SELECT COUNT(*) FROM attachments WHERE secret_id = ?", secretID).Scan(&n)
	return n, err
}

// AddAttachment encrypts and stores a file for the given secret.
func (db *DB) AddAttachment(secretID int64, filename, mimeType string, data []byte) error {
	if len(data) > maxAttachmentSize {
		return fmt.Errorf("attachment too large")
	}
	ct, err := encryptBytes(data, db.key)
	if err != nil {
		return err
	}
	_, err = db.conn.Exec("INSERT INTO attachments (secret_id, filename, mime_type, size, data, sort_order) VALUES (?, ?, ?, ?, ?, COALESCE((SELECT MAX(sort_order)+1 FROM attachments WHERE secret_id = ?), 0))",
		secretID, filename, mimeType, len(data), ct, secretID)
	return err
}

// DeleteAttachment removes a single attachment owned by the secret.
func (db *DB) DeleteAttachment(id, secretID int64) error {
	_, err := db.conn.Exec("DELETE FROM attachments WHERE id = ? AND secret_id = ?", id, secretID)
	return err
}

// GetAttachment returns the metadata of one attachment.
func (db *DB) GetAttachment(id, secretID int64) (*Attachment, error) {
	a := &Attachment{}
	err := db.conn.QueryRow("SELECT id, secret_id, filename, mime_type, size, created_at FROM attachments WHERE id = ? AND secret_id = ?", id, secretID).
		Scan(&a.ID, &a.SecretID, &a.Filename, &a.MimeType, &a.Size, &a.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return a, nil
}

// GetAttachmentData decrypts and returns the file content.
func (db *DB) GetAttachmentData(id int64) ([]byte, error) {
	var ct string
	err := db.conn.QueryRow("SELECT data FROM attachments WHERE id = ?", id).Scan(&ct)
	if err != nil {
		return nil, err
	}
	return decryptBytes(ct, db.key)
}

// --- Handlers ---------------------------------------------------------------

// writeAttachment serves the decrypted content as a download.
func (app *App) writeAttachment(w http.ResponseWriter, att *Attachment) {
	data, err := app.db.GetAttachmentData(att.ID)
	if err != nil {
		log.Printf("failed to decrypt attachment %d: %v", att.ID, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", att.MimeType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename*=UTF-8''%s", url.PathEscape(att.Filename)))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
	_, _ = w.Write(data)
}

// attachmentDownloadHandler serves a file to the authenticated administrator.
func (app *App) attachmentDownloadHandler(w http.ResponseWriter, r *http.Request) {
	secretID, _ := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	attID, _ := strconv.ParseInt(r.URL.Query().Get("att"), 10, 64)
	if _, err := app.db.GetSecretAnyCategory(secretID); err != nil {
		http.NotFound(w, r)
		return
	}
	att, err := app.db.GetAttachment(attID, secretID)
	if err != nil || att == nil {
		http.NotFound(w, r)
		return
	}
	app.writeAttachment(w, att)
}

// saveFormAttachments stores newly uploaded files for the secret.
func (app *App) saveFormAttachments(secretID int64, r *http.Request) error {
	if r.MultipartForm == nil || len(r.MultipartForm.File["attachment"]) == 0 {
		return nil
	}
	current, err := app.db.CountAttachments(secretID)
	if err != nil {
		return err
	}
	for _, fh := range r.MultipartForm.File["attachment"] {
		if fh.Size == 0 {
			continue
		}
		if current >= maxAttachmentsPerSecret {
			return fmt.Errorf("attachment limit exceeded")
		}
		if fh.Size > maxAttachmentSize {
			return fmt.Errorf("attachment too large: %s", fh.Filename)
		}
		f, err := fh.Open()
		if err != nil {
			return err
		}
		data, err := io.ReadAll(f)
		f.Close()
		if err != nil {
			return err
		}
		name := sanitizeAttachmentFilename(fh.Filename)
		mime := fh.Header.Get("Content-Type")
		if mime == "" || strings.ContainsAny(mime, "\n\r") {
			mime = "application/octet-stream"
		}
		if err := app.db.AddAttachment(secretID, name, mime, data); err != nil {
			return err
		}
		current++
	}
	return nil
}

// processAttachmentRemovals deletes attachments ticked for removal on the form.
func (app *App) processAttachmentRemovals(secretID int64, r *http.Request) error {
	for _, raw := range r.Form["remove_attachment"] {
		id, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
		if err != nil || id <= 0 {
			continue
		}
		if err := app.db.DeleteAttachment(id, secretID); err != nil {
			return err
		}
	}
	return nil
}
