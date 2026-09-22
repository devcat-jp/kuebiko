package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// DB wraps the SQLite connection and encryption key.
type DB struct {
	conn *sql.DB
	key  string
}

// NewDB opens the SQLite database and initializes the schema.
func NewDB(path, encryptionKey string) (*DB, error) {
	// foreign_keys(1) is required for the viewer_links ON DELETE CASCADE
	// constraint to be enforced; SQLite disables foreign keys by default and
	// the setting is per-connection, so it must be part of the DSN.
	conn, err := sql.Open("sqlite", path+"?_journal_mode=WAL&_busy_timeout=5000&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	if err := conn.Ping(); err != nil {
		return nil, err
	}
	db := &DB{conn: conn, key: encryptionKey}
	if err := db.createSchema(); err != nil {
		return nil, err
	}
	// Keep the database and its WAL sidecar files private to the owner.
	// Besides the encrypted secrets, these files hold the SMTP password and
	// the admin session token, so world-readable permissions would expose
	// both to any other local user.
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		if err := os.Chmod(p, 0600); err != nil && !os.IsNotExist(err) {
			log.Printf("failed to restrict permissions on %s: %v", p, err)
		}
	}
	return db, nil
}

func (db *DB) createSchema() error {
	schema := `
CREATE TABLE IF NOT EXISTS config (
	key TEXT PRIMARY KEY,
	value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
	id INTEGER PRIMARY KEY CHECK (id = 1),
	password_hash TEXT NOT NULL,
	session_token TEXT,
	session_expires_at DATETIME,
	check_in_interval_hours INTEGER NOT NULL DEFAULT 168,
	last_check_in_at DATETIME,
	is_triggered INTEGER NOT NULL DEFAULT 0,
	email_enabled INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS smtp_settings (
	id INTEGER PRIMARY KEY CHECK (id = 1),
	host TEXT NOT NULL,
	port INTEGER NOT NULL,
	username TEXT NOT NULL,
	password TEXT NOT NULL,
	from_address TEXT NOT NULL,
	use_tls INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS recipients (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	email TEXT NOT NULL UNIQUE,
	name TEXT,
	sort_order INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS secrets (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	category TEXT NOT NULL DEFAULT 'financial',
	title TEXT NOT NULL,
	content TEXT NOT NULL,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	sort_order INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS documents (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	title TEXT NOT NULL,
	content TEXT NOT NULL,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	sort_order INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS viewer_links (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	recipient_id INTEGER NOT NULL,
	token_hash TEXT NOT NULL UNIQUE,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	expires_at INTEGER,
	is_test INTEGER NOT NULL DEFAULT 0,
	FOREIGN KEY (recipient_id) REFERENCES recipients(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS attachments (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	secret_id INTEGER NOT NULL,
	filename TEXT NOT NULL,
	mime_type TEXT NOT NULL DEFAULT 'application/octet-stream',
	size INTEGER NOT NULL DEFAULT 0,
	data TEXT NOT NULL,
	sort_order INTEGER NOT NULL DEFAULT 0,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (secret_id) REFERENCES secrets(id) ON DELETE CASCADE
);
`
	if _, err := db.conn.Exec(schema); err != nil {
		return err
	}
	// Older databases do not have the category column. Existing records are
	// financial information, so migrate them without changing their content.
	var categoryColumn string
	err := db.conn.QueryRow("SELECT name FROM pragma_table_info('secrets') WHERE name = 'category'").Scan(&categoryColumn)
	hasCategory := err == nil && categoryColumn == "category"
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	if !hasCategory {
		if _, err := db.conn.Exec("ALTER TABLE secrets ADD COLUMN category TEXT NOT NULL DEFAULT 'financial'"); err != nil {
			return err
		}
	}
	// Older databases created viewer_links without the test-link columns.
	// Test links expire automatically and are flagged so they can be told
	// apart from the links issued by the real overdue trigger.
	columns := map[string]string{
		"expires_at": "ALTER TABLE viewer_links ADD COLUMN expires_at INTEGER",
		"is_test":    "ALTER TABLE viewer_links ADD COLUMN is_test INTEGER NOT NULL DEFAULT 0",
	}
	for name, statement := range columns {
		var found string
		err := db.conn.QueryRow("SELECT name FROM pragma_table_info('viewer_links') WHERE name = ?", name).Scan(&found)
		if err != nil && err != sql.ErrNoRows {
			return err
		}
		if found == name {
			continue
		}
		if _, err := db.conn.Exec(statement); err != nil {
			return err
		}
	}
	return nil
}

// Close closes the database connection.
func (db *DB) Close() error {
	return db.conn.Close()
}

// Config helpers.
func (db *DB) GetConfig(key string) (string, error) {
	var value string
	err := db.conn.QueryRow("SELECT value FROM config WHERE key = ?", key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return value, err
}

func (db *DB) SetConfig(key, value string) error {
	_, err := db.conn.Exec("INSERT INTO config (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", key, value)
	return err
}

const (
	checkInTokenHashConfig       = "checkin_token_hash"
	checkInTokenCiphertextConfig = "checkin_token_ciphertext"
	viewerMessageConfig          = "viewer_message"
)

func hashCheckInToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

// SetCheckInToken stores a hash for validation and an encrypted copy for the
// authenticated settings page, where the private URL can be displayed again.
func (db *DB) SetCheckInToken(token string) error {
	if strings.TrimSpace(token) == "" {
		return fmt.Errorf("check-in token must not be empty")
	}
	ciphertext, err := encrypt(token, db.key)
	if err != nil {
		return err
	}
	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for key, value := range map[string]string{
		checkInTokenHashConfig:       hashCheckInToken(token),
		checkInTokenCiphertextConfig: ciphertext,
	} {
		if _, err := tx.Exec("INSERT INTO config (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", key, value); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// GetCheckInToken returns the token for authenticated settings pages only.
func (db *DB) GetCheckInToken() (string, error) {
	ciphertext, err := db.GetConfig(checkInTokenCiphertextConfig)
	if err != nil || ciphertext == "" {
		return "", err
	}
	return decrypt(ciphertext, db.key)
}

func (db *DB) ValidateCheckInToken(token string) (bool, error) {
	expected, err := db.GetConfig(checkInTokenHashConfig)
	if err != nil {
		return false, err
	}
	if expected == "" {
		return false, nil
	}
	actual, err := hex.DecodeString(expected)
	if err != nil {
		return false, fmt.Errorf("invalid stored check-in token hash: %w", err)
	}
	digest := sha256.Sum256([]byte(token))
	return len(actual) == len(digest) && subtle.ConstantTimeCompare(actual, digest[:]) == 1, nil
}

func (db *DB) ClearCheckInToken() error {
	_, err := db.conn.Exec("DELETE FROM config WHERE key IN (?, ?)", checkInTokenHashConfig, checkInTokenCiphertextConfig)
	return err
}

// Viewer message helpers. The message is encrypted at rest because it may
// contain personal or otherwise sensitive information.
func (db *DB) GetViewerMessage() (string, error) {
	ciphertext, err := db.GetConfig(viewerMessageConfig)
	if err != nil || ciphertext == "" {
		return "", err
	}
	return decrypt(ciphertext, db.key)
}

func (db *DB) SetViewerMessage(message string) error {
	ciphertext, err := encrypt(message, db.key)
	if err != nil {
		return err
	}
	return db.SetConfig(viewerMessageConfig, ciphertext)
}

// CreateViewerLink stores a non-expiring link issued by the overdue trigger.
func (db *DB) CreateViewerLink(recipientID int64, token string) error {
	return db.CreateViewerLinkWithExpiry(recipientID, token, time.Time{}, false)
}

// CreateViewerLinkWithExpiry stores a viewer link that optionally expires.
// A zero expiry means the link stays valid until the next check-in. Test
// links use isTest so the administrator can identify and revoke them.
func (db *DB) CreateViewerLinkWithExpiry(recipientID int64, token string, expiresAt time.Time, isTest bool) error {
	if strings.TrimSpace(token) == "" {
		return fmt.Errorf("viewer token must not be empty")
	}
	// Expiry is stored as a Unix timestamp so SQLite can compare it directly.
	var expires any
	if !expiresAt.IsZero() {
		expires = expiresAt.Unix()
	}
	_, err := db.conn.Exec(
		"INSERT INTO viewer_links (recipient_id, token_hash, expires_at, is_test) VALUES (?, ?, ?, ?)",
		recipientID, hashCheckInToken(token), expires, isTest)
	return err
}

func (db *DB) ValidateViewerToken(token string) (bool, error) {
	var found int
	err := db.conn.QueryRow(
		"SELECT 1 FROM viewer_links WHERE token_hash = ? AND (expires_at IS NULL OR expires_at > ?)",
		hashCheckInToken(token), time.Now().Unix()).Scan(&found)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return err == nil && found == 1, err
}

// DeleteExpiredViewerLinks removes test links whose validity has ended.
func (db *DB) DeleteExpiredViewerLinks() error {
	_, err := db.conn.Exec("DELETE FROM viewer_links WHERE expires_at IS NOT NULL AND expires_at <= ?", time.Now().Unix())
	return err
}

// DeleteTestViewerLinks removes every link issued by the email test feature.
func (db *DB) DeleteTestViewerLinks() error {
	_, err := db.conn.Exec("DELETE FROM viewer_links WHERE is_test = 1")
	return err
}

func (db *DB) ClearViewerLinks() error {
	_, err := db.conn.Exec("DELETE FROM viewer_links")
	return err
}

// MaxViewerLinkID returns the highest viewer link row id, used to identify
// the links created by a single trigger attempt.
func (db *DB) MaxViewerLinkID() (int64, error) {
	var id int64
	err := db.conn.QueryRow("SELECT COALESCE(MAX(id), 0) FROM viewer_links").Scan(&id)
	return id, err
}

// DeleteViewerLinksUpTo removes non-test viewer links created up to and
// including maxID. It is used to prune links left over from earlier failed
// trigger attempts once a complete generation has been delivered, without
// invalidating the links that were just sent.
func (db *DB) DeleteViewerLinksUpTo(maxID int64) error {
	_, err := db.conn.Exec("DELETE FROM viewer_links WHERE id <= ? AND is_test = 0", maxID)
	return err
}

// User helpers.
func (db *DB) CreateUser(passwordHash string) error {
	_, err := db.conn.Exec("INSERT INTO users (id, password_hash) VALUES (1, ?)", passwordHash)
	return err
}

func (db *DB) GetUser() (*User, error) {
	row := db.conn.QueryRow(`
		SELECT id, password_hash, session_token, session_expires_at,
		       check_in_interval_hours, last_check_in_at, is_triggered, email_enabled
		FROM users WHERE id = 1`)
	u := &User{}
	var sessionToken sql.NullString
	var sessionExpires sql.NullTime
	var lastCheckIn sql.NullTime
	var isTriggered, emailEnabled int
	err := row.Scan(&u.ID, &u.PasswordHash, &sessionToken, &sessionExpires,
		&u.CheckInIntervalHours, &lastCheckIn, &isTriggered, &emailEnabled)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if sessionToken.Valid {
		u.SessionToken = &sessionToken.String
	}
	if sessionExpires.Valid {
		u.SessionExpiresAt = &sessionExpires.Time
	}
	if lastCheckIn.Valid {
		u.LastCheckInAt = &lastCheckIn.Time
	}
	u.IsTriggered = isTriggered != 0
	u.EmailEnabled = emailEnabled != 0
	return u, nil
}

func (db *DB) UpdateUserSession(token string, expires time.Time) error {
	_, err := db.conn.Exec("UPDATE users SET session_token = ?, session_expires_at = ? WHERE id = 1", token, expires)
	return err
}

func (db *DB) ClearSession() error {
	_, err := db.conn.Exec("UPDATE users SET session_token = NULL, session_expires_at = NULL WHERE id = 1")
	return err
}

func (db *DB) UpdateUserPassword(passwordHash string) error {
	_, err := db.conn.Exec("UPDATE users SET password_hash = ? WHERE id = 1", passwordHash)
	return err
}

func (db *DB) UpdateCheckIn(intervalHours int, t time.Time) error {
	_, err := db.conn.Exec("UPDATE users SET check_in_interval_hours = ?, last_check_in_at = ?, is_triggered = 0 WHERE id = 1",
		intervalHours, t)
	return err
}

func (db *DB) MarkTriggered() error {
	_, err := db.conn.Exec("UPDATE users SET is_triggered = 1 WHERE id = 1")
	return err
}

func (db *DB) SetEmailEnabled(enabled bool) error {
	v := 0
	if enabled {
		v = 1
	}
	_, err := db.conn.Exec("UPDATE users SET email_enabled = ? WHERE id = 1", v)
	return err
}

// SMTP helpers.
func (db *DB) GetSMTPSettings() (*SMTPSettings, error) {
	row := db.conn.QueryRow("SELECT id, host, port, username, password, from_address, use_tls FROM smtp_settings WHERE id = 1")
	s := &SMTPSettings{}
	var useTLS int
	err := row.Scan(&s.ID, &s.Host, &s.Port, &s.Username, &s.Password, &s.FromAddress, &useTLS)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	s.UseTLS = useTLS != 0
	return s, err
}

func (db *DB) SaveSMTPSettings(s *SMTPSettings) error {
	useTLS := 0
	if s.UseTLS {
		useTLS = 1
	}
	_, err := db.conn.Exec(`
		INSERT INTO smtp_settings (id, host, port, username, password, from_address, use_tls)
		VALUES (1, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			host = excluded.host,
			port = excluded.port,
			username = excluded.username,
			password = excluded.password,
			from_address = excluded.from_address,
			use_tls = excluded.use_tls`,
		s.Host, s.Port, s.Username, s.Password, s.FromAddress, useTLS)
	return err
}

// Recipient helpers.
func (db *DB) ListRecipients() ([]Recipient, error) {
	rows, err := db.conn.Query("SELECT id, email, name, sort_order FROM recipients ORDER BY sort_order, id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []Recipient
	for rows.Next() {
		r := Recipient{}
		if err := rows.Scan(&r.ID, &r.Email, &r.Name, &r.SortOrder); err != nil {
			return nil, err
		}
		list = append(list, r)
	}
	return list, rows.Err()
}

func (db *DB) GetRecipient(id int64) (*Recipient, error) {
	r := &Recipient{}
	err := db.conn.QueryRow("SELECT id, email, name, sort_order FROM recipients WHERE id = ?", id).Scan(&r.ID, &r.Email, &r.Name, &r.SortOrder)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return r, err
}

func (db *DB) CreateRecipient(email, name string) error {
	_, err := db.conn.Exec("INSERT INTO recipients (email, name, sort_order) VALUES (?, ?, COALESCE((SELECT MAX(sort_order)+1 FROM recipients), 0))", email, name)
	return err
}

func (db *DB) UpdateRecipient(id int64, email, name string) error {
	_, err := db.conn.Exec("UPDATE recipients SET email = ?, name = ? WHERE id = ?", email, name, id)
	return err
}

func (db *DB) UpdateRecipientSortOrder(id int64, sortOrder int) error {
	_, err := db.conn.Exec("UPDATE recipients SET sort_order = ? WHERE id = ?", sortOrder, id)
	return err
}

func (db *DB) DeleteRecipient(id int64) error {
	// Delete the viewer links explicitly as well as relying on ON DELETE
	// CASCADE. The cascade only runs when foreign key enforcement is on, and
	// an orphaned link would keep a deleted recipient's viewer URL alive.
	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec("DELETE FROM viewer_links WHERE recipient_id = ?", id); err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM recipients WHERE id = ?", id); err != nil {
		return err
	}
	return tx.Commit()
}

// Secret helpers (encrypted at rest).
func (db *DB) ListSecrets() ([]Secret, error) {
	return db.ListSecretsByCategory("financial")
}

func (db *DB) ListSecretsByCategory(category string) ([]Secret, error) {
	rows, err := db.conn.Query("SELECT id, category, title, content, created_at, updated_at, sort_order FROM secrets WHERE category = ? ORDER BY sort_order, id", category)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []Secret
	for rows.Next() {
		s := Secret{}
		var ct string
		if err := rows.Scan(&s.ID, &s.Category, &s.Title, &ct, &s.CreatedAt, &s.UpdatedAt, &s.SortOrder); err != nil {
			return nil, err
		}
		pt, err := decrypt(ct, db.key)
		if err != nil {
			log.Printf("failed to decrypt secret %d: %v", s.ID, err)
			pt = "[復号できません]"
		}
		s.Content = pt
		list = append(list, s)
	}
	return list, rows.Err()
}

func (db *DB) GetSecret(id int64) (*Secret, error) {
	return db.GetSecretByCategory(id, "financial")
}

func (db *DB) GetSecretByCategory(id int64, category string) (*Secret, error) {
	s := &Secret{}
	var ct string
	err := db.conn.QueryRow("SELECT id, category, title, content, created_at, updated_at, sort_order FROM secrets WHERE id = ? AND category = ?", id, category).Scan(&s.ID, &s.Category, &s.Title, &ct, &s.CreatedAt, &s.UpdatedAt, &s.SortOrder)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	pt, err := decrypt(ct, db.key)
	if err != nil {
		return nil, fmt.Errorf("decrypt secret: %w", err)
	}
	s.Content = pt
	return s, nil
}

func (db *DB) CreateSecret(title, content string) (int64, error) {
	return db.CreateSecretInCategory("financial", title, content)
}

func (db *DB) CreateSecretInCategory(category, title, content string) (int64, error) {
	ct, err := encrypt(content, db.key)
	if err != nil {
		return 0, err
	}
	res, err := db.conn.Exec("INSERT INTO secrets (category, title, content, sort_order) VALUES (?, ?, ?, COALESCE((SELECT MAX(sort_order)+1 FROM secrets WHERE category = ?), 0))", category, title, ct, category)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	return id, nil
}

func (db *DB) UpdateSecret(id int64, title, content string) error {
	return db.UpdateSecretInCategory(id, "financial", title, content)
}

func (db *DB) UpdateSecretInCategory(id int64, category, title, content string) error {
	ct, err := encrypt(content, db.key)
	if err != nil {
		return err
	}
	_, err = db.conn.Exec("UPDATE secrets SET title = ?, content = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND category = ?", title, ct, id, category)
	return err
}

func (db *DB) UpdateSecretSortOrder(id int64, sortOrder int) error {
	_, err := db.conn.Exec("UPDATE secrets SET sort_order = ? WHERE id = ?", sortOrder, id)
	return err
}

func (db *DB) UpdateSecretSortOrderInCategory(id int64, category string, sortOrder int) error {
	_, err := db.conn.Exec("UPDATE secrets SET sort_order = ? WHERE id = ? AND category = ?", sortOrder, id, category)
	return err
}

func (db *DB) DeleteSecret(id int64) error {
	_, err := db.conn.Exec("DELETE FROM secrets WHERE id = ?", id)
	return err
}

func (db *DB) DeleteSecretInCategory(id int64, category string) error {
	_, err := db.conn.Exec("DELETE FROM secrets WHERE id = ? AND category = ?", id, category)
	return err
}

// GetSecretAnyCategory returns the secret regardless of its category.
func (db *DB) GetSecretAnyCategory(id int64) (*Secret, error) {
	for _, c := range []string{"financial", "insurance", "subscription"} {
		s, err := db.GetSecretByCategory(id, c)
		if err != nil {
			return nil, err
		}
		if s != nil {
			return s, nil
		}
	}
	return nil, nil
}

// Document helpers (encrypted at rest).
func (db *DB) ListDocuments() ([]Document, error) {
	rows, err := db.conn.Query("SELECT id, title, content, created_at, updated_at, sort_order FROM documents ORDER BY sort_order, id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []Document
	for rows.Next() {
		d := Document{}
		var ct string
		if err := rows.Scan(&d.ID, &d.Title, &ct, &d.CreatedAt, &d.UpdatedAt, &d.SortOrder); err != nil {
			return nil, err
		}
		pt, err := decrypt(ct, db.key)
		if err != nil {
			log.Printf("failed to decrypt document %d: %v", d.ID, err)
			pt = "[復号できません]"
		}
		d.Content = pt
		list = append(list, d)
	}
	return list, rows.Err()
}

func (db *DB) GetDocument(id int64) (*Document, error) {
	d := &Document{}
	var ct string
	err := db.conn.QueryRow("SELECT id, title, content, created_at, updated_at, sort_order FROM documents WHERE id = ?", id).Scan(&d.ID, &d.Title, &ct, &d.CreatedAt, &d.UpdatedAt, &d.SortOrder)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	pt, err := decrypt(ct, db.key)
	if err != nil {
		return nil, fmt.Errorf("decrypt document: %w", err)
	}
	d.Content = pt
	return d, nil
}

func (db *DB) CreateDocument(title, content string) error {
	ct, err := encrypt(content, db.key)
	if err != nil {
		return err
	}
	_, err = db.conn.Exec("INSERT INTO documents (title, content, sort_order) VALUES (?, ?, COALESCE((SELECT MAX(sort_order)+1 FROM documents), 0))", title, ct)
	return err
}

func (db *DB) UpdateDocument(id int64, title, content string) error {
	ct, err := encrypt(content, db.key)
	if err != nil {
		return err
	}
	_, err = db.conn.Exec("UPDATE documents SET title = ?, content = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", title, ct, id)
	return err
}

func (db *DB) UpdateDocumentSortOrder(id int64, sortOrder int) error {
	_, err := db.conn.Exec("UPDATE documents SET sort_order = ? WHERE id = ?", sortOrder, id)
	return err
}

func (db *DB) DeleteDocument(id int64) error {
	_, err := db.conn.Exec("DELETE FROM documents WHERE id = ?", id)
	return err
}
