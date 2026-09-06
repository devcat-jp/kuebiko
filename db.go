package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
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
	conn, err := sql.Open("sqlite", path+"?_journal_mode=WAL&_busy_timeout=5000")
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
	name TEXT
);

CREATE TABLE IF NOT EXISTS secrets (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	title TEXT NOT NULL,
	content TEXT NOT NULL,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS documents (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	title TEXT NOT NULL,
	content TEXT NOT NULL,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`
	if _, err := db.conn.Exec(schema); err != nil {
		return err
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
	rows, err := db.conn.Query("SELECT id, email, name FROM recipients ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []Recipient
	for rows.Next() {
		r := Recipient{}
		if err := rows.Scan(&r.ID, &r.Email, &r.Name); err != nil {
			return nil, err
		}
		list = append(list, r)
	}
	return list, rows.Err()
}

func (db *DB) GetRecipient(id int64) (*Recipient, error) {
	r := &Recipient{}
	err := db.conn.QueryRow("SELECT id, email, name FROM recipients WHERE id = ?", id).Scan(&r.ID, &r.Email, &r.Name)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return r, err
}

func (db *DB) CreateRecipient(email, name string) error {
	_, err := db.conn.Exec("INSERT INTO recipients (email, name) VALUES (?, ?)", email, name)
	return err
}

func (db *DB) UpdateRecipient(id int64, email, name string) error {
	_, err := db.conn.Exec("UPDATE recipients SET email = ?, name = ? WHERE id = ?", email, name, id)
	return err
}

func (db *DB) DeleteRecipient(id int64) error {
	_, err := db.conn.Exec("DELETE FROM recipients WHERE id = ?", id)
	return err
}

// Secret helpers (encrypted at rest).
func (db *DB) ListSecrets() ([]Secret, error) {
	rows, err := db.conn.Query("SELECT id, title, content, created_at, updated_at FROM secrets ORDER BY updated_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []Secret
	for rows.Next() {
		s := Secret{}
		var ct string
		if err := rows.Scan(&s.ID, &s.Title, &ct, &s.CreatedAt, &s.UpdatedAt); err != nil {
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
	s := &Secret{}
	var ct string
	err := db.conn.QueryRow("SELECT id, title, content, created_at, updated_at FROM secrets WHERE id = ?", id).Scan(&s.ID, &s.Title, &ct, &s.CreatedAt, &s.UpdatedAt)
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

func (db *DB) CreateSecret(title, content string) error {
	ct, err := encrypt(content, db.key)
	if err != nil {
		return err
	}
	_, err = db.conn.Exec("INSERT INTO secrets (title, content) VALUES (?, ?)", title, ct)
	return err
}

func (db *DB) UpdateSecret(id int64, title, content string) error {
	ct, err := encrypt(content, db.key)
	if err != nil {
		return err
	}
	_, err = db.conn.Exec("UPDATE secrets SET title = ?, content = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", title, ct, id)
	return err
}

func (db *DB) DeleteSecret(id int64) error {
	_, err := db.conn.Exec("DELETE FROM secrets WHERE id = ?", id)
	return err
}

// Document helpers (encrypted at rest).
func (db *DB) ListDocuments() ([]Document, error) {
	rows, err := db.conn.Query("SELECT id, title, content, created_at, updated_at FROM documents ORDER BY updated_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []Document
	for rows.Next() {
		d := Document{}
		var ct string
		if err := rows.Scan(&d.ID, &d.Title, &ct, &d.CreatedAt, &d.UpdatedAt); err != nil {
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
	err := db.conn.QueryRow("SELECT id, title, content, created_at, updated_at FROM documents WHERE id = ?", id).Scan(&d.ID, &d.Title, &ct, &d.CreatedAt, &d.UpdatedAt)
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
	_, err = db.conn.Exec("INSERT INTO documents (title, content) VALUES (?, ?)", title, ct)
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

func (db *DB) DeleteDocument(id int64) error {
	_, err := db.conn.Exec("DELETE FROM documents WHERE id = ?", id)
	return err
}
