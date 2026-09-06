package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"strings"
	"time"
)

// User represents the single application user.
type User struct {
	ID                   int64
	Username             string
	PasswordHash         string
	SessionToken         *string
	SessionExpiresAt     *time.Time
	CheckInIntervalHours int
	LastCheckInAt        *time.Time
	IsTriggered          bool
	EmailEnabled         bool
}

// SMTPSettings holds outgoing mail server configuration.
type SMTPSettings struct {
	ID          int64
	Host        string
	Port        int
	Username    string
	Password    string
	FromAddress string
	UseTLS      bool
}

// Recipient receives the kuebiko payload.
type Recipient struct {
	ID    int64
	Email string
	Name  string
}

// Secret stores login credentials or other sensitive information.
type Secret struct {
	ID        int64
	Title     string
	Content   string // encrypted JSON of SecretPayload
	CreatedAt time.Time
	UpdatedAt time.Time
}

// SecretPayload is the structured content of a Secret.
type SecretPayload struct {
	ID       string        `json:"id"`
	URL      string        `json:"url"`
	Password string        `json:"password"`
	Memo     string        `json:"memo"`
	Fields   []SecretField `json:"fields"`
}

// SecretField is a user-defined additional field.
type SecretField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Hidden bool   `json:"hidden"`
}

// ParseSecretPayload parses the JSON content of a Secret.
// If parsing fails, it treats the content as legacy plain text.
func (s *Secret) ParseSecretPayload() (*SecretPayload, error) {
	if s.Content == "" {
		return &SecretPayload{}, nil
	}
	var p SecretPayload
	if err := json.Unmarshal([]byte(s.Content), &p); err != nil {
		// Legacy plain text fallback.
		return &SecretPayload{
			Fields: []SecretField{{Name: "内容", Value: s.Content}},
		}, nil
	}
	return &p, nil
}

// FormatForEmail returns a human-readable string for email body.
func (p *SecretPayload) FormatForEmail() string {
	var b strings.Builder
	if p.URL != "" {
		fmt.Fprintf(&b, "URL: %s\n", p.URL)
	}
	if p.ID != "" {
		fmt.Fprintf(&b, "ID: %s\n", p.ID)
	}
	if p.Password != "" {
		fmt.Fprintf(&b, "Password: %s\n", p.Password)
	}
	for _, f := range p.Fields {
		if f.Name != "" {
			fmt.Fprintf(&b, "%s: %s\n", f.Name, f.Value)
		}
	}
	if p.Memo != "" {
		fmt.Fprintf(&b, "\nMemo:\n%s\n", p.Memo)
	}
	return b.String()
}

// Document stores a markdown document that is delivered on trigger.
type Document struct {
	ID        int64
	Title     string
	Content   string // markdown, encrypted at rest
	CreatedAt time.Time
	UpdatedAt time.Time
}

// AppData is passed to templates.
type AppData struct {
	User          *User
	Flash         string
	FlashType     string
	CheckInURL    string
	SMTPSettings  *SMTPSettings
	AllowedIPs    string
	Recipients    []Recipient
	Secrets       []Secret
	Documents     []Document
	Secret        *Secret
	SecretPayload *SecretPayload
	Document      *Document
	Recipient     *Recipient
	Deadline      *time.Time
	IsOverdue     bool
	TriggerAt     *time.Time
	Title         template.HTML
	Content       template.HTML
}
