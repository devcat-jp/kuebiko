package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net/smtp"
	"strings"
	"time"

	"github.com/jordan-wright/email"
)

// sendTriggerEmail sends the payload to all recipients.
func (app *App) sendTriggerEmail(recipients []Recipient, financial, insurance, subscriptions []Secret, documents []Document) error {
	settings, err := app.db.GetSMTPSettings()
	if err != nil {
		return fmt.Errorf("get smtp settings: %w", err)
	}
	if settings == nil {
		return fmt.Errorf("SMTP 設定がありません")
	}

	e := email.NewEmail()
	e.From = settings.FromAddress
	for _, r := range recipients {
		e.To = append(e.To, r.Email)
	}
	e.Subject = fmt.Sprintf("【%s作動】重要な情報のご連絡", applicationName)

	var body bytes.Buffer
	body.WriteString(fmt.Sprintf("このメールは、%sが作動したため自動送信されています。\n\n", applicationName))
	body.WriteString("送信者が設定した期限までに生存確認が行われなかったため、登録されていた情報をお送りします。\n\n")
	body.WriteString("==================================================\n")
	body.WriteString("【金融情報 / シークレット】\n")
	body.WriteString("==================================================\n\n")
	if len(financial) == 0 {
		body.WriteString("登録されているシークレットはありません。\n\n")
	} else {
		for _, s := range financial {
			body.WriteString(fmt.Sprintf("--- %s ---\n", s.Title))
			payload, err := s.ParseSecretPayload()
			if err != nil {
				body.WriteString(s.Content)
			} else {
				body.WriteString(payload.FormatForEmail())
			}
			body.WriteString("\n\n")
		}
	}
	writeSecretCategory := func(title, empty string, items []Secret) {
		body.WriteString("==================================================\n")
		_, _ = fmt.Fprintln(&body, title)
		body.WriteString("==================================================\n\n")
		if len(items) == 0 {
			_, _ = fmt.Fprintln(&body, empty)
			body.WriteByte('\n')
			return
		}
		for _, s := range items {
			body.WriteString(fmt.Sprintf("--- %s ---\n", s.Title))
			payload, err := s.ParseSecretPayload()
			if err != nil {
				body.WriteString(s.Content)
			} else {
				body.WriteString(payload.FormatForEmail())
			}
			body.WriteString("\n\n")
		}
	}
	writeSecretCategory("【保険情報】", "登録されている保険情報はありません。", insurance)
	writeSecretCategory("【サブスク】", "登録されているサブスクはありません。", subscriptions)

	body.WriteString("==================================================\n")
	body.WriteString("【メモ】\n")
	body.WriteString("==================================================\n\n")
	if len(documents) == 0 {
		body.WriteString("登録されているメモはありません。\n\n")
	} else {
		for _, d := range documents {
			body.WriteString(fmt.Sprintf("--- %s ---\n", d.Title))
			body.WriteString(d.Content)
			body.WriteString("\n\n")
		}
	}

	body.WriteString("\n")
	body.WriteString(fmt.Sprintf("送信日時: %s\n", time.Now().Format(time.RFC3339)))
	body.WriteString("本メールは自動送信されています。\n")

	e.Text = body.Bytes()

	// Attach memos as .md files.
	for _, d := range documents {
		filename := fmt.Sprintf("%s.md", strings.ReplaceAll(d.Title, " ", "_"))
		e.Attach(bytes.NewReader([]byte(d.Content)), filename, "text/markdown; charset=utf-8")
	}

	addr := fmt.Sprintf("%s:%d", settings.Host, settings.Port)
	auth := smtp.PlainAuth("", settings.Username, settings.Password, settings.Host)

	// Port 465 usually requires TLS from the start. Port 587 and others use STARTTLS.
	if settings.UseTLS && settings.Port == 465 {
		return e.SendWithTLS(addr, auth, &tls.Config{ServerName: settings.Host})
	}
	if settings.UseTLS {
		return e.SendWithStartTLS(addr, auth, &tls.Config{ServerName: settings.Host})
	}
	return e.Send(addr, auth)
}
