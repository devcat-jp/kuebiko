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

// sendViewerEmail sends only a recipient-specific read-only portal URL.
func (app *App) sendViewerEmail(recipient Recipient, viewerURL string) error {
	return app.sendViewerEmailWithMode(recipient, viewerURL, false, 0)
}

// sendTestViewerEmail sends the same message as the real trigger but marked as
// a test and with a link that expires after validity.
func (app *App) sendTestViewerEmail(recipient Recipient, viewerURL string, validity time.Duration) error {
	return app.sendViewerEmailWithMode(recipient, viewerURL, true, validity)
}

func (app *App) sendViewerEmailWithMode(recipient Recipient, viewerURL string, isTest bool, validity time.Duration) error {
	settings, err := app.db.GetSMTPSettings()
	if err != nil {
		return fmt.Errorf("get smtp settings: %w", err)
	}
	if settings == nil {
		return fmt.Errorf("SMTP 設定がありません")
	}

	e := email.NewEmail()
	e.From = settings.FromAddress
	e.To = []string{recipient.Email}
	var body bytes.Buffer
	if isTest {
		e.Subject = fmt.Sprintf("【%s】メール送信テスト", applicationName)
		body.WriteString(fmt.Sprintf("これは%sのメール送信テストです。実際の作動時と同じ形式で送信しています。\n\n", applicationName))
		body.WriteString("以下の閲覧専用ページから、実際に表示される内容を確認できます。\n\n")
		body.WriteString(viewerURL)
		if validity > 0 {
			body.WriteString(fmt.Sprintf("\n\nこのテスト用URLは約%d分間のみ有効です。\n", int(validity.Minutes())))
		}
	} else {
		e.Subject = fmt.Sprintf("【%s作動】重要なお知らせ", applicationName)
		body.WriteString(fmt.Sprintf("このメールは、%sが作動したため自動送信されています。\n\n", applicationName))
		body.WriteString("以下の閲覧専用ページから、登録情報をご確認ください。\n\n")
		body.WriteString(viewerURL)
	}
	body.WriteString("\n\nこのURLは第三者に共有しないでください。\n")
	e.Text = body.Bytes()

	addr := fmt.Sprintf("%s:%d", settings.Host, settings.Port)
	// A relay without authentication (for example a local MTA) is supported by
	// leaving the username empty, in which case no AUTH is attempted.
	var auth smtp.Auth
	if strings.TrimSpace(settings.Username) != "" {
		auth = smtp.PlainAuth("", settings.Username, settings.Password, settings.Host)
	}
	if settings.UseTLS && settings.Port == 465 {
		return e.SendWithTLS(addr, auth, &tls.Config{ServerName: settings.Host})
	}
	if settings.UseTLS {
		return e.SendWithStartTLS(addr, auth, &tls.Config{ServerName: settings.Host})
	}
	return e.Send(addr, auth)
}
