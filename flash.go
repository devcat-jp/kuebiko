package main

import (
	"encoding/base64"
	"net/http"
)

const flashCookieName = "app_flash"
const flashTypeCookieName = "app_flash_type"

func encodeCookieValue(s string) string {
	return base64.URLEncoding.EncodeToString([]byte(s))
}

func decodeCookieValue(s string) string {
	b, err := base64.URLEncoding.DecodeString(s)
	if err != nil {
		return ""
	}
	return string(b)
}

func flashCookie(name, value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   cookieSecure,
	}
}

func setFlash(w http.ResponseWriter, message, typ string) {
	http.SetCookie(w, flashCookie(flashCookieName, encodeCookieValue(message), 60))
	http.SetCookie(w, flashCookie(flashTypeCookieName, encodeCookieValue(typ), 60))
}

func getFlash(w http.ResponseWriter, r *http.Request) (string, string) {
	msg := ""
	typ := ""
	if c, err := r.Cookie(flashCookieName); err == nil {
		msg = decodeCookieValue(c.Value)
		http.SetCookie(w, flashCookie(flashCookieName, "", -1))
	}
	if c, err := r.Cookie(flashTypeCookieName); err == nil {
		typ = decodeCookieValue(c.Value)
		http.SetCookie(w, flashCookie(flashTypeCookieName, "", -1))
	}
	return msg, typ
}
