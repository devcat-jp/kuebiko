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

func setFlash(w http.ResponseWriter, message, typ string) {
	http.SetCookie(w, &http.Cookie{
		Name:     flashCookieName,
		Value:    encodeCookieValue(message),
		Path:     "/",
		MaxAge:   60,
		HttpOnly: true,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     flashTypeCookieName,
		Value:    encodeCookieValue(typ),
		Path:     "/",
		MaxAge:   60,
		HttpOnly: true,
	})
}

func getFlash(w http.ResponseWriter, r *http.Request) (string, string) {
	msg := ""
	typ := ""
	if c, err := r.Cookie(flashCookieName); err == nil {
		msg = decodeCookieValue(c.Value)
		http.SetCookie(w, &http.Cookie{
			Name:     flashCookieName,
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
		})
	}
	if c, err := r.Cookie(flashTypeCookieName); err == nil {
		typ = decodeCookieValue(c.Value)
		http.SetCookie(w, &http.Cookie{
			Name:     flashTypeCookieName,
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
		})
	}
	return msg, typ
}
