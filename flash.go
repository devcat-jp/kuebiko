package main

import (
	"encoding/base64"
	"net/http"
)

const flashCookieName = "app_flash"
const flashTypeCookieName = "app_flash_type"

// Flash values are also mirrored into response headers so a handler that calls
// setFlash() and then renders a page in the same response (inline validation
// errors) shows the message immediately. Cookies alone are only visible on the
// next request.
const flashHeaderName = "X-App-Flash"
const flashHeaderType = "X-App-Flash-Type"

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
	w.Header().Set(flashHeaderName, encodeCookieValue(message))
	w.Header().Set(flashHeaderType, encodeCookieValue(typ))
	http.SetCookie(w, flashCookie(flashCookieName, encodeCookieValue(message), 60))
	http.SetCookie(w, flashCookie(flashTypeCookieName, encodeCookieValue(typ), 60))
}

func getFlash(w http.ResponseWriter, r *http.Request) (string, string) {
	// A flash set earlier in this same response takes precedence and must not
	// leak into the next request, so drop the cookies set alongside it.
	if v := w.Header().Get(flashHeaderName); v != "" {
		msg := decodeCookieValue(v)
		typ := decodeCookieValue(w.Header().Get(flashHeaderType))
		w.Header().Del(flashHeaderName)
		w.Header().Del(flashHeaderType)
		http.SetCookie(w, flashCookie(flashCookieName, "", -1))
		http.SetCookie(w, flashCookie(flashTypeCookieName, "", -1))
		return msg, typ
	}
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
