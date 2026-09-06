package main

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const sessionCookieName = "kuebiko_session"

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func checkPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func generateSessionToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// authMiddleware ensures the request has a valid session.
func (app *App) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookieName)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		user, err := app.db.GetUser()
		if err != nil || user == nil || user.SessionToken == nil || *user.SessionToken != cookie.Value {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if user.SessionExpiresAt != nil && user.SessionExpiresAt.Before(time.Now()) {
			_ = app.db.ClearSession()
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

// currentUser returns the currently authenticated user.
func (app *App) currentUser(r *http.Request) (*User, error) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil, nil
	}
	user, err := app.db.GetUser()
	if err != nil || user == nil || user.SessionToken == nil || *user.SessionToken != cookie.Value {
		return nil, nil
	}
	if user.SessionExpiresAt != nil && user.SessionExpiresAt.Before(time.Now()) {
		_ = app.db.ClearSession()
		return nil, nil
	}
	return user, nil
}
