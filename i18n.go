package main

import (
	"embed"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

//go:embed locales/*.json
var localesFS embed.FS

var translations map[string]map[string]string

const languageCookieName = "app_language"

func isSupportedLanguage(lang string) bool {
	return lang == "ja" || lang == "en"
}

func initTranslations() error {
	translations = make(map[string]map[string]string)
	for _, lang := range []string{"ja", "en"} {
		data, err := localesFS.ReadFile("locales/" + lang + ".json")
		if err != nil {
			return err
		}
		var dictionary map[string]string
		if err := json.Unmarshal(data, &dictionary); err != nil {
			return err
		}
		translations[lang] = dictionary
	}
	return nil
}

func languageFromRequest(r *http.Request) string {
	if lang := r.URL.Query().Get("lang"); isSupportedLanguage(lang) {
		return lang
	}
	if cookie, err := r.Cookie(languageCookieName); err == nil {
		if isSupportedLanguage(cookie.Value) {
			return cookie.Value
		}
	}
	if strings.HasPrefix(strings.ToLower(r.Header.Get("Accept-Language")), "en") {
		return "en"
	}
	return "ja"
}

func setLanguageCookie(w http.ResponseWriter, lang string) {
	if !isSupportedLanguage(lang) {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     languageCookieName,
		Value:    lang,
		Path:     "/",
		MaxAge:   31536000,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   cookieSecure,
	})
}

// languageMiddleware synchronizes a valid query-string selection with the
// cookie before any handler can redirect, and initializes the cookie when
// there is no prior selection.
func languageMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lang := languageFromRequest(r)
		cookie, err := r.Cookie(languageCookieName)
		if err != nil || cookie.Value != lang {
			setLanguageCookie(w, lang)
		}
		next.ServeHTTP(w, r)
	})
}

// languageURL safely encodes the current request URI into the language
// switcher's return query parameter.
func languageURL(lang, returnPath string) string {
	if !isSupportedLanguage(lang) {
		lang = "ja"
	}
	returnPath = safeReturnPath(returnPath)
	values := url.Values{}
	values.Set("lang", lang)
	values.Set("return", returnPath)
	return "/language?" + values.Encode()
}

func translate(lang, key string) string {
	value := ""
	if v := translations[lang][key]; v != "" {
		value = v
	} else if v := translations["ja"][key]; v != "" {
		value = v
	} else {
		return key
	}
	// Locale strings may reference the application name, which is fixed at
	// build time via the applicationName constant.
	return strings.ReplaceAll(value, "{{.AppName}}", applicationName)
}

func (app *App) languageHandler(w http.ResponseWriter, r *http.Request) {
	lang := r.URL.Query().Get("lang")
	if !isSupportedLanguage(lang) {
		lang = "ja"
	}
	setLanguageCookie(w, lang)
	returnTo := safeReturnPath(r.URL.Query().Get("return"))
	http.Redirect(w, r, returnTo, http.StatusSeeOther)
}
