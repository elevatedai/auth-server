package auth

import (
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"auth/pkg/config"
	"auth/pkg/jwt"
	"auth/pkg/types"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
)

var templates *template.Template

func InitTemplates(tmpl *template.Template) {
	templates = tmpl
}

func HomeHandler(w http.ResponseWriter, r *http.Request) {
	if _, err := getUserFromRequest(r, ""); err == nil { // need secret
		http.Redirect(w, r, "/user", http.StatusSeeOther)
		return
	}

	data := map[string]interface{}{
		"Title":    "Central Auth",
		"Error":    r.URL.Query().Get("error"),
		"Redirect": "/user",
	}

	templates.ExecuteTemplate(w, "login.html", data)
}

func LoginHandler(w http.ResponseWriter, r *http.Request, appConfig *config.Config) {
	redirect := r.URL.Query().Get("redirect")
	if redirect == "" {
		redirect = "/user"
	}

	if !validateRedirectURL(redirect, appConfig.Domain) {
		redirect = "/user"
	}

	data := map[string]interface{}{
		"Title":    "Sign In",
		"Redirect": redirect,
	}

	templates.ExecuteTemplate(w, "login.html", data)
}

func RefreshHandler(w http.ResponseWriter, r *http.Request, appConfig *config.Config) {
	claims, err := jwt.GetClaimsFromRequest(r, appConfig.SecretKey)
	if err != nil {
		http.Redirect(w, r, "/login?error=unauthorized", http.StatusSeeOther)
		return
	}

	refreshToken := claims.RefreshToken
	provider := claims.Provider
	if refreshToken == "" {
		http.Redirect(w, r, "/login?error=no_refresh_token", http.StatusSeeOther)
		return
	}

	// Create OAuth config based on provider
	var oauthConfig *oauth2.Config
	if provider == "google" {
		oauthConfig = &oauth2.Config{
			ClientID:     appConfig.GoogleClientID,
			ClientSecret: appConfig.GoogleClientSecret,
			Endpoint:     google.Endpoint,
		}
	} else if provider == "github" {
		oauthConfig = &oauth2.Config{
			ClientID:     appConfig.GithubClientID,
			ClientSecret: appConfig.GithubClientSecret,
			Endpoint:     github.Endpoint,
		}
	} else {
		http.Redirect(w, r, "/login?error=unknown_provider", http.StatusSeeOther)
		return
	}

	tokenSource := oauthConfig.TokenSource(r.Context(), &oauth2.Token{RefreshToken: refreshToken})
	newToken, err := tokenSource.Token()
	if err != nil {
		http.Redirect(w, r, "/login?error=refresh_failed", http.StatusSeeOther)
		return
	}

	user := &types.User{
		ID:       claims.UserID,
		Email:    claims.Email,
		Name:     claims.Name,
		Provider: claims.Provider,
		Avatar:   claims.Avatar,
	}

	newRefreshToken := newToken.RefreshToken
	if newRefreshToken == "" {
		newRefreshToken = refreshToken
	}

	tokenString, err := jwt.GenerateJWT(user, newRefreshToken, appConfig.SecretKey)
	if err != nil {
		http.Redirect(w, r, "/login?error=token_failed", http.StatusSeeOther)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    tokenString,
		HttpOnly: true,
		Secure:   true,
		Domain:   config.GetCookieDomain(appConfig.Domain),
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
		MaxAge:   86400,
	})

	redirect := r.URL.Query().Get("redirect")
	if redirect == "" {
		redirect = "/user"
	}
	if !validateRedirectURL(redirect, appConfig.Domain) {
		redirect = "/user"
	}
	http.Redirect(w, r, redirect, http.StatusSeeOther)
}

func UserHandler(w http.ResponseWriter, r *http.Request, appConfig *config.Config) {
	user, err := getUserFromRequest(r, appConfig.SecretKey)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

func ValidateHandler(w http.ResponseWriter, r *http.Request, appConfig *config.Config) {
	user, err := getUserFromRequest(r, appConfig.SecretKey)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"valid":    true,
		"user_id":  user.ID,
		"email":    user.Email,
		"name":     user.Name,
		"provider": user.Provider,
		"avatar":   user.Avatar,
	})
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:   "access_token",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func HealthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func getUserFromRequest(r *http.Request, secret string) (*types.User, error) {
	authHeader := r.Header.Get("Authorization")
	var tokenString string
	if strings.HasPrefix(authHeader, "Bearer ") {
		tokenString = strings.TrimPrefix(authHeader, "Bearer ")
	} else {
		cookie, err := r.Cookie("access_token")
		if err != nil {
			return nil, err
		}
		tokenString = cookie.Value
	}

	return jwt.ValidateJWT(tokenString, secret)
}

func validateRedirectURL(redirectURL, domain string) bool {
	u, err := url.Parse(redirectURL)
	if err != nil {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	// Check if host is subdomain of domain
	if !strings.HasSuffix(u.Host, "."+domain) && u.Host != domain {
		return false
	}
	return true
}
