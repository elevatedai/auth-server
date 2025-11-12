package oauth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"auth/pkg/config"
	"auth/pkg/jwt"
	"auth/pkg/types"

	"golang.org/x/oauth2"
)

func HandleGoogleLogin(w http.ResponseWriter, r *http.Request, oauthConfig *oauth2.Config, appConfig *config.Config) {
	state := generateRandomString(32)
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
		MaxAge:   600,
	})

	redirect := r.URL.Query().Get("redirect")
	http.SetCookie(w, &http.Cookie{
		Name:     "redirect_url",
		Value:    redirect,
		HttpOnly: true,
		Secure:   true,
		Domain:   config.GetCookieDomain(appConfig.Domain),
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
		MaxAge:   600,
	})

	url := oauthConfig.AuthCodeURL(state, oauth2.AccessTypeOnline)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func HandleGoogleCallback(w http.ResponseWriter, r *http.Request, oauthConfig *oauth2.Config, appConfig *config.Config) {
	if r.URL.Query().Get("state") != getCookieValue(r, "oauth_state") {
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	token, err := oauthConfig.Exchange(r.Context(), code)
	if err != nil {
		http.Redirect(w, r, "/login?error=oauth_exchange_failed", http.StatusSeeOther)
		return
	}

	client := oauthConfig.Client(r.Context(), token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		http.Redirect(w, r, "/login?error=user_info_failed", http.StatusSeeOther)
		return
	}
	defer resp.Body.Close()

	var userInfo struct {
		ID      string `json:"id"`
		Email   string `json:"email"`
		Name    string `json:"name"`
		Picture string `json:"picture"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		http.Redirect(w, r, "/login?error=parse_failed", http.StatusSeeOther)
		return
	}

	user := &types.User{
		ID:       userInfo.ID,
		Email:    userInfo.Email,
		Name:     userInfo.Name,
		Provider: "google",
		Avatar:   userInfo.Picture,
	}

	tokenString, err := jwt.GenerateJWT(user, token.RefreshToken, appConfig.SecretKey)
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

	redirect := getCookieValue(r, "redirect_url")
	if redirect == "" {
		redirect = "/user"
	}
	http.SetCookie(w, &http.Cookie{
		Name:   "redirect_url",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	http.Redirect(w, r, redirect, http.StatusSeeOther)
}

func HandleGitHubLogin(w http.ResponseWriter, r *http.Request, oauthConfig *oauth2.Config, appConfig *config.Config) {
	state := generateRandomString(32)
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
		MaxAge:   600,
	})

	redirect := r.URL.Query().Get("redirect")
	http.SetCookie(w, &http.Cookie{
		Name:     "redirect_url",
		Value:    redirect,
		HttpOnly: true,
		Secure:   true,
		Domain:   config.GetCookieDomain(appConfig.Domain),
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
		MaxAge:   600,
	})

	url := oauthConfig.AuthCodeURL(state, oauth2.AccessTypeOnline)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func HandleGitHubCallback(w http.ResponseWriter, r *http.Request, oauthConfig *oauth2.Config, appConfig *config.Config) {
	if r.URL.Query().Get("state") != getCookieValue(r, "oauth_state") {
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	token, err := oauthConfig.Exchange(r.Context(), code)
	if err != nil {
		http.Redirect(w, r, "/login?error=oauth_exchange_failed", http.StatusSeeOther)
		return
	}

	client := oauthConfig.Client(r.Context(), token)

	// Get user info
	userResp, err := client.Get("https://api.github.com/user")
	if err != nil {
		http.Redirect(w, r, "/login?error=user_info_failed", http.StatusSeeOther)
		return
	}
	defer userResp.Body.Close()

	var userInfo struct {
		ID        int    `json:"id"`
		Email     string `json:"email"`
		Name      string `json:"name"`
		Login     string `json:"login"`
		AvatarURL string `json:"avatar_url"`
	}

	if err := json.NewDecoder(userResp.Body).Decode(&userInfo); err != nil {
		http.Redirect(w, r, "/login?error=parse_failed", http.StatusSeeOther)
		return
	}

	// Get email if not provided
	if userInfo.Email == "" {
		emailResp, err := client.Get("https://api.github.com/user/emails")
		if err == nil {
			defer emailResp.Body.Close()
			var emails []struct {
				Email   string `json:"email"`
				Primary bool   `json:"primary"`
			}
			if err := json.NewDecoder(emailResp.Body).Decode(&emails); err == nil {
				for _, email := range emails {
					if email.Primary {
						userInfo.Email = email.Email
						break
					}
				}
			}
		}
	}

	user := &types.User{
		ID:       fmt.Sprintf("%d", userInfo.ID),
		Email:    userInfo.Email,
		Name:     userInfo.Name,
		Provider: "github",
		Avatar:   userInfo.AvatarURL,
	}

	tokenString, err := jwt.GenerateJWT(user, token.RefreshToken, appConfig.SecretKey)
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

	redirect := getCookieValue(r, "redirect_url")
	if redirect == "" {
		redirect = "/user"
	}
	http.SetCookie(w, &http.Cookie{
		Name:   "redirect_url",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	http.Redirect(w, r, redirect, http.StatusSeeOther)
}

func getCookieValue(r *http.Request, name string) string {
	cookie, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return cookie.Value
}

func generateRandomString(length int) string {
	b := make([]byte, length)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}
