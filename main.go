package main

import (
	"embed"
	"fmt"
	"html/template"
	"log"
	"net/http"

	"auth/pkg/auth"
	"auth/pkg/config"
	"auth/pkg/oauth"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
)

//go:embed templates/*
var templatesFS embed.FS

var (
	templates *template.Template
	appConfig *config.Config
)

func main() {
	appConfig = config.LoadConfig()

	// Parse templates
	templates = template.Must(template.ParseFS(templatesFS, "templates/*.html"))
	auth.InitTemplates(templates)

	// OAuth2 configs
	googleOauthConfig := &oauth2.Config{
		RedirectURL:  fmt.Sprintf("https://%s/auth/google/callback", appConfig.Domain),
		ClientID:     appConfig.GoogleClientID,
		ClientSecret: appConfig.GoogleClientSecret,
		Scopes: []string{"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile"},
		Endpoint: google.Endpoint,
	}

	githubOauthConfig := &oauth2.Config{
		RedirectURL:  fmt.Sprintf("https://%s/auth/github/callback", appConfig.Domain),
		ClientID:     appConfig.GithubClientID,
		ClientSecret: appConfig.GithubClientSecret,
		Scopes:       []string{"user:email", "read:user"},
		Endpoint:     github.Endpoint,
	}

	// Routes
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		auth.HomeHandler(w, r)
	})
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		auth.LoginHandler(w, r, appConfig)
	})
	http.HandleFunc("/auth/google", func(w http.ResponseWriter, r *http.Request) {
		oauth.HandleGoogleLogin(w, r, googleOauthConfig, appConfig)
	})
	http.HandleFunc("/auth/google/callback", func(w http.ResponseWriter, r *http.Request) {
		oauth.HandleGoogleCallback(w, r, googleOauthConfig, appConfig)
	})
	http.HandleFunc("/auth/github", func(w http.ResponseWriter, r *http.Request) {
		oauth.HandleGitHubLogin(w, r, githubOauthConfig, appConfig)
	})
	http.HandleFunc("/auth/github/callback", func(w http.ResponseWriter, r *http.Request) {
		oauth.HandleGitHubCallback(w, r, githubOauthConfig, appConfig)
	})
	http.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		auth.LogoutHandler(w, r)
	})
	http.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		auth.UserHandler(w, r, appConfig)
	})
	http.HandleFunc("/auth/validate", func(w http.ResponseWriter, r *http.Request) {
		auth.ValidateHandler(w, r, appConfig)
	})
	http.HandleFunc("/auth/refresh", func(w http.ResponseWriter, r *http.Request) {
		auth.RefreshHandler(w, r, appConfig)
	})
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		auth.HealthHandler(w, r)
	})

	log.Printf("Starting server on :%s", appConfig.Port)
	log.Fatal(http.ListenAndServe(":"+appConfig.Port, nil))
}
