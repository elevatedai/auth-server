package config

import (
	"os"
	"strings"
)

type Config struct {
	GoogleClientID     string
	GoogleClientSecret string
	GithubClientID     string
	GithubClientSecret string
	Domain             string
	Port               string
	SecretKey          string
}

func LoadConfig() *Config {
	return &Config{
		GoogleClientID:     getEnv("GOOGLE_CLIENT_ID", ""),
		GoogleClientSecret: getEnv("GOOGLE_CLIENT_SECRET", ""),
		GithubClientID:     getEnv("GITHUB_CLIENT_ID", ""),
		GithubClientSecret: getEnv("GITHUB_CLIENT_SECRET", ""),
		Domain:             getEnv("DOMAIN", "localhost:8080"),
		Port:               getEnv("PORT", "8080"),
		SecretKey:          getEnv("SECRET_KEY", ""),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func GetCookieDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) >= 2 {
		return "." + strings.Join(parts[len(parts)-2:], ".")
	}
	return domain
}
