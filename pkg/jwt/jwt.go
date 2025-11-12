package jwt

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"auth/pkg/types"

	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	UserID       string `json:"user_id"`
	Email        string `json:"email"`
	Name         string `json:"name"`
	Provider     string `json:"provider"`
	Avatar       string `json:"avatar"`
	RefreshToken string `json:"refresh_token"`
	jwt.RegisteredClaims
}

func GenerateJWT(user *types.User, refreshToken, secret string) (string, error) {
	claims := &Claims{
		UserID:       user.ID,
		Email:        user.Email,
		Name:         user.Name,
		Provider:     user.Provider,
		Avatar:       user.Avatar,
		RefreshToken: refreshToken,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "central-auth",
			Subject:   user.ID,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

func ValidateJWT(tokenString, secret string) (*types.User, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return &types.User{
			ID:       claims.UserID,
			Email:    claims.Email,
			Name:     claims.Name,
			Provider: claims.Provider,
			Avatar:   claims.Avatar,
		}, nil
	}

	return nil, fmt.Errorf("invalid token")
}

func GetClaimsFromRequest(r *http.Request, secret string) (*Claims, error) {
	authHeader := r.Header.Get("Authorization")
	var tokenString string
	if strings.HasPrefix(authHeader, "Bearer ") {
		tokenString = strings.TrimPrefix(authHeader, "Bearer ")
	} else {
		cookie, err := r.Cookie("access_token")
		if err != nil {
			return nil, fmt.Errorf("no token")
		}
		tokenString = cookie.Value
	}

	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}
