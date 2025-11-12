package auth

type User struct {
	ID       string `json:"id"`
	Email    string `json:"email"`
	Name     string `json:"name"`
	Provider string `json:"provider"`
	Avatar   string `json:"avatar"`
}

type Claims struct {
	UserID       string `json:"user_id"`
	Email        string `json:"email"`
	Name         string `json:"name"`
	Provider     string `json:"provider"`
	Avatar       string `json:"avatar"`
	RefreshToken string `json:"refresh_token"`
}
