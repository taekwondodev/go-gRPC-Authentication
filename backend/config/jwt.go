package config

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}
type Token interface {
	GenerateJWT(username, email, id, role string) (string, string, error)
	ValidateJWT(tokenString string) (*Claims, error)
}

type JWT struct{}

func (j *JWT) GenerateJWT(username, email, id, role string) (string, string, error) {
	// Valid for 24 hours
	accessClaims := Claims{
		Username: username,
		Email:    email,
		Role:     role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 24)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        id,
		},
	}

	// Valid for 7 days
	refreshClaims := Claims{
		Username: username,
		Email:    email,
		Role:     role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 24 * 7)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        id,
		},
	}

	accessToken, err := generateToken(accessClaims)
	if err != nil {
		return "", "", err
	}

	refreshToken, err := generateToken(refreshClaims)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

func (j *JWT) ValidateJWT(tokenString string) (*Claims, error) {
	token, claims, err := parseJWT(tokenString)

	if err != nil || !token.Valid {
		return nil, jwt.ErrSignatureInvalid
	}

	if claims.ExpiresAt != nil && claims.ExpiresAt.Time.Before(time.Now()) {
		return nil, jwt.ErrTokenExpired
	}

	return claims, nil
}

func generateToken(claims Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(JwtSecret)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func parseJWT(tokenString string) (*jwt.Token, *Claims, error) {
	claims := &Claims{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (any, error) {
		return JwtSecret, nil
	})

	return token, claims, err
}
