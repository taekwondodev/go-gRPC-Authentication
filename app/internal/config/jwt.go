package config

import (
	"log"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type Claims struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}
type Token interface {
	GenerateJWT(username, email, role string, sub uuid.UUID) (string, string, error)
	ValidateJWT(tokenString string) (*Claims, error)
}

type JWT struct {
	jwtSecret []byte
}

func NewJWT() *JWT {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		log.Fatal("JWT_SECRET not defined")
	}

	return &JWT{
		jwtSecret: []byte(secret),
	}
}

func (j *JWT) GenerateJWT(username, email, role string, sub uuid.UUID) (string, string, error) {
	// Valid for 24 hours
	accessClaims := Claims{
		Username: username,
		Email:    email,
		Role:     role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 24)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   sub.String(),
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
			Subject:   sub.String(),
		},
	}

	accessToken, err := j.generateToken(accessClaims)
	if err != nil {
		return "", "", err
	}

	refreshToken, err := j.generateToken(refreshClaims)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

func (j *JWT) ValidateJWT(tokenString string) (*Claims, error) {
	token, claims, err := j.parseJWT(tokenString)

	if err != nil || !token.Valid {
		return nil, jwt.ErrSignatureInvalid
	}

	if claims.ExpiresAt != nil && claims.ExpiresAt.Time.Before(time.Now()) {
		return nil, jwt.ErrTokenExpired
	}

	return claims, nil
}

func (j *JWT) generateToken(claims Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(j.jwtSecret)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func (j *JWT) parseJWT(tokenString string) (*jwt.Token, *Claims, error) {
	claims := &Claims{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (any, error) {
		return j.jwtSecret, nil
	})

	return token, claims, err
}
