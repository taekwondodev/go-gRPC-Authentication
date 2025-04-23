package service

import (
	"app/internal/auth/repository"
	"app/internal/config"
	customerrors "app/internal/customErrors"
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

type AuthService interface {
	Register(username, email, password, role string) (uuid.UUID, error)
	Login(username, password string) (string, string, error)
	Refresh(refreshToken string) (string, error)
	HealthCheck() (string, error)
}

type AuthServiceImpl struct {
	repo repository.UserRepository
	jwt  config.Token
}

func NewAuthService(repo repository.UserRepository, jwt config.Token) AuthService {
	return &AuthServiceImpl{repo: repo, jwt: jwt}
}

func (s *AuthServiceImpl) Register(username, email, password, role string) (uuid.UUID, error) {
	if isValidEmail(email) {
		return uuid.Nil, customerrors.ErrInvalidEmail
	}

	if isValidPassword(password) {
		return uuid.Nil, customerrors.ErrInvalidPassword
	}

	if err := s.repo.CheckUserExists(username, email); err != nil {
		return uuid.Nil, err
	}

	sub, err := s.repo.SaveUser(username, password, email, role)
	if err != nil {
		return uuid.Nil, err
	}

	return sub, nil
}

func (s *AuthServiceImpl) Login(username, password string) (string, string, error) {
	if username == "" || password == "" {
		return "", "", customerrors.ErrBadRequest
	}

	user, err := s.repo.GetUserByCredentials(username, password)
	if err != nil {
		return "", "", err
	}

	accessToken, refreshToken, err := s.jwt.GenerateJWT(user.Username, user.Email, user.Role, user.Sub)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

func (s *AuthServiceImpl) Refresh(refreshToken string) (string, error) {
	if refreshToken == "" {
		return "", customerrors.ErrBadRequest
	}

	claims, err := s.jwt.ValidateJWT(refreshToken)
	if err != nil {
		return "", err
	}

	accessToken, _, err := s.jwt.GenerateJWT(claims.Username, claims.Email, claims.Role, uuid.MustParse(claims.Subject))
	if err != nil {
		return "", err
	}

	return accessToken, nil
}

func (s *AuthServiceImpl) HealthCheck() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := config.Db.PingContext(ctx); err != nil {
		switch {
		case isSSLerror(err):
			return "", customerrors.ErrDbSSLHandshakeFailed
		case ctx.Err() == context.DeadlineExceeded:
			return "", customerrors.ErrDbTimeout
		default:
			return "", customerrors.ErrDbUnreacheable
		}
	}

	return "OK", nil
}

func isValidEmail(email string) bool {
	return regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`).MatchString(email)
}

func isValidPassword(password string) bool {
	return len(password) >= 8 &&
		strings.ContainsAny(password, "0123456789") &&
		strings.ContainsAny(password, "!@#$%^&*()_+")
}

func isSSLerror(err error) bool {
	return strings.Contains(err.Error(), "SSL") ||
		strings.Contains(err.Error(), "certificate") ||
		strings.Contains(err.Error(), "TLS")
}
