package service

import (
	"app/internal/auth/repository"
	"app/internal/config"
	customerrors "app/internal/customErrors"
	"context"
	"regexp"
	"strings"

	"github.com/google/uuid"
)

type AuthService interface {
	Register(username, email, password, role string) (uuid.UUID, error)
	Login(username, password string) (string, string, error)
	Refresh(refreshToken string) (string, error)
	Validate(accessToken string) (*config.Claims, error)
	HealthCheck(ctx context.Context) error
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

	claims, err := s.Validate(refreshToken)
	if err != nil {
		return "", err
	}

	accessToken, _, err := s.jwt.GenerateJWT(claims.Username, claims.Email, claims.Role, uuid.MustParse(claims.Subject))
	if err != nil {
		return "", err
	}

	return accessToken, nil
}

func (s *AuthServiceImpl) Validate(accessToken string) (*config.Claims, error) {
	if accessToken == "" {
		return nil, customerrors.ErrBadRequest
	}

	claims, err := s.jwt.ValidateJWT(accessToken)
	if err != nil {
		return nil, err
	}

	return claims, nil
}

func (s *AuthServiceImpl) HealthCheck(ctx context.Context) error {
	return s.repo.Healtz(ctx)
}

func isValidEmail(email string) bool {
	return regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`).MatchString(email)
}

func isValidPassword(password string) bool {
	return len(password) >= 8 &&
		strings.ContainsAny(password, "0123456789") &&
		strings.ContainsAny(password, "!@#$%^&*()_+")
}
