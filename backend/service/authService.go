package service

import (
	"backend/config"
	customerrors "backend/customErrors"
	"backend/dto"
	"backend/repository"
	"context"
	"fmt"
	"strings"
	"time"
)

type AuthService interface {
	Register(req dto.AuthRequest) (*dto.AuthResponse, error)
	Login(req dto.AuthRequest) (*dto.AuthResponse, error)
	Refresh(req dto.RefreshTokenRequest) (*dto.AuthResponse, error)
	HealthCheck() (*dto.HealthResponse, error)
}

type AuthServiceImpl struct {
	repo repository.UserRepository
	jwt  config.Token
}

func NewAuthService(repo repository.UserRepository, jwt config.Token) AuthService {
	return &AuthServiceImpl{repo: repo, jwt: jwt}
}

func (s *AuthServiceImpl) Register(req dto.AuthRequest) (*dto.AuthResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, customerrors.ErrBadRequest
	}

	if err := s.repo.CheckUserExists(req.Username, req.Email); err != nil {
		return nil, err
	}

	if err := s.repo.SaveUser(req.Username, req.Password, req.Email, req.Role); err != nil {
		return nil, err
	}

	return &dto.AuthResponse{Message: "Sign-Up successfully!"}, nil
}

func (s *AuthServiceImpl) Login(req dto.AuthRequest) (*dto.AuthResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, customerrors.ErrBadRequest
	}

	user, err := s.repo.GetUserByCredentials(req.Username, req.Password)
	if err != nil {
		return nil, err
	}

	accessToken, refreshToken, err := s.jwt.GenerateJWT(user.Username, user.Email, fmt.Sprintf("%d", user.ID), user.Role)
	if err != nil {
		return nil, err
	}

	return &dto.AuthResponse{
		Message:      "Sign-In successfully!",
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (s *AuthServiceImpl) Refresh(req dto.RefreshTokenRequest) (*dto.AuthResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, customerrors.ErrBadRequest
	}

	claims, err := s.jwt.ValidateJWT(req.RefreshToken)
	if err != nil {
		return nil, err
	}

	accessToken, _, err := s.jwt.GenerateJWT(claims.Username, claims.Email, claims.ID, claims.Role)
	if err != nil {
		return nil, err
	}

	return &dto.AuthResponse{
		Message:     "Update token successfully!",
		AccessToken: accessToken,
	}, nil
}

func (s *AuthServiceImpl) HealthCheck() (*dto.HealthResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := config.Db.PingContext(ctx); err != nil {
		switch {
		case isSSLerror(err):
			return nil, customerrors.ErrDbSSLHandshakeFailed
		case ctx.Err() == context.DeadlineExceeded:
			return nil, customerrors.ErrDbTimeout
		default:
			return nil, customerrors.ErrDbUnreacheable
		}
	}

	return &dto.HealthResponse{
		Status:   "OK",
		Database: "Connected",
		SslMode:  "verify-full",
	}, nil
}

func isSSLerror(err error) bool {
	return strings.Contains(err.Error(), "SSL") ||
		strings.Contains(err.Error(), "certificate") ||
		strings.Contains(err.Error(), "TLS")
}
