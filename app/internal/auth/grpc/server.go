package grpc

import (
	"context"

	pb "github.com/taekwondodev/go-gRPC-Authentication/gen"

	"github.com/taekwondodev/go-gRPC-Authentication/internal/auth/service"
)

type Server struct {
	pb.UnimplementedAuthServiceServer
	authService service.AuthService
}

func NewServer(authService service.AuthService) *Server {
	return &Server{authService: authService}
}

func (s *Server) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	sub, err := s.authService.Register(req.Username, req.Email, req.Password, req.Role)
	if err != nil {
		return nil, err
	}
	return &pb.RegisterResponse{
		Sub: sub.String(),
	}, nil
}

func (s *Server) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	token, refreshToken, err := s.authService.Login(req.Username, req.Password)
	if err != nil {
		return nil, err
	}
	return &pb.LoginResponse{
		AccessToken:  token,
		RefreshToken: refreshToken,
	}, nil
}

func (s *Server) Refresh(ctx context.Context, req *pb.RefreshTokenRequest) (*pb.RefreshTokenResponse, error) {
	newAccessToken, err := s.authService.Refresh(req.RefreshToken)
	if err != nil {
		return nil, err
	}
	return &pb.RefreshTokenResponse{
		AccessToken: newAccessToken,
	}, nil
}

func (s *Server) Validate(ctx context.Context, req *pb.ValidateTokenRequest) (*pb.ValidateTokenResponse, error) {
	claims, err := s.authService.Validate(req.AccessToken)
	if err != nil {
		return nil, err
	}
	return &pb.ValidateTokenResponse{
		Sub:      claims.Subject,
		Username: claims.Username,
		Email:    claims.Email,
		Role:     claims.Role,
	}, nil
}

func (s *Server) Healthz(ctx context.Context, req *pb.HealthzRequest) (*pb.HealthzResponse, error) {
	if err := s.authService.HealthCheck(ctx); err != nil {
		return nil, err
	}
	return &pb.HealthzResponse{
		Status: "OK",
	}, nil
}
