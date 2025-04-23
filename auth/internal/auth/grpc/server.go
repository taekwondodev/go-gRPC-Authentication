package grpc

import (
	"backend/internal/auth/service"
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Server struct {
	pb.UnimplementedAuthServiceServer
	authService service.AuthService
}

func NewServer(authService service.AuthService) *Server {
	return &Server{authService: authService}
}

func (s *Server) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	token, refreshToken, err := s.authService.Login(req.Email, req.Password)
	if err != nil {
		return nil, err
	}
	return &pb.LoginResponse{Token: token, RefreshToken: refreshToken}, nil
}

func (s *Server) RefreshToken(ctx context.Context, req *pb.RefreshRequest) (*pb.RefreshResponse, error) {
	newToken, newRefreshToken, err := s.authService.RefreshToken(req.RefreshToken)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid refresh token")
	}
	return &pb.RefreshResponse{
		Token:        newToken,
		RefreshToken: newRefreshToken,
	}, nil
}

func (s *Server) HealthCheck(ctx context.Context, req *pb.HealthRequest) (*pb.HealthResponse, error) {
	// Verifica la connessione al database (esempio con Postgres)
	if err := s.authService.HealthCheck(); err != nil {
		return nil, status.Error(codes.Internal, "service unhealthy")
	}
	return &pb.HealthResponse{Status: "OK"}, nil
}
