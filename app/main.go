package main

import (
	pb "github.com/taekwondodev/go-gRPC-Authentication/gen"
	"github.com/taekwondodev/go-gRPC-Authentication/internal/auth/grpc"
	"github.com/taekwondodev/go-gRPC-Authentication/internal/auth/repository"
	"github.com/taekwondodev/go-gRPC-Authentication/internal/auth/service"
	"github.com/taekwondodev/go-gRPC-Authentication/internal/config"
)

func main() {
	db := config.NewPostgres()
	db.InitDB()
	defer db.CloseDB()

	authRepo := repository.NewUserRepository(db.Db)
	authService := service.NewAuthService(authRepo, config.NewJWT())
	authServer := grpc.NewServer(authService)

	grpcServer := config.NewGRPCServer()
	pb.RegisterAuthServiceServer(grpcServer.Server, authServer)
	grpcServer.StartWithGracefulShutdown()
}
