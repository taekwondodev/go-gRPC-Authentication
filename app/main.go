package main

import (
	pb "app/gen"
	"app/internal/auth/grpc"
	"app/internal/auth/repository"
	"app/internal/auth/service"
	"app/internal/config"
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
