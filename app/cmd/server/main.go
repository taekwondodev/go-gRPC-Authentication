package cmd

import (
	"backend/internal/auth/service"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"log"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func loadTLSCredentials() (credentials.TransportCredentials, error) {
	serverCert, err := tls.LoadX509KeyPair("certs/server.crt", "certs/server.key")
	if err != nil {
		return nil, err
	}

	caCert, err := ioutil.ReadFile("certs/ca.crt")
	if err != nil {
		return nil, err
	}

	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(caCert)

	config := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    certPool,
		MinVersion:   tls.VersionTLS13,
	}

	return credentials.NewTLS(config), nil
}

func main() {
	creds, err := loadTLSCredentials()
	if err != nil {
		log.Fatal(err)
	}

	// Inizializza i tuoi layer (repository, service)
	authRepo := repository.NewPostgresRepository() // Adatta al tuo DB
	authService := service.NewAuthService(authRepo)
	grpcServer := grpc.NewServer(
		grpc.Creds(creds),
		grpc.UnaryInterceptor(interceptors.LoggingInterceptor),
		grpc.UnaryInterceptor(interceptors.ErrorInterceptor),
	)

	pb.RegisterAuthServiceServer(grpcServer, grpc.NewServer(authService))

	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Server gRPC in ascolto su :50051")
	grpcServer.Serve(lis)
}
