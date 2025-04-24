package config

import (
	"app/internal/interceptors"
	"crypto/tls"
	"crypto/x509"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type GRPCServer struct {
	Server          *grpc.Server
	config          Config
	shutdownTimeout time.Duration
}

type Config struct {
	TLSCertFile string
	TLSKeyFile  string
	CACertFile  string
	Port        string
}

func NewGRPCServer() *GRPCServer {
	cfg := Config{
		TLSCertFile: "certs/server.crt",
		TLSKeyFile:  "certs/server.key",
		CACertFile:  "certs/ca.crt",
		Port:        "50051",
	}

	creds, err := loadTLSCredentials(cfg)
	if err != nil {
		log.Fatalf("Failed to load TLS credentials: %v", err)
	}

	grpcServer := grpc.NewServer(
		grpc.Creds(creds),
		grpc.ChainUnaryInterceptor(
			interceptors.LoggingInterceptor,
			interceptors.ErrorInterceptor,
		),
	)

	return &GRPCServer{
		Server:          grpcServer,
		config:          cfg,
		shutdownTimeout: 10 * time.Second,
	}
}

func (s *GRPCServer) StartWithGracefulShutdown() {
	serverErrors := make(chan error, 1)

	go func() {
		serverErrors <- s.start()
	}()

	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, syscall.SIGINT, syscall.SIGTERM)

	// Block until we receive a signal or an error
	select {
	case err := <-serverErrors:
		log.Fatalf("Error starting server: %v", err)

	case <-shutdown:
		log.Println("Starting graceful shutdown...")

		stopped := make(chan struct{})
		go func() {
			s.Server.GracefulStop()
			close(stopped)
		}()

		select {
		case <-stopped:
			log.Println("Server stopped gracefully")
		case <-time.After(s.shutdownTimeout):
			log.Println("Timeout reached, forcing shutdown")
			s.Server.Stop()
		}
	}
}

func (s *GRPCServer) start() error {
	lis, err := net.Listen("tcp", ":"+s.config.Port)
	if err != nil {
		return err
	}

	log.Printf("Server gRPC is listening on :%s", s.config.Port)
	return s.Server.Serve(lis)
}

func (s *GRPCServer) GracefulShutdown(timeout time.Duration) {
	stopped := make(chan struct{})
	go func() {
		s.Server.GracefulStop()
		close(stopped)
	}()

	timer := time.NewTimer(timeout)
	select {
	case <-timer.C:
		log.Println("Forcing shutdown...")
		s.Server.Stop()
	case <-stopped:
		timer.Stop()
	}
}

func loadTLSCredentials(cfg Config) (credentials.TransportCredentials, error) {
	serverCert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
	if err != nil {
		return nil, err
	}

	caCert, err := os.ReadFile(cfg.CACertFile)
	if err != nil {
		return nil, err
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(caCert) {
		return nil, err
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    certPool,
		MinVersion:   tls.VersionTLS13,
	}

	return credentials.NewTLS(config), nil
}
