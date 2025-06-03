package config

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/taekwondodev/go-gRPC-Authentication/internal/interceptors"
	"google.golang.org/grpc"
)

type GRPCServer struct {
	Server          *grpc.Server
	port            string
	shutdownTimeout time.Duration
}

var defaultPort = flag.String("port", "50051", "The gRPC server port")

func NewGRPCServer() *GRPCServer {
	if !flag.Parsed() {
		flag.Parse()
	}
	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			interceptors.LoggingInterceptor,
			interceptors.ErrorInterceptor,
		),
	)

	return &GRPCServer{
		Server:          grpcServer,
		port:            *defaultPort,
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
	lis, err := net.Listen("tcp", ":"+s.port)
	if err != nil {
		return err
	}

	log.Printf("Server gRPC is listening on :%s", s.port)
	return s.Server.Serve(lis)
}
