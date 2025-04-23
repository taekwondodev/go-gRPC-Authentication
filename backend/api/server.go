package api

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

type Server struct {
	*http.Server
	shutdownTimeout time.Duration
}

func NewServer(addr string, router *http.ServeMux) *Server {
	return &Server{
		Server: &http.Server{
			Addr:    addr,
			Handler: router,
		},
		shutdownTimeout: 10 * time.Second,
	}
}

func (s *Server) StartWithGracefulShutdown() {
	serverErrors := make(chan error, 1)

	go func() {
		serverErrors <- s.start()
	}()

	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	// Block until we receive a signal or an error
	select {
	case err := <-serverErrors:
		log.Fatalf("Error starting server: %v", err)

	case <-shutdown:
		log.Println("Starting graceful shutdown...")

		ctx, cancel := context.WithTimeout(context.Background(), s.shutdownTimeout)
		defer cancel()

		if err := s.shutdown(ctx); err != nil {
			log.Printf("Could not gracefully shutdown the server: %v", err)

			if err := s.Close(); err != nil {
				log.Printf("Could not close server: %v", err)
			}
		}
		log.Println("Server gracefully stopped")
	}
}

func (s *Server) start() error {
	log.Printf("Server listening on %s", s.Addr)
	return s.ListenAndServe()
}

func (s *Server) shutdown(ctx context.Context) error {
	return s.Server.Shutdown(ctx)
}
