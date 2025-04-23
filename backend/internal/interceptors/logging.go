package middleware

import (
	customerrors "backend/customErrors"
	"context"
	"log"
	"net/http"
	"time"

	"google.golang.org/grpc"
)

func LoggingInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	start := time.Now()
	log.Printf("Starting %s at %s", info.FullMethod, start.Format(time.RFC3339))

	resp, err := handler(ctx, req)

	duration := time.Since(start)
	log.Printf("Finished %s in %v", info.FullMethod, duration)

	return resp, err
}

func LoggingMiddleware(next HandlerFunc) HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		start := time.Now()
		log.Printf("Started %s %s", r.Method, r.URL.Path)

		err := next(w, r)

		duration := time.Since(start)
		status := http.StatusOK
		if err != nil {
			status = customerrors.GetStatus(err)
		}

		log.Printf("Completed %s %s | Status: %d | Duration: %v",
			r.Method, r.URL.Path, status, duration)

		return err
	}
}
