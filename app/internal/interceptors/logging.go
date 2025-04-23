package middleware

import (
	customerrors "app/internal/customErrors"
	"context"
	"log"
	"time"

	"google.golang.org/grpc"
)

func LoggingInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	start := time.Now()
	log.Printf("Starting %s at %s", info.FullMethod, start.Format(time.RFC3339))

	resp, err := handler(ctx, req)

	duration := time.Since(start)
	code := 0
	if err != nil {
		code = customerrors.GetCode(err)
	}

	log.Printf(
		"Completed: %s | Code: %d | Duration: %v",
		info.FullMethod, code, duration,
	)

	return resp, err
}
