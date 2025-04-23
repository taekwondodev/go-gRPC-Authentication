package middleware

import (
	customerrors "backend/customErrors"
	"context"
	"encoding/json"
	"log"
	"net/http"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func ErrorInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	resp, err := handler(ctx, req)
	if err != nil {
		log.Printf("Error: %v", err)
		// Converti errori specifici in status gRPC
		return nil, status.Errorf(codes.Internal, "internal error")
	}
	return resp, nil
}

type HandlerFunc func(w http.ResponseWriter, r *http.Request) error

func ErrorHandler(h HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := h(w, r); err != nil {
			handleHttpError(w, err)
		}
	}
}

func handleHttpError(w http.ResponseWriter, err error) {
	status := customerrors.GetStatus(err)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	res := &customerrors.Error{
		Code:    status,
		Message: customerrors.GetMessage(err),
	}

	json.NewEncoder(w).Encode(res)
}
