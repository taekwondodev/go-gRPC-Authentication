package interceptors

import (
	"context"

	customerrors "github.com/taekwondodev/go-gRPC-Authentication/internal/customErrors"
	"google.golang.org/grpc"
)

func ErrorInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	resp, err := handler(ctx, req)
	if err != nil {
		return nil, handleGrpcError(err)
	}
	return resp, nil
}

func handleGrpcError(err error) error {
	return &customerrors.Error{
		Code:    customerrors.GetCode(err),
		Message: customerrors.GetMessage(err),
	}
}
