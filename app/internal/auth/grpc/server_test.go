package grpc_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	pb "app/gen"
	gRPC "app/internal/auth/grpc"
	"app/internal/config"
	customerrors "app/internal/customErrors"
)

type MockAuthService struct {
	mock.Mock
}

func (m *MockAuthService) Register(username, email, password, role string) (uuid.UUID, error) {
	args := m.Called(username, email, password, role)
	return args.Get(0).(uuid.UUID), args.Error(1)
}

func (m *MockAuthService) Login(username, password string) (string, string, error) {
	args := m.Called(username, password)
	return args.String(0), args.String(1), args.Error(2)
}

func (m *MockAuthService) Refresh(refreshToken string) (string, error) {
	args := m.Called(refreshToken)
	return args.String(0), args.Error(1)
}

func (m *MockAuthService) Validate(accessToken string) (*config.Claims, error) {
	args := m.Called(accessToken)
	return args.Get(0).(*config.Claims), args.Error(1)
}

func (m *MockAuthService) HealthCheck(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

// Test helpers
type grpcTestDeps struct {
	authService *MockAuthService
	server      *grpc.Server
	client      pb.AuthServiceClient
	cleanup     func()
}

func setupGRPCTest(t *testing.T) *grpcTestDeps {
	authService := &MockAuthService{}
	authServer := gRPC.NewServer(authService)
	grpcServer := config.NewGRPCServer()
	pb.RegisterAuthServiceServer(grpcServer.Server, authServer)

	// Create in-memory connection for testing
	listener := bufconn.Listen(1024 * 1024)

	// Start server in goroutine
	go func() {
		if err := grpcServer.Serve(listener); err != nil {
			t.Logf("Server exited with error: %v", err)
		}
	}()

	// Create gRPC client
	conn, err := grpc.DialContext(
		context.Background(),
		"bufnet",
		grpc.WithContextDialer(func(ctx context.Context, s string) (net.Conn, error) {
			return listener.Dial()
		}),
		grpc.WithInsecure(),
	)
	require.NoError(t, err, "Failed to create gRPC client connection")

	return &grpcTestDeps{
		authService: authService,
		server:      grpcServer,
		client:      pb.NewAuthServiceClient(conn),
		cleanup: func() {
			grpcServer.GracefulStop()
			conn.Close()
			listener.Close()
		},
	}
}

func mockClaims() *config.Claims {
	return &config.Claims{
		Username: "testuser",
		Email:    "test@example.com",
		Role:     "user",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   uuid.New().String(),
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
		},
	}
}

func TestRegister(t *testing.T) {
	t.Parallel()

	testUUID := uuid.New()

	testCases := []struct {
		name           string
		req            *pb.RegisterRequest
		mockSetup      func(*grpcTestDeps)
		expectedResp   *pb.RegisterResponse
		expectedStatus codes.Code
	}{
		{
			name: "Successful registration",
			req: &pb.RegisterRequest{
				Username: "newuser",
				Email:    "new@example.com",
				Password: "ValidPass123!",
				Role:     "user",
			},
			mockSetup: func(d *grpcTestDeps) {
				d.authService.On("Register",
					"newuser", "new@example.com", "ValidPass123!", "user").
					Return(testUUID, nil)
			},
			expectedResp: &pb.RegisterResponse{
				Sub: testUUID.String(),
			},
			expectedStatus: codes.OK,
		},
		{
			name: "Invalid email format",
			req: &pb.RegisterRequest{
				Email:    "invalid-email",
				Password: "ValidPass123!",
			},
			mockSetup: func(d *grpcTestDeps) {
				d.authService.On("Register",
					"", "invalid-email", "ValidPass123!", "").
					Return(uuid.Nil, customerrors.ErrInvalidEmail)
			},
			expectedStatus: codes.InvalidArgument,
		},
		{
			name: "Username already exists",
			req: &pb.RegisterRequest{
				Username: "existinguser",
				Email:    "new@example.com",
				Password: "ValidPass123!",
				Role:     "user",
			},
			mockSetup: func(d *grpcTestDeps) {
				d.authService.On("Register",
					"existinguser", "new@example.com", "ValidPass123!", "user").
					Return(uuid.Nil, customerrors.ErrUsernameAlreadyExists)
			},
			expectedStatus: codes.AlreadyExists,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d := setupGRPCTest(t)
			defer d.cleanup()
			tc.mockSetup(d)

			resp, err := d.client.Register(context.Background(), tc.req)

			if tc.expectedStatus == codes.OK {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedResp, resp)
			} else {
				assert.Error(t, err)
				st, ok := status.FromError(err)
				require.True(t, ok, "Expected gRPC status error")
				assert.Equal(t, tc.expectedStatus, st.Code())
			}

			d.authService.AssertExpectations(t)
		})
	}
}

func TestLogin(t *testing.T) {
	t.Parallel()

	accessToken := "test-access-token"
	refreshToken := "test-refresh-token"

	testCases := []struct {
		name           string
		req            *pb.LoginRequest
		mockSetup      func(*grpcTestDeps)
		expectedResp   *pb.LoginResponse
		expectedStatus codes.Code
	}{
		{
			name: "Successful login",
			req: &pb.LoginRequest{
				Username: "testuser",
				Password: "correctpassword",
			},
			mockSetup: func(d *grpcTestDeps) {
				d.authService.On("Login",
					"testuser", "correctpassword").
					Return(accessToken, refreshToken, nil)
			},
			expectedResp: &pb.LoginResponse{
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
			},
			expectedStatus: codes.OK,
		},
		{
			name: "Empty credentials",
			req: &pb.LoginRequest{
				Username: "",
				Password: "",
			},
			mockSetup: func(d *grpcTestDeps) {
				d.authService.On("Login", "", "").
					Return("", "", customerrors.ErrBadRequest)
			},
			expectedStatus: codes.InvalidArgument,
		},
		{
			name: "Invalid credentials",
			req: &pb.LoginRequest{
				Username: "testuser",
				Password: "wrongpassword",
			},
			mockSetup: func(d *grpcTestDeps) {
				d.authService.On("Login",
					"testuser", "wrongpassword").
					Return("", "", customerrors.ErrInvalidCredentials)
			},
			expectedStatus: codes.Unauthenticated,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d := setupGRPCTest(t)
			defer d.cleanup()
			tc.mockSetup(d)

			resp, err := d.client.Login(context.Background(), tc.req)

			if tc.expectedStatus == codes.OK {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedResp, resp)
			} else {
				assert.Error(t, err)
				st, ok := status.FromError(err)
				require.True(t, ok, "Expected gRPC status error")
				assert.Equal(t, tc.expectedStatus, st.Code())
			}

			d.authService.AssertExpectations(t)
		})
	}
}

func TestRefresh(t *testing.T) {
	t.Parallel()

	newAccessToken := "new-access-token"

	testCases := []struct {
		name           string
		req            *pb.RefreshTokenRequest
		mockSetup      func(*grpcTestDeps)
		expectedResp   *pb.RefreshTokenResponse
		expectedStatus codes.Code
	}{
		{
			name: "Successful refresh",
			req: &pb.RefreshTokenRequest{
				RefreshToken: "valid-refresh-token",
			},
			mockSetup: func(d *grpcTestDeps) {
				d.authService.On("Refresh", "valid-refresh-token").
					Return(newAccessToken, nil)
			},
			expectedResp: &pb.RefreshTokenResponse{
				AccessToken: newAccessToken,
			},
			expectedStatus: codes.OK,
		},
		{
			name: "Empty refresh token",
			req: &pb.RefreshTokenRequest{
				RefreshToken: "",
			},
			mockSetup: func(d *grpcTestDeps) {
				d.authService.On("Refresh", "").
					Return("", customerrors.ErrBadRequest)
			},
			expectedStatus: codes.InvalidArgument,
		},
		{
			name: "Invalid refresh token",
			req: &pb.RefreshTokenRequest{
				RefreshToken: "invalid-token",
			},
			mockSetup: func(d *grpcTestDeps) {
				d.authService.On("Refresh", "invalid-token").
					Return("", customerrors.ErrInvalidToken)
			},
			expectedStatus: codes.Unauthenticated,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d := setupGRPCTest(t)
			defer d.cleanup()
			tc.mockSetup(d)

			resp, err := d.client.Refresh(context.Background(), tc.req)

			if tc.expectedStatus == codes.OK {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedResp, resp)
			} else {
				assert.Error(t, err)
				st, ok := status.FromError(err)
				require.True(t, ok, "Expected gRPC status error")
				assert.Equal(t, tc.expectedStatus, st.Code())
			}

			d.authService.AssertExpectations(t)
		})
	}
}

func TestValidate(t *testing.T) {
	t.Parallel()

	testClaims := mockClaims()

	testCases := []struct {
		name           string
		req            *pb.ValidateTokenRequest
		mockSetup      func(*grpcTestDeps)
		expectedResp   *pb.ValidateTokenResponse
		expectedStatus codes.Code
	}{
		{
			name: "Successful validation",
			req: &pb.ValidateTokenRequest{
				AccessToken: "valid-token",
			},
			mockSetup: func(d *grpcTestDeps) {
				d.authService.On("Validate", "valid-token").
					Return(testClaims, nil)
			},
			expectedResp: &pb.ValidateTokenResponse{
				Sub:      testClaims.Subject,
				Username: testClaims.Username,
				Email:    testClaims.Email,
				Role:     testClaims.Role,
			},
			expectedStatus: codes.OK,
		},
		{
			name: "Empty token",
			req: &pb.ValidateTokenRequest{
				AccessToken: "",
			},
			mockSetup: func(d *grpcTestDeps) {
				d.authService.On("Validate", "").
					Return(nil, customerrors.ErrBadRequest)
			},
			expectedStatus: codes.InvalidArgument,
		},
		{
			name: "Expired token",
			req: &pb.ValidateTokenRequest{
				AccessToken: "expired-token",
			},
			mockSetup: func(d *grpcTestDeps) {
				d.authService.On("Validate", "expired-token").
					Return(nil, customerrors.ErrTokenExpired)
			},
			expectedStatus: codes.Unauthenticated,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d := setupGRPCTest(t)
			defer d.cleanup()
			tc.mockSetup(d)

			resp, err := d.client.Validate(context.Background(), tc.req)

			if tc.expectedStatus == codes.OK {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedResp, resp)
			} else {
				assert.Error(t, err)
				st, ok := status.FromError(err)
				require.True(t, ok, "Expected gRPC status error")
				assert.Equal(t, tc.expectedStatus, st.Code())
			}

			d.authService.AssertExpectations(t)
		})
	}
}

func TestHealthz(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name           string
		mockSetup      func(*grpcTestDeps)
		expectedResp   *pb.HealthzResponse
		expectedStatus codes.Code
	}{
		{
			name: "Healthy service",
			mockSetup: func(d *grpcTestDeps) {
				d.authService.On("HealthCheck", mock.Anything).
					Return(nil)
			},
			expectedResp: &pb.HealthzResponse{
				Status: "OK",
			},
			expectedStatus: codes.OK,
		},
		{
			name: "Database unreachable",
			mockSetup: func(d *grpcTestDeps) {
				d.authService.On("HealthCheck", mock.Anything).
					Return(customerrors.ErrDbUnreacheable)
			},
			expectedStatus: codes.Unavailable,
		},
		{
			name: "Context timeout",
			mockSetup: func(d *grpcTestDeps) {
				d.authService.On("HealthCheck", mock.Anything).
					Return(context.DeadlineExceeded)
			},
			expectedStatus: codes.DeadlineExceeded,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d := setupGRPCTest(t)
			defer d.cleanup()
			tc.mockSetup(d)

			resp, err := d.client.Healthz(context.Background(), &pb.HealthzRequest{})

			if tc.expectedStatus == codes.OK {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedResp, resp)
			} else {
				assert.Error(t, err)
				st, ok := status.FromError(err)
				require.True(t, ok, "Expected gRPC status error")
				assert.Equal(t, tc.expectedStatus, st.Code())
			}

			d.authService.AssertExpectations(t)
		})
	}
}
