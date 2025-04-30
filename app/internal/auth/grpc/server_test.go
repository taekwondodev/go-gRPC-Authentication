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
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	pb "app/gen"
	gRPC "app/internal/auth/grpc"
	"app/internal/config"
	customerrors "app/internal/customErrors"
	"app/internal/interceptors"
)

const (
	testUsername      = "testuser"
	testPassword      = "password123!"
	testEmail         = "test@example.com"
	testRole          = "user"
	validRefreshToken = "valid-refresh-token"
	accessToken       = "access-token"
	invalidToken      = "invalid-token"
)

var testUUID = uuid.New()

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
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*config.Claims), args.Error(1)
}

func (m *MockAuthService) HealthCheck(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

type grpcTestDeps struct {
	authService *MockAuthService
	server      *grpc.Server
	client      pb.AuthServiceClient
	cleanup     func()
}

func setupGRPCTest(t *testing.T) *grpcTestDeps {
	authService := &MockAuthService{}
	authServer := gRPC.NewServer(authService)

	serveropts := []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(
			interceptors.ErrorInterceptor,
		),
	}
	grpcServer := grpc.NewServer(serveropts...)
	pb.RegisterAuthServiceServer(grpcServer, authServer)
	listener := bufconn.Listen(1024 * 1024)

	go func() {
		if err := grpcServer.Serve(listener); err != nil {
			t.Logf("server exited with error: %v", err)
		}
	}()

	conn, err := grpc.Dial(
		"bufnet",
		grpc.WithContextDialer(func(ctx context.Context, s string) (net.Conn, error) {
			return listener.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	assert.NoError(t, err)

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
		Username: testUsername,
		Email:    testEmail,
		Role:     testRole,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   testUUID.String(),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
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
		expectedErr    bool
		expectedStatus int
	}{
		{
			name: "Successful registration",
			req: &pb.RegisterRequest{
				Username: testUsername,
				Email:    testEmail,
				Password: testPassword,
				Role:     testRole,
			},
			mockSetup: func(d *grpcTestDeps) {
				d.authService.On("Register",
					testUsername, testEmail, testPassword, testRole).
					Return(testUUID, nil)
			},
			expectedResp: &pb.RegisterResponse{
				Sub: testUUID.String(),
			},
			expectedErr: false,
		},
		{
			name: "Invalid email format",
			req: &pb.RegisterRequest{
				Email:    "invalid-email",
				Password: testPassword,
			},
			mockSetup: func(d *grpcTestDeps) {
				d.authService.On("Register",
					"", "invalid-email", testPassword, "").
					Return(uuid.Nil, customerrors.ErrInvalidEmail)
			},
			expectedErr:    true,
			expectedStatus: 3,
		},
		{
			name: "Username already exists",
			req: &pb.RegisterRequest{
				Username: "existinguser",
				Email:    testEmail,
				Password: testPassword,
				Role:     testRole,
			},
			mockSetup: func(d *grpcTestDeps) {
				d.authService.On("Register",
					"existinguser", testEmail, testPassword, testRole).
					Return(uuid.Nil, customerrors.ErrUsernameAlreadyExists)
			},
			expectedErr:    true,
			expectedStatus: 6,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d := setupGRPCTest(t)
			defer d.cleanup()
			tc.mockSetup(d)

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			resp, err := d.client.Register(ctx, tc.req)

			if !tc.expectedErr {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedResp, resp)
			} else {
				assert.Error(t, err)
				st, _ := status.FromError(err)
				assert.Equal(t, tc.expectedStatus, st.Code())
			}

			d.authService.AssertExpectations(t)
		})
	}
}

func TestLogin(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name           string
		req            *pb.LoginRequest
		mockSetup      func(*grpcTestDeps)
		expectedResp   *pb.LoginResponse
		expectedErr    bool
		expectedStatus int
	}{
		{
			name: "Successful login",
			req: &pb.LoginRequest{
				Username: testUsername,
				Password: testPassword,
			},
			mockSetup: func(d *grpcTestDeps) {
				d.authService.On("Login",
					testUsername, testPassword).
					Return(accessToken, validRefreshToken, nil)
			},
			expectedResp: &pb.LoginResponse{
				AccessToken:  accessToken,
				RefreshToken: validRefreshToken,
			},
			expectedErr: false,
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
			expectedErr:    true,
			expectedStatus: 3,
		},
		{
			name: "Invalid credentials",
			req: &pb.LoginRequest{
				Username: testUsername,
				Password: "wrongpassword",
			},
			mockSetup: func(d *grpcTestDeps) {
				d.authService.On("Login",
					testUsername, "wrongpassword").
					Return("", "", customerrors.ErrInvalidCredentials)
			},
			expectedErr:    true,
			expectedStatus: 16,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d := setupGRPCTest(t)
			defer d.cleanup()
			tc.mockSetup(d)

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			resp, err := d.client.Login(ctx, tc.req)

			if !tc.expectedErr {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedResp, resp)
			} else {
				assert.Error(t, err)
				st, _ := status.FromError(err)
				assert.Equal(t, tc.expectedStatus, st.Code())
			}

			d.authService.AssertExpectations(t)
		})
	}
}

func TestRefresh(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name           string
		req            *pb.RefreshTokenRequest
		mockSetup      func(*grpcTestDeps)
		expectedResp   *pb.RefreshTokenResponse
		expectedErr    bool
		expectedStatus int
	}{
		{
			name: "Successful refresh",
			req: &pb.RefreshTokenRequest{
				RefreshToken: validRefreshToken,
			},
			mockSetup: func(d *grpcTestDeps) {
				d.authService.On("Refresh", validRefreshToken).
					Return(accessToken, nil)
			},
			expectedResp: &pb.RefreshTokenResponse{
				AccessToken: accessToken,
			},
			expectedErr: false,
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
			expectedErr:    true,
			expectedStatus: 3,
		},
		{
			name: "Invalid refresh token",
			req: &pb.RefreshTokenRequest{
				RefreshToken: invalidToken,
			},
			mockSetup: func(d *grpcTestDeps) {
				d.authService.On("Refresh", invalidToken).
					Return("", jwt.ErrSignatureInvalid)
			},
			expectedErr:    true,
			expectedStatus: 16,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d := setupGRPCTest(t)
			defer d.cleanup()
			tc.mockSetup(d)

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			resp, err := d.client.Refresh(ctx, tc.req)

			if !tc.expectedErr {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedResp, resp)
			} else {
				assert.Error(t, err)
				st, _ := status.FromError(err)
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
		expectedErr    bool
		expectedStatus int
	}{
		{
			name: "Successful validation",
			req: &pb.ValidateTokenRequest{
				AccessToken: accessToken,
			},
			mockSetup: func(d *grpcTestDeps) {
				d.authService.On("Validate", accessToken).
					Return(testClaims, nil)
			},
			expectedResp: &pb.ValidateTokenResponse{
				Sub:      testClaims.Subject,
				Username: testClaims.Username,
				Email:    testClaims.Email,
				Role:     testClaims.Role,
			},
			expectedErr: false,
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
			expectedErr:    true,
			expectedStatus: 3,
		},
		{
			name: "Expired token",
			req: &pb.ValidateTokenRequest{
				AccessToken: "expired-token",
			},
			mockSetup: func(d *grpcTestDeps) {
				d.authService.On("Validate", "expired-token").
					Return(nil, jwt.ErrTokenExpired)
			},
			expectedErr:    true,
			expectedStatus: 16,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d := setupGRPCTest(t)
			defer d.cleanup()
			tc.mockSetup(d)

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			resp, err := d.client.Validate(ctx, tc.req)

			if !tc.expectedErr {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedResp, resp)
			} else {
				assert.Error(t, err)
				st, _ := status.FromError(err)
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
		expectedErr    bool
		expectedStatus int
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
			expectedErr: false,
		},
		{
			name: "Database unreachable",
			mockSetup: func(d *grpcTestDeps) {
				d.authService.On("HealthCheck", mock.Anything).
					Return(customerrors.ErrDbUnreacheable)
			},
			expectedErr:    true,
			expectedStatus: 14,
		},
		{
			name: "Context timeout",
			mockSetup: func(d *grpcTestDeps) {
				d.authService.On("HealthCheck", mock.Anything).
					Return(customerrors.ErrDbTimeout)
			},
			expectedErr:    true,
			expectedStatus: 14,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d := setupGRPCTest(t)
			defer d.cleanup()
			tc.mockSetup(d)

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			resp, err := d.client.Healthz(ctx, &pb.HealthzRequest{})

			if !tc.expectedErr {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedResp, resp)
			} else {
				assert.Error(t, err)
				st, _ := status.FromError(err)
				assert.Equal(t, tc.expectedStatus, st.Code())
			}

			d.authService.AssertExpectations(t)
		})
	}
}
