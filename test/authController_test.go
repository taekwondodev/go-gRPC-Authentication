package test

import (
	"backend/controller"
	customerrors "backend/customErrors"
	"backend/dto"
	"backend/middleware"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

const (
	endpointRegisterString     = "/register"
	endpointLoginString        = "/login"
	endpointRefreshTokenString = "/refresh"
	endpointHealthString       = "/health"
	invalidRefreshTokenString  = "invalid-refresh-token"
)

type MockAuthService struct {
	mock.Mock
}

func (m *MockAuthService) Register(req dto.AuthRequest) (*dto.AuthResponse, error) {
	args := m.Called(req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*dto.AuthResponse), args.Error(1)
}

func (m *MockAuthService) Login(req dto.AuthRequest) (*dto.AuthResponse, error) {
	args := m.Called(req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*dto.AuthResponse), args.Error(1)
}

func (m *MockAuthService) Refresh(req dto.RefreshTokenRequest) (*dto.AuthResponse, error) {
	args := m.Called(req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*dto.AuthResponse), args.Error(1)
}

func (m *MockAuthService) HealthCheck() (*dto.HealthResponse, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*dto.HealthResponse), args.Error(1)
}

func setupAuthController() (*MockAuthService, controller.AuthController) {
	mockService := new(MockAuthService)
	authController := controller.NewAuthController(mockService)
	return mockService, *authController
}

func createRequest(method, endpoint string, payload any) *http.Request {
	if payload == nil {
		return httptest.NewRequest(method, endpoint, nil)
	}

	jsonBytes, _ := json.Marshal(payload)
	return httptest.NewRequest(method, endpoint, bytes.NewBuffer(jsonBytes))
}

func createInvalidJSONRequest(method, endpoint string) *http.Request {
	return httptest.NewRequest(method, endpoint, bytes.NewBufferString(`invalid-json`))
}

type registerControllerTestCase struct {
	name           string
	requestBody    any
	mockSetup      func(*MockAuthService)
	expectedStatus int
	expectedBody   string
}

func TestAuthControllerRegister(t *testing.T) {
	validRequest := dto.AuthRequest{
		Username: "testuser",
		Password: "testpassword",
		Email:    emailString,
	}

	testCases := []registerControllerTestCase{
		{
			name:        "RegisterSuccessful",
			requestBody: validRequest,
			mockSetup: func(mockService *MockAuthService) {
				mockService.On("Register", validRequest).
					Return(&dto.AuthResponse{Message: "Sign-Up successfully!"}, nil)
			},
			expectedStatus: http.StatusCreated,
			expectedBody:   `{"message":"Sign-Up successfully!"}`,
		},
		{
			name:        "UsernameAlreadyExists",
			requestBody: validRequest,
			mockSetup: func(mockService *MockAuthService) {
				mockService.On("Register", validRequest).
					Return(nil, customerrors.ErrUsernameAlreadyExists)
			},
			expectedStatus: http.StatusConflict,
			expectedBody:   `{"code":409,"message":"username already exists"}`,
		},
		{
			name:        "EmailAlreadyExists",
			requestBody: validRequest,
			mockSetup: func(mockService *MockAuthService) {
				mockService.On("Register", validRequest).
					Return(nil, customerrors.ErrEmailAlreadyExists)
			},
			expectedStatus: http.StatusConflict,
			expectedBody:   `{"code":409,"message":"email already exists"}`,
		},
		{
			name:        "InvalidRequest",
			requestBody: nil, // Will create invalid JSON
			mockSetup: func(mockService *MockAuthService) {
				// No setup needed
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   `{"code":400,"message":"bad request"}`,
		},
		{
			name:        "DatabaseError",
			requestBody: validRequest,
			mockSetup: func(mockService *MockAuthService) {
				mockService.On("Register", validRequest).
					Return(nil, customerrors.ErrInternalServer)
			},
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   `{"code":500,"message":"internal server error"}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockService, authController := setupAuthController()
			tc.mockSetup(mockService)

			w := httptest.NewRecorder()
			var r *http.Request

			if tc.requestBody == nil {
				r = createInvalidJSONRequest(http.MethodPost, endpointRegisterString)
			} else {
				r = createRequest(http.MethodPost, endpointRegisterString, tc.requestBody)
			}

			handler := middleware.ErrorHandler(authController.Register)
			handler.ServeHTTP(w, r)

			assert.Equal(t, tc.expectedStatus, w.Code)
			assert.JSONEq(t, tc.expectedBody, w.Body.String())
			mockService.AssertExpectations(t)
		})
	}
}

type loginControllerTestCase struct {
	name           string
	requestBody    any
	mockSetup      func(*MockAuthService)
	expectedStatus int
	expectedBody   string
}

func TestAuthControllerLogin(t *testing.T) {
	validRequest := dto.AuthRequest{
		Username: "testuser",
		Password: "testpassword",
	}

	testCases := []loginControllerTestCase{
		{
			name:        "LoginSuccessful",
			requestBody: validRequest,
			mockSetup: func(mockService *MockAuthService) {
				mockService.On("Login", validRequest).
					Return(&dto.AuthResponse{Message: "Login successful!"}, nil)
			},
			expectedStatus: http.StatusOK,
			expectedBody:   `{"message":"Login successful!"}`,
		},
		{
			name:        "InvalidCredentials",
			requestBody: validRequest,
			mockSetup: func(mockService *MockAuthService) {
				mockService.On("Login", validRequest).
					Return(nil, customerrors.ErrInvalidCredentials)
			},
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   `{"code":401,"message":"invalid credentials"}`,
		},
		{
			name:        "UserNotFound",
			requestBody: validRequest,
			mockSetup: func(mockService *MockAuthService) {
				mockService.On("Login", validRequest).
					Return(nil, customerrors.ErrUserNotFound)
			},
			expectedStatus: http.StatusNotFound,
			expectedBody:   `{"code":404,"message":"user not found"}`,
		},
		{
			name:        "InvalidRequest",
			requestBody: nil, // Will create invalid JSON
			mockSetup: func(mockService *MockAuthService) {
				// No setup needed
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   `{"code":400,"message":"bad request"}`,
		},
		{
			name:        "JWTError",
			requestBody: validRequest,
			mockSetup: func(mockService *MockAuthService) {
				mockService.On("Login", validRequest).
					Return(nil, customerrors.ErrInternalServer)
			},
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   `{"code":500,"message":"internal server error"}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockService, authController := setupAuthController()
			tc.mockSetup(mockService)

			w := httptest.NewRecorder()
			var r *http.Request

			if tc.requestBody == nil {
				r = createInvalidJSONRequest(http.MethodPost, endpointLoginString)
			} else {
				r = createRequest(http.MethodPost, endpointLoginString, tc.requestBody)
			}

			handler := middleware.ErrorHandler(authController.Login)
			handler.ServeHTTP(w, r)

			assert.Equal(t, tc.expectedStatus, w.Code)
			assert.JSONEq(t, tc.expectedBody, w.Body.String())
			mockService.AssertExpectations(t)
		})
	}
}

type refreshTokenControllerTestCase struct {
	name           string
	requestBody    any
	mockSetup      func(*MockAuthService)
	expectedStatus int
	expectedBody   string
}

func TestAuthControllerRefreshToken(t *testing.T) {
	validRequest := dto.RefreshTokenRequest{
		RefreshToken: "valid-refresh-token",
	}

	invalidTokenRequest := dto.RefreshTokenRequest{
		RefreshToken: invalidRefreshTokenString,
	}

	testCases := []refreshTokenControllerTestCase{
		{
			name:        "RefreshSuccessful",
			requestBody: validRequest,
			mockSetup: func(mockService *MockAuthService) {
				mockService.On("Refresh", validRequest).
					Return(&dto.AuthResponse{Message: "Token refreshed successfully!"}, nil)
			},
			expectedStatus: http.StatusOK,
			expectedBody:   `{"message":"Token refreshed successfully!"}`,
		},
		{
			name:        "InvalidRequest",
			requestBody: nil, // Will create invalid JSON
			mockSetup: func(mockService *MockAuthService) {
				// No setup needed
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   `{"code":400,"message":"bad request"}`,
		},
		{
			name:        "InternalServerError",
			requestBody: invalidTokenRequest,
			mockSetup: func(mockService *MockAuthService) {
				mockService.On("Refresh", invalidTokenRequest).
					Return(nil, customerrors.ErrInternalServer)
			},
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   `{"code":500,"message":"internal server error"}`,
		},
		{
			name:        "TokenExpired",
			requestBody: invalidTokenRequest,
			mockSetup: func(mockService *MockAuthService) {
				mockService.On("Refresh", invalidTokenRequest).
					Return(nil, jwt.ErrTokenExpired)
			},
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   `{"code":401,"message":"token is expired"}`,
		},
		{
			name:        "InvalidSignature",
			requestBody: invalidTokenRequest,
			mockSetup: func(mockService *MockAuthService) {
				mockService.On("Refresh", invalidTokenRequest).
					Return(nil, jwt.ErrSignatureInvalid)
			},
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   `{"code":401,"message":"signature is invalid"}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockService, authController := setupAuthController()
			tc.mockSetup(mockService)

			w := httptest.NewRecorder()
			var r *http.Request

			if tc.requestBody == nil {
				r = createInvalidJSONRequest(http.MethodPost, endpointRefreshTokenString)
			} else {
				r = createRequest(http.MethodPost, endpointRefreshTokenString, tc.requestBody)
			}

			handler := middleware.ErrorHandler(authController.Refresh)
			handler.ServeHTTP(w, r)

			assert.Equal(t, tc.expectedStatus, w.Code)
			assert.JSONEq(t, tc.expectedBody, w.Body.String())
			mockService.AssertExpectations(t)
		})
	}
}

func TestAuthControllerHealth(t *testing.T) {
	mockService, authController := setupAuthController()

	mockService.On("HealthCheck").
		Return(&dto.HealthResponse{
			Status:   "OK",
			Database: "",
			SslMode:  "",
		}, nil)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, endpointHealthString, nil)

	handler := middleware.ErrorHandler(authController.HealthCheck)
	handler.ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{"status":"OK", "database":"", "ssl_mode":""}`, w.Body.String())
	mockService.AssertExpectations(t)
}
