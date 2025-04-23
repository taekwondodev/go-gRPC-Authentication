package test

import (
	"backend/config"
	customerrors "backend/customErrors"
	"backend/dto"
	"backend/models"
	"backend/service"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockUserRepository struct {
	mock.Mock
}

type MockToken struct {
	mock.Mock
}

func (m *MockUserRepository) CheckUserExists(username, email string) error {
	args := m.Called(username, email)
	return args.Error(0)
}

func (m *MockUserRepository) SaveUser(username, password, email, role string) error {
	args := m.Called(username, password, email, role)
	return args.Error(0)
}

func (m *MockUserRepository) GetUserByCredentials(username, password string) (*models.User, error) {
	args := m.Called(username, password)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockToken) GenerateJWT(username, email, id, role string) (string, string, error) {
	args := m.Called(username, email, id, role)
	return args.String(0), args.String(1), args.Error(2)
}

func (m *MockToken) ValidateJWT(tokenString string) (*config.Claims, error) {
	args := m.Called(tokenString)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*config.Claims), args.Error(1)
}

/*******************************************************************************/

func setupAuthService() (*MockUserRepository, *MockToken, service.AuthService) {
	mockRepo := new(MockUserRepository)
	mockToken := new(MockToken)
	authService := service.NewAuthService(mockRepo, mockToken)
	return mockRepo, mockToken, authService
}

type registerServiceTestCase struct {
	name           string
	request        dto.AuthRequest
	mockSetup      func(*MockUserRepository)
	expectedResult *dto.AuthResponse
	expectedError  error
}

func TestAuthServiceRegister(t *testing.T) {
	testCases := []registerServiceTestCase{
		{
			name: "RegisterSuccessful",
			request: dto.AuthRequest{
				Username: "testuser",
				Password: "password123",
				Email:    emailString,
			},
			mockSetup: func(mockRepo *MockUserRepository) {
				mockRepo.On("CheckUserExists", "testuser", emailString).Return(nil)
				mockRepo.On("SaveUser", "testuser", "password123", emailString, "").Return(nil)
			},
			expectedResult: &dto.AuthResponse{Message: "Sign-Up successfully!"},
			expectedError:  nil,
		},
		{
			name: "RegisterWithRoleSuccessful",
			request: dto.AuthRequest{
				Username: "testuser",
				Password: "password123",
				Email:    emailString,
				Role:     "admin",
			},
			mockSetup: func(mockRepo *MockUserRepository) {
				mockRepo.On("CheckUserExists", "testuser", emailString).Return(nil)
				mockRepo.On("SaveUser", "testuser", "password123", emailString, "admin").Return(nil)
			},
			expectedResult: &dto.AuthResponse{Message: "Sign-Up successfully!"},
			expectedError:  nil,
		},
		{
			name: "InvalidRequest",
			request: dto.AuthRequest{
				Username: "",
				Password: "",
				Email:    "",
			},
			mockSetup: func(mockRepo *MockUserRepository) {
				// No mock setup needed
			},
			expectedResult: nil,
			expectedError:  customerrors.ErrBadRequest,
		},
		{
			name: "UsernameAlreadyExists",
			request: dto.AuthRequest{
				Username: "existinguser",
				Password: "password123",
				Email:    emailString,
			},
			mockSetup: func(mockRepo *MockUserRepository) {
				mockRepo.On("CheckUserExists", "existinguser", emailString).
					Return(customerrors.ErrUsernameAlreadyExists)
			},
			expectedResult: nil,
			expectedError:  customerrors.ErrUsernameAlreadyExists,
		},
		{
			name: "EmailAlreadyExists",
			request: dto.AuthRequest{
				Username: "existinguser",
				Password: "password123",
				Email:    emailString,
			},
			mockSetup: func(mockRepo *MockUserRepository) {
				mockRepo.On("CheckUserExists", "existinguser", emailString).
					Return(customerrors.ErrEmailAlreadyExists)
			},
			expectedResult: nil,
			expectedError:  customerrors.ErrEmailAlreadyExists,
		},
		{
			name: "SaveUserError",
			request: dto.AuthRequest{
				Username: "newuser",
				Password: "password123",
				Email:    emailString,
			},
			mockSetup: func(mockRepo *MockUserRepository) {
				mockRepo.On("CheckUserExists", "newuser", emailString).Return(nil)
				mockRepo.On("SaveUser", "newuser", "password123", emailString, "").
					Return(assert.AnError)
			},
			expectedResult: nil,
			expectedError:  assert.AnError,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockRepo, _, authService := setupAuthService()
			tc.mockSetup(mockRepo)

			res, err := authService.Register(tc.request)

			if tc.expectedError != nil {
				assert.Error(t, err)
				if tc.expectedError != assert.AnError {
					assert.Equal(t, tc.expectedError.Error(), err.Error())
				}
				assert.Nil(t, res)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedResult.Message, res.Message)
			}
			mockRepo.AssertExpectations(t)
		})
	}
}

type loginServiceTestCase struct {
	name           string
	request        dto.AuthRequest
	mockSetup      func(*MockUserRepository, *MockToken)
	expectedResult *dto.AuthResponse
	expectedError  error
}

func TestAuthServiceLogin(t *testing.T) {
	testCases := []loginServiceTestCase{
		{
			name: "LoginSuccessful",
			request: dto.AuthRequest{
				Username: "testuser",
				Password: "password123",
			},
			mockSetup: func(mockRepo *MockUserRepository, mockToken *MockToken) {
				mockUser := &models.User{
					ID:       1,
					Username: "testuser",
					Email:    emailString,
					Role:     "user",
				}
				mockRepo.On("GetUserByCredentials", "testuser", "password123").Return(mockUser, nil)
				mockToken.On("GenerateJWT", mockUser.Username, mockUser.Email, "1", mockUser.Role).
					Return("mockAccessToken", "mockRefreshToken", nil)
			},
			expectedResult: &dto.AuthResponse{
				Message:      "Sign-In successfully!",
				AccessToken:  "mockAccessToken",
				RefreshToken: "mockRefreshToken",
			},
			expectedError: nil,
		},
		{
			name: "InvalidRequest",
			request: dto.AuthRequest{
				Username: "",
				Password: "",
			},
			mockSetup: func(mockRepo *MockUserRepository, mockToken *MockToken) {
				// No mock setup needed
			},
			expectedResult: nil,
			expectedError:  customerrors.ErrBadRequest,
		},
		{
			name: "UserNotFound",
			request: dto.AuthRequest{
				Username: "nonexistent",
				Password: "password123",
			},
			mockSetup: func(mockRepo *MockUserRepository, mockToken *MockToken) {
				mockRepo.On("GetUserByCredentials", "nonexistent", "password123").
					Return(nil, customerrors.ErrUserNotFound)
			},
			expectedResult: nil,
			expectedError:  customerrors.ErrUserNotFound,
		},
		{
			name: "JWTGenerationError",
			request: dto.AuthRequest{
				Username: "testuser",
				Password: "password123",
			},
			mockSetup: func(mockRepo *MockUserRepository, mockToken *MockToken) {
				mockUser := &models.User{
					ID:       1,
					Username: "testuser",
					Email:    emailString,
					Role:     "user",
				}
				mockRepo.On("GetUserByCredentials", "testuser", "password123").Return(mockUser, nil)
				mockToken.On("GenerateJWT", mockUser.Username, mockUser.Email, "1", mockUser.Role).
					Return("", "", assert.AnError)
			},
			expectedResult: nil,
			expectedError:  assert.AnError,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockRepo, mockToken, authService := setupAuthService()
			tc.mockSetup(mockRepo, mockToken)

			res, err := authService.Login(tc.request)

			if tc.expectedError != nil {
				assert.Error(t, err)
				if tc.expectedError != assert.AnError {
					assert.Equal(t, tc.expectedError.Error(), err.Error())
				}
				assert.Nil(t, res)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedResult.Message, res.Message)
				assert.Equal(t, tc.expectedResult.AccessToken, res.AccessToken)
				assert.Equal(t, tc.expectedResult.RefreshToken, res.RefreshToken)
			}
			mockRepo.AssertExpectations(t)
			mockToken.AssertExpectations(t)
		})
	}
}

type refreshTokenServiceTestCase struct {
	name           string
	request        dto.RefreshTokenRequest
	mockSetup      func(*MockToken)
	expectedResult *dto.AuthResponse
	expectedError  error
}

func TestAuthServiceRefresh(t *testing.T) {
	testCases := []refreshTokenServiceTestCase{
		{
			name: "RefreshSuccessful",
			request: dto.RefreshTokenRequest{
				RefreshToken: "valid-refresh-token",
			},
			mockSetup: func(mockToken *MockToken) {
				mockClaims := &config.Claims{
					Username: "testuser",
					Email:    emailString,
					Role:     "user",
					RegisteredClaims: jwt.RegisteredClaims{
						ID: "1",
					},
				}
				mockToken.On("ValidateJWT", "valid-refresh-token").Return(mockClaims, nil)
				mockToken.On("GenerateJWT", "testuser", emailString, "1", "user").
					Return("mockAccessToken", "", nil)
			},
			expectedResult: &dto.AuthResponse{
				Message:     "Update token successfully!",
				AccessToken: "mockAccessToken",
			},
			expectedError: nil,
		},
		{
			name: "InvalidRequest",
			request: dto.RefreshTokenRequest{
				RefreshToken: "",
			},
			mockSetup: func(mockToken *MockToken) {
				// No mock setup needed
			},
			expectedResult: nil,
			expectedError:  customerrors.ErrBadRequest,
		},
		{
			name: "InvalidToken",
			request: dto.RefreshTokenRequest{
				RefreshToken: "invalid-token",
			},
			mockSetup: func(mockToken *MockToken) {
				mockToken.On("ValidateJWT", "invalid-token").Return(nil, assert.AnError)
			},
			expectedResult: nil,
			expectedError:  assert.AnError,
		},
		{
			name: "JWTGenerationError",
			request: dto.RefreshTokenRequest{
				RefreshToken: "valid-but-error",
			},
			mockSetup: func(mockToken *MockToken) {
				mockClaims := &config.Claims{
					Username: "testuser",
					Email:    emailString,
					Role:     "user",
					RegisteredClaims: jwt.RegisteredClaims{
						ID: "1",
					},
				}
				mockToken.On("ValidateJWT", "valid-but-error").Return(mockClaims, nil)
				mockToken.On("GenerateJWT", "testuser", emailString, "1", "user").
					Return("", "", assert.AnError)
			},
			expectedResult: nil,
			expectedError:  assert.AnError,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, mockToken, authService := setupAuthService()
			tc.mockSetup(mockToken)

			res, err := authService.Refresh(tc.request)

			if tc.expectedError != nil {
				assert.Error(t, err)
				if tc.expectedError != assert.AnError {
					assert.Equal(t, tc.expectedError.Error(), err.Error())
				}
				assert.Nil(t, res)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedResult.Message, res.Message)
				assert.Equal(t, tc.expectedResult.AccessToken, res.AccessToken)
			}
			mockToken.AssertExpectations(t)
		})
	}
}
