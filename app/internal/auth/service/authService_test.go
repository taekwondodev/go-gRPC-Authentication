package service_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"app/internal/auth/repository"
	"app/internal/auth/service"
	"app/internal/config"
	customerrors "app/internal/customErrors"
	"app/internal/models"
)

type MockToken struct {
	mock.Mock
}

func (m *MockToken) GenerateJWT(username, email, role string, sub uuid.UUID) (string, string, error) {
	args := m.Called(username, email, role, sub)
	return args.String(0), args.String(1), args.Error(2)
}

func (m *MockToken) ValidateJWT(token string) (*config.Claims, error) {
	args := m.Called(token)
	return args.Get(0).(*config.Claims), args.Error(1)
}

type authTestDeps struct {
	repo     *repository.UserRepositoryImpl
	repoMock sqlmock.Sqlmock
	token    *MockToken
	service  service.AuthService
	cleanup  func()
}

func setupAuthTest(t *testing.T) *authTestDeps {
	db, repoMock, err := sqlmock.New()
	require.NoError(t, err, "Failed to create sqlmock")

	repo := repository.NewUserRepository(db).(*repository.UserRepositoryImpl)

	token := &MockToken{}

	authService := service.NewAuthService(repo, token)

	return &authTestDeps{
		repo:     repo,
		repoMock: repoMock,
		token:    token,
		service:  authService,
		cleanup: func() {
			assert.NoError(t, repoMock.ExpectationsWereMet())
			db.Close()
		},
	}
}

func mockUser() models.User {
	return models.User{
		Sub:          uuid.New(),
		Username:     "testuser",
		Email:        "test@example.com",
		PasswordHash: "$2a$10$fakehash",
		Role:         "user",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
		IsActive:     true,
	}
}

func mockClaims() *config.Claims {
	return &config.Claims{
		Username: "testuser",
		Email:    "test@example.com",
		Role:     "user",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   uuid.New().String(),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
}

const newEmail = "new@example.com"
const validPassword = "ValidPass123!"
const validRefreshToken = "valid-refresh-token"
const invalidToken = "invalid-token"

func TestRegister(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		username      string
		email         string
		password      string
		role          string
		mockSetup     func(*authTestDeps)
		expectedUUID  uuid.UUID
		expectedError error
	}{
		{
			name:     "Successful registration",
			username: "newuser",
			email:    newEmail,
			password: validPassword,
			role:     "user",
			mockSetup: func(d *authTestDeps) {
				d.repoMock.ExpectQuery(
					`SELECT EXISTS\(SELECT 1 FROM users WHERE username = \$1\) AS username_exists,`+
						`EXISTS\(SELECT 1 FROM users WHERE email = \$2\) AS email_exists`,
				).WithArgs("newuser", newEmail).
					WillReturnRows(sqlmock.NewRows([]string{"username_exists", "email_exists"}).AddRow(false, false))

				d.repoMock.ExpectQuery(
					`INSERT INTO users \(username, email, password_hash, role\) VALUES \(\$1, \$2, \$3, \$4\) RETURNING sub`,
				).WithArgs("newuser", newEmail, mock.Anything, "user").
					WillReturnRows(sqlmock.NewRows([]string{"sub"}).AddRow(uuid.New()))
			},
			expectedError: nil,
		},
		{
			name:     "Invalid email format",
			email:    "invalid-email",
			password: validPassword,
			mockSetup: func(d *authTestDeps) {
				// No DB expectations for invalid email
			},
			expectedError: customerrors.ErrInvalidEmail,
		},
		{
			name:     "Invalid password format",
			email:    "valid@example.com",
			password: "short",
			mockSetup: func(d *authTestDeps) {
				// No DB expectations for invalid password
			},
			expectedError: customerrors.ErrInvalidPassword,
		},
		{
			name:     "Username already exists",
			username: "existinguser",
			email:    newEmail,
			password: validPassword,
			role:     "user",
			mockSetup: func(d *authTestDeps) {
				d.repoMock.ExpectQuery(
					`SELECT EXISTS\(SELECT 1 FROM users WHERE username = \$1\) AS username_exists,`+
						`EXISTS\(SELECT 1 FROM users WHERE email = \$2\) AS email_exists`,
				).WithArgs("existinguser", newEmail).
					WillReturnRows(sqlmock.NewRows([]string{"username_exists", "email_exists"}).AddRow(true, false))
			},
			expectedError: customerrors.ErrUsernameAlreadyExists,
		},
		{
			name:     "Database error on save",
			username: "newuser",
			email:    newEmail,
			password: validPassword,
			role:     "user",
			mockSetup: func(d *authTestDeps) {
				d.repoMock.ExpectQuery(
					`SELECT EXISTS\(SELECT 1 FROM users WHERE username = \$1\) AS username_exists,`+
						`EXISTS\(SELECT 1 FROM users WHERE email = \$2\) AS email_exists`,
				).WithArgs("newuser", newEmail).
					WillReturnRows(sqlmock.NewRows([]string{"username_exists", "email_exists"}).AddRow(false, false))

				d.repoMock.ExpectQuery(
					`INSERT INTO users \(username, email, password_hash, role\) VALUES \(\$1, \$2, \$3, \$4\) RETURNING sub`,
				).WithArgs("newuser", newEmail, mock.Anything, "user").
					WillReturnError(errors.New("database error"))
			},
			expectedError: errors.New("database error"),
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d := setupAuthTest(t)
			defer d.cleanup()

			if tc.mockSetup != nil {
				tc.mockSetup(d)
			}

			userID, err := d.service.Register(tc.username, tc.email, tc.password, tc.role)

			if tc.expectedError != nil {
				assert.ErrorContains(t, err, tc.expectedError.Error())
			} else {
				assert.NoError(t, err)
				assert.NotEqual(t, uuid.Nil, userID)
			}
		})
	}
}

func TestLogin(t *testing.T) {
	t.Parallel()

	testUser := mockUser()
	accessToken := "test-access-token"
	refreshToken := "test-refresh-token"

	testCases := []struct {
		name           string
		username       string
		password       string
		mockSetup      func(*authTestDeps)
		expectedTokens []string
		expectedError  error
	}{
		{
			name:     "Successful login",
			username: "testuser",
			password: "correctpassword",
			mockSetup: func(d *authTestDeps) {
				d.repoMock.ExpectQuery(
					`SELECT sub, username, email, password_hash, role, created_at, updated_at, is_active ` +
						`FROM users WHERE username = \$1`,
				).WithArgs("testuser").
					WillReturnRows(sqlmock.NewRows([]string{
						"sub", "username", "email", "password_hash", "role",
						"created_at", "updated_at", "is_active",
					}).AddRow(
						testUser.Sub, testUser.Username, testUser.Email,
						testUser.PasswordHash, testUser.Role,
						testUser.CreatedAt, testUser.UpdatedAt, testUser.IsActive,
					))

				d.token.On("GenerateJWT",
					testUser.Username, testUser.Email, testUser.Role, testUser.Sub).
					Return(accessToken, refreshToken, nil)
			},
			expectedTokens: []string{accessToken, refreshToken},
			expectedError:  nil,
		},
		{
			name:     "Empty credentials",
			username: "",
			password: "",
			mockSetup: func(d *authTestDeps) {
				// No DB expectations for empty credentials
			},
			expectedError: customerrors.ErrBadRequest,
		},
		{
			name:     "User not found",
			username: "nonexistent",
			password: "anypassword",
			mockSetup: func(d *authTestDeps) {
				d.repoMock.ExpectQuery(
					`SELECT sub, username, email, password_hash, role, created_at, updated_at, is_active ` +
						`FROM users WHERE username = \$1`,
				).WithArgs("nonexistent").
					WillReturnError(customerrors.ErrUserNotFound)
			},
			expectedError: customerrors.ErrUserNotFound,
		},
		{
			name:     "Token generation error",
			username: "testuser",
			password: "correctpassword",
			mockSetup: func(d *authTestDeps) {
				d.repoMock.ExpectQuery(
					`SELECT sub, username, email, password_hash, role, created_at, updated_at, is_active ` +
						`FROM users WHERE username = \$1`,
				).WithArgs("testuser").
					WillReturnRows(sqlmock.NewRows([]string{
						"sub", "username", "email", "password_hash", "role",
						"created_at", "updated_at", "is_active",
					}).AddRow(
						testUser.Sub, testUser.Username, testUser.Email,
						testUser.PasswordHash, testUser.Role,
						testUser.CreatedAt, testUser.UpdatedAt, testUser.IsActive,
					))

				d.token.On("GenerateJWT",
					testUser.Username, testUser.Email, testUser.Role, testUser.Sub).
					Return("", "", errors.New("token generation failed"))
			},
			expectedError: errors.New("token generation failed"),
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d := setupAuthTest(t)
			defer d.cleanup()

			if tc.mockSetup != nil {
				tc.mockSetup(d)
			}

			at, rt, err := d.service.Login(tc.username, tc.password)

			if tc.expectedError != nil {
				assert.ErrorContains(t, err, tc.expectedError.Error())
				assert.Empty(t, at)
				assert.Empty(t, rt)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedTokens[0], at)
				assert.Equal(t, tc.expectedTokens[1], rt)
			}

			d.token.AssertExpectations(t)
		})
	}
}

func TestRefresh(t *testing.T) {
	t.Parallel()

	testClaims := mockClaims()
	newAccessToken := "new-access-token"

	testCases := []struct {
		name          string
		refreshToken  string
		mockSetup     func(*authTestDeps)
		expectedToken string
		expectedError error
	}{
		{
			name:         "Successful refresh",
			refreshToken: validRefreshToken,
			mockSetup: func(d *authTestDeps) {
				d.token.On("ValidateJWT", validRefreshToken).
					Return(testClaims, nil)

				d.token.On("GenerateJWT",
					testClaims.Username, testClaims.Email, testClaims.Role,
					uuid.MustParse(testClaims.Subject)).
					Return(newAccessToken, "", nil)
			},
			expectedToken: newAccessToken,
			expectedError: nil,
		},
		{
			name:         "Empty refresh token",
			refreshToken: "",
			mockSetup: func(d *authTestDeps) {
				// No expectations for empty token
			},
			expectedError: customerrors.ErrBadRequest,
		},
		{
			name:         "Invalid refresh token",
			refreshToken: invalidToken,
			mockSetup: func(d *authTestDeps) {
				d.token.On("ValidateJWT", invalidToken).
					Return(nil, jwt.ErrSignatureInvalid)
			},
			expectedError: jwt.ErrSignatureInvalid,
		},
		{
			name:         "Token generation error",
			refreshToken: validRefreshToken,
			mockSetup: func(d *authTestDeps) {
				d.token.On("ValidateJWT", validRefreshToken).
					Return(testClaims, nil)

				d.token.On("GenerateJWT",
					testClaims.Username, testClaims.Email, testClaims.Role,
					uuid.MustParse(testClaims.Subject)).
					Return("", "", errors.New("generation error"))
			},
			expectedError: errors.New("generation error"),
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d := setupAuthTest(t)
			defer d.cleanup()

			if tc.mockSetup != nil {
				tc.mockSetup(d)
			}

			token, err := d.service.Refresh(tc.refreshToken)

			if tc.expectedError != nil {
				assert.ErrorContains(t, err, tc.expectedError.Error())
				assert.Empty(t, token)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedToken, token)
			}

			d.token.AssertExpectations(t)
		})
	}
}

func TestValidate(t *testing.T) {
	t.Parallel()

	testClaims := mockClaims()

	testCases := []struct {
		name          string
		accessToken   string
		mockSetup     func(*authTestDeps)
		expectedError error
	}{
		{
			name:        "Successful validation",
			accessToken: "valid-token",
			mockSetup: func(d *authTestDeps) {
				d.token.On("ValidateJWT", "valid-token").
					Return(testClaims, nil)
			},
			expectedError: nil,
		},
		{
			name:        "Empty token",
			accessToken: "",
			mockSetup: func(d *authTestDeps) {
				// No expectations for empty token
			},
			expectedError: customerrors.ErrBadRequest,
		},
		{
			name:        "Invalid token",
			accessToken: invalidToken,
			mockSetup: func(d *authTestDeps) {
				d.token.On("ValidateJWT", invalidToken).
					Return(nil, jwt.ErrSignatureInvalid)
			},
			expectedError: jwt.ErrSignatureInvalid,
		},
		{
			name:        "Expired token",
			accessToken: "expired-token",
			mockSetup: func(d *authTestDeps) {
				d.token.On("ValidateJWT", "expired-token").
					Return(nil, jwt.ErrTokenExpired)
			},
			expectedError: jwt.ErrTokenExpired,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d := setupAuthTest(t)
			defer d.cleanup()

			if tc.mockSetup != nil {
				tc.mockSetup(d)
			}

			_, err := d.service.Validate(tc.accessToken)

			if tc.expectedError != nil {
				assert.ErrorContains(t, err, tc.expectedError.Error())
			} else {
				assert.NoError(t, err)
			}

			d.token.AssertExpectations(t)
		})
	}
}

func TestHealthCheck(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		mockSetup     func(*authTestDeps)
		expectedError error
	}{
		{
			name: "Healthy service",
			mockSetup: func(d *authTestDeps) {
				d.repoMock.ExpectPing().WillReturnError(nil)
			},
			expectedError: nil,
		},
		{
			name: "Database unreachable",
			mockSetup: func(d *authTestDeps) {
				d.repoMock.ExpectPing().WillReturnError(errors.New("connection failed"))
			},
			expectedError: customerrors.ErrDbUnreacheable,
		},
		{
			name: "Context timeout",
			mockSetup: func(d *authTestDeps) {
				d.repoMock.ExpectPing().WillReturnError(context.DeadlineExceeded)
			},
			expectedError: customerrors.ErrDbTimeout,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			d := setupAuthTest(t)
			defer d.cleanup()

			if tc.mockSetup != nil {
				tc.mockSetup(d)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()

			err := d.service.HealthCheck(ctx)

			if tc.expectedError != nil {
				assert.ErrorIs(t, err, tc.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
