package repository_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"app/internal/auth/repository"
	customerrors "app/internal/customErrors"
	"app/internal/models"
)

type testDependencies struct {
	repo    *repository.UserRepositoryImpl
	mock    sqlmock.Sqlmock
	cleanup func()
}

const newEmail = "new@test.com"
const databaseError = "Database error"
const dbError = "db error"

func setupTest(t *testing.T) *testDependencies {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	require.NoError(t, err, "Error mocking DB")

	repo := repository.NewUserRepository(db).(*repository.UserRepositoryImpl)

	return &testDependencies{
		repo: repo,
		mock: mock,
		cleanup: func() {
			assert.NoError(t, mock.ExpectationsWereMet(), "Expectations were not met")
			db.Close()
		},
	}
}

func mockUserRow(mock sqlmock.Sqlmock, user models.User) *sqlmock.Rows {
	return mock.NewRows([]string{
		"sub", "username", "email", "password_hash", "role",
		"created_at", "updated_at", "is_active",
	}).AddRow(
		user.Sub, user.Username, user.Email, user.PasswordHash, user.Role,
		user.CreatedAt, user.UpdatedAt, user.IsActive,
	)
}

func mockExistsQuery(mock sqlmock.Sqlmock, usernameExists, emailExists bool) {
	mock.ExpectQuery(
		`SELECT EXISTS(SELECT 1 FROM users WHERE username = $1) AS username_exists,` +
			`EXISTS(SELECT 1 FROM users WHERE email = $2) AS email_exists`,
	).WillReturnRows(
		sqlmock.NewRows([]string{"username_exists", "email_exists"}).
			AddRow(usernameExists, emailExists),
	)
}

func TestCheckUserExists(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		username      string
		email         string
		mockSetup     func(sqlmock.Sqlmock)
		expectedError error
	}{
		{
			name:     "User does not exist",
			username: "newuser",
			email:    newEmail,
			mockSetup: func(m sqlmock.Sqlmock) {
				mockExistsQuery(m, false, false)
			},
			expectedError: nil,
		},
		{
			name:     "Username exists",
			username: "existing",
			email:    newEmail,
			mockSetup: func(m sqlmock.Sqlmock) {
				mockExistsQuery(m, true, false)
			},
			expectedError: customerrors.ErrUsernameAlreadyExists,
		},
		{
			name:     "Email exists",
			username: "newuser",
			email:    "existing@test.com",
			mockSetup: func(m sqlmock.Sqlmock) {
				mockExistsQuery(m, false, true)
			},
			expectedError: customerrors.ErrEmailAlreadyExists,
		},
		{
			name:     databaseError,
			username: "user",
			email:    "email@test.com",
			mockSetup: func(m sqlmock.Sqlmock) {
				m.ExpectQuery(
					`SELECT EXISTS(SELECT 1 FROM users WHERE username = $1) AS username_exists,` +
						`EXISTS(SELECT 1 FROM users WHERE email = $2) AS email_exists`,
				).WillReturnError(errors.New(dbError))
			},
			expectedError: errors.New(dbError),
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			td := setupTest(t)
			defer td.cleanup()

			tc.mockSetup(td.mock)

			err := td.repo.CheckUserExists(tc.username, tc.email)

			if tc.expectedError != nil {
				assert.ErrorContains(t, err, tc.expectedError.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSaveUser(t *testing.T) {
	t.Parallel()

	testUUID := uuid.New()
	validPassword := "validPassword123"
	invalidPassword := string(make([]byte, 73))

	testCases := []struct {
		name          string
		username      string
		password      string
		email         string
		role          string
		mockSetup     func(sqlmock.Sqlmock)
		expectedUUID  uuid.UUID
		expectedError error
	}{
		{
			name:     "Success case",
			username: "newuser",
			password: validPassword,
			email:    newEmail,
			role:     "user",
			mockSetup: func(m sqlmock.Sqlmock) {
				m.ExpectQuery(
					`INSERT INTO users (username, email, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING sub`,
				).WithArgs(
					"newuser", newEmail, sqlmock.AnyArg(), "user",
				).WillReturnRows(
					sqlmock.NewRows([]string{"sub"}).AddRow(testUUID),
				)
			},
			expectedUUID:  testUUID,
			expectedError: nil,
		},
		{
			name:     "Invalid password length",
			password: invalidPassword,
			mockSetup: func(m sqlmock.Sqlmock) {
				// No expectations
			},
			expectedUUID:  uuid.Nil,
			expectedError: bcrypt.ErrPasswordTooLong,
		},
		{
			name:     databaseError,
			username: "newuser",
			password: validPassword,
			email:    newEmail,
			role:     "user",
			mockSetup: func(m sqlmock.Sqlmock) {
				m.ExpectQuery(
					`INSERT INTO users (username, email, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING sub`,
				).WithArgs(
					"newuser", newEmail, sqlmock.AnyArg(), "user",
				).WillReturnError(errors.New(dbError))
			},
			expectedUUID:  uuid.Nil,
			expectedError: errors.New(dbError),
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			td := setupTest(t)
			defer td.cleanup()

			tc.mockSetup(td.mock)

			userUUID, err := td.repo.SaveUser(tc.username, tc.password, tc.email, tc.role)

			if tc.expectedError != nil {
				assert.ErrorContains(t, err, tc.expectedError.Error())
			} else {
				assert.NoError(t, err)
			}

			assert.Equal(t, tc.expectedUUID, userUUID)
		})
	}
}

func TestGetUserByCredentials(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	testUUID := uuid.New()
	correctPassword := "correctPassword123"
	wrongPassword := "wrongPassword"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(correctPassword), bcrypt.DefaultCost)

	testUser := models.User{
		Sub:          testUUID,
		Username:     "testuser",
		Email:        "test@test.com",
		PasswordHash: string(hashedPassword),
		Role:         "user",
		CreatedAt:    now,
		UpdatedAt:    now,
		IsActive:     true,
	}

	testCases := []struct {
		name          string
		username      string
		password      string
		mockSetup     func(sqlmock.Sqlmock)
		expectedUser  *models.User
		expectedError error
	}{
		{
			name:     "Success case",
			username: "testuser",
			password: correctPassword,
			mockSetup: func(m sqlmock.Sqlmock) {
				m.ExpectQuery(
					`SELECT sub, username, email, password_hash, role, created_at, updated_at, is_active ` +
						`FROM users WHERE username = $1`,
				).WithArgs("testuser").WillReturnRows(mockUserRow(m, testUser))
			},
			expectedUser:  &testUser,
			expectedError: nil,
		},
		{
			name:     "User not found",
			username: "nonexistent",
			password: "anypassword",
			mockSetup: func(m sqlmock.Sqlmock) {
				m.ExpectQuery(
					`SELECT sub, username, email, password_hash, role, created_at, updated_at, is_active ` +
						`FROM users WHERE username = $1`,
				).WithArgs("nonexistent").WillReturnError(sql.ErrNoRows)
			},
			expectedUser:  nil,
			expectedError: customerrors.ErrUserNotFound,
		},
		{
			name:     "Wrong password",
			username: "testuser",
			password: wrongPassword,
			mockSetup: func(m sqlmock.Sqlmock) {
				m.ExpectQuery(
					`SELECT sub, username, email, password_hash, role, created_at, updated_at, is_active ` +
						`FROM users WHERE username = $1`,
				).WithArgs("testuser").WillReturnRows(mockUserRow(m, testUser))
			},
			expectedUser:  nil,
			expectedError: customerrors.ErrInvalidCredentials,
		},
		{
			name:     databaseError,
			username: "testuser",
			password: correctPassword,
			mockSetup: func(m sqlmock.Sqlmock) {
				m.ExpectQuery(
					`SELECT sub, username, email, password_hash, role, created_at, updated_at, is_active ` +
						`FROM users WHERE username = $1`,
				).WithArgs("testuser").WillReturnError(errors.New(dbError))
			},
			expectedUser:  nil,
			expectedError: errors.New(dbError),
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			td := setupTest(t)
			defer td.cleanup()

			tc.mockSetup(td.mock)

			user, err := td.repo.GetUserByCredentials(tc.username, tc.password)

			if tc.expectedError != nil {
				assert.ErrorContains(t, err, tc.expectedError.Error())
			} else {
				assert.NoError(t, err)
			}

			assert.Equal(t, tc.expectedUser, user)
		})
	}
}

func TestHealtz(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		ctx           context.Context
		mockSetup     func(sqlmock.Sqlmock)
		expectedError error
	}{
		{
			name: "Healthy database",
			ctx:  context.Background(),
			mockSetup: func(m sqlmock.Sqlmock) {
				m.ExpectPing().WillReturnError(nil)
			},
			expectedError: nil,
		},
		{
			name: "SSL error",
			ctx:  context.Background(),
			mockSetup: func(m sqlmock.Sqlmock) {
				m.ExpectPing().WillReturnError(errors.New("SSL connection failed"))
			},
			expectedError: customerrors.ErrDbSSLHandshakeFailed,
		},
		{
			name: "Timeout error",
			ctx: func() context.Context {
				ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
				time.Sleep(2 * time.Nanosecond)
				cancel()
				return ctx
			}(),
			mockSetup: func(m sqlmock.Sqlmock) {
				m.ExpectPing().WillReturnError(context.DeadlineExceeded)
			},
			expectedError: customerrors.ErrDbTimeout,
		},
		{
			name: "Generic error",
			ctx:  context.Background(),
			mockSetup: func(m sqlmock.Sqlmock) {
				m.ExpectPing().WillReturnError(errors.New("connection refused"))
			},
			expectedError: customerrors.ErrDbUnreacheable,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			td := setupTest(t)
			defer td.cleanup()

			tc.mockSetup(td.mock)

			err := td.repo.Healtz(tc.ctx)

			if tc.expectedError != nil {
				assert.ErrorIs(t, err, tc.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
