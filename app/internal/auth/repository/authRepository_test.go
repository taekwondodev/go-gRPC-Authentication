package repository_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"

	"app/internal/auth/repository"
	customerrors "app/internal/customErrors"
	"app/internal/models"
)

const (
	testUsername  = "testuser"
	testPassword  = "password123!"
	testEmail     = "test@example.com"
	testRole      = "user"
	databaseError = "Database error"
)

var testUUID = uuid.New()

type testDependencies struct {
	repo    *repository.UserRepositoryImpl
	mock    sqlmock.Sqlmock
	cleanup func()
}

func setupTest(t *testing.T) *testDependencies {
	db, mock, err := sqlmock.New(
		sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual),
		sqlmock.MonitorPingsOption(true),
	)
	assert.NoError(t, err)

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
		`SELECT EXISTS(SELECT 1 FROM users WHERE username = $1) AS username_exists, ` +
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
			username: testUsername,
			email:    testEmail,
			mockSetup: func(m sqlmock.Sqlmock) {
				mockExistsQuery(m, false, false)
			},
			expectedError: nil,
		},
		{
			name:     "Username exists",
			username: testUsername,
			email:    testEmail,
			mockSetup: func(m sqlmock.Sqlmock) {
				mockExistsQuery(m, true, false)
			},
			expectedError: customerrors.ErrUsernameAlreadyExists,
		},
		{
			name:     "Email exists",
			username: testUsername,
			email:    testEmail,
			mockSetup: func(m sqlmock.Sqlmock) {
				mockExistsQuery(m, false, true)
			},
			expectedError: customerrors.ErrEmailAlreadyExists,
		},
		{
			name:     "Username and email exists",
			username: testUsername,
			email:    testEmail,
			mockSetup: func(m sqlmock.Sqlmock) {
				mockExistsQuery(m, true, true)
			},
			expectedError: customerrors.ErrUsernameAlreadyExists,
		},
		{
			name:     databaseError,
			username: testUsername,
			email:    testEmail,
			mockSetup: func(m sqlmock.Sqlmock) {
				m.ExpectQuery(
					`SELECT EXISTS(SELECT 1 FROM users WHERE username = $1) AS username_exists, ` +
						`EXISTS(SELECT 1 FROM users WHERE email = $2) AS email_exists`,
				).WillReturnError(customerrors.ErrInternalServer)
			},
			expectedError: customerrors.ErrInternalServer,
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
			username: testUsername,
			password: testPassword,
			email:    testEmail,
			role:     testRole,
			mockSetup: func(m sqlmock.Sqlmock) {
				m.ExpectQuery(
					`INSERT INTO users (username, email, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING sub`,
				).WithArgs(
					testUsername, testEmail, sqlmock.AnyArg(), testRole,
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
			username: testUsername,
			password: testPassword,
			email:    testEmail,
			role:     testRole,
			mockSetup: func(m sqlmock.Sqlmock) {
				m.ExpectQuery(
					`INSERT INTO users (username, email, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING sub`,
				).WithArgs(
					testUsername, testEmail, sqlmock.AnyArg(), testRole,
				).WillReturnError(customerrors.ErrInternalServer)
			},
			expectedUUID:  uuid.Nil,
			expectedError: customerrors.ErrInternalServer,
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
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(testPassword), bcrypt.DefaultCost)

	testUser := models.User{
		Sub:          testUUID,
		Username:     testUsername,
		Email:        testEmail,
		PasswordHash: string(hashedPassword),
		Role:         testRole,
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
			username: testUsername,
			password: testPassword,
			mockSetup: func(m sqlmock.Sqlmock) {
				m.ExpectQuery(
					`SELECT sub, username, email, password_hash, role, created_at, updated_at, is_active ` +
						`FROM users WHERE username = $1`,
				).WithArgs(testUsername).WillReturnRows(mockUserRow(m, testUser))
			},
			expectedUser:  &testUser,
			expectedError: nil,
		},
		{
			name:     "User not found",
			username: testUsername,
			password: testPassword,
			mockSetup: func(m sqlmock.Sqlmock) {
				m.ExpectQuery(
					`SELECT sub, username, email, password_hash, role, created_at, updated_at, is_active ` +
						`FROM users WHERE username = $1`,
				).WithArgs(testUsername).WillReturnError(sql.ErrNoRows)
			},
			expectedUser:  nil,
			expectedError: customerrors.ErrUserNotFound,
		},
		{
			name:     "Wrong password",
			username: testUsername,
			password: "wrongpassword",
			mockSetup: func(m sqlmock.Sqlmock) {
				m.ExpectQuery(
					`SELECT sub, username, email, password_hash, role, created_at, updated_at, is_active ` +
						`FROM users WHERE username = $1`,
				).WithArgs(testUsername).WillReturnRows(mockUserRow(m, testUser))
			},
			expectedUser:  nil,
			expectedError: customerrors.ErrInvalidCredentials,
		},
		{
			name:     databaseError,
			username: testUsername,
			password: testPassword,
			mockSetup: func(m sqlmock.Sqlmock) {
				m.ExpectQuery(
					`SELECT sub, username, email, password_hash, role, created_at, updated_at, is_active ` +
						`FROM users WHERE username = $1`,
				).WithArgs("testuser").WillReturnError(customerrors.ErrInternalServer)
			},
			expectedUser:  nil,
			expectedError: customerrors.ErrInternalServer,
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
				m.ExpectPing().WillReturnError(customerrors.ErrDbSSLHandshakeFailed)
			},
			expectedError: customerrors.ErrDbSSLHandshakeFailed,
		},
		{
			name: "Generic error",
			ctx:  context.Background(),
			mockSetup: func(m sqlmock.Sqlmock) {
				m.ExpectPing().WillReturnError(customerrors.ErrDbUnreacheable)
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
