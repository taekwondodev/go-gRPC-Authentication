package test

import (
	customerrors "backend/customErrors"
	"backend/repository"
	"database/sql"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

const (
	existQuery      = "SELECT EXISTS"
	selectUserQuery = "SELECT id, username, email, password_hash, role, created_at, updated_at, is_active FROM users WHERE username = \\$1"
	emailString     = "example@domain.com"
	date            = "2023-01-01"
	defaultRole     = "user"
)

// Test setup helper
func setupMockRepo(t *testing.T) (*sql.DB, sqlmock.Sqlmock, repository.UserRepository) {
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)
	repo := repository.NewUserRepository(db)
	return db, mock, repo
}

// Helper for CheckUserExists scenarios
func testCheckUserExists(t *testing.T, usernameExists, emailExists bool, expectedErr error) {
	db, mock, repo := setupMockRepo(t)
	defer db.Close()

	username := "testuser"
	email := "testemail@example.com"

	if expectedErr == sql.ErrConnDone {
		mock.ExpectQuery(existQuery).WithArgs(username, email).WillReturnError(sql.ErrConnDone)
	} else {
		rows := sqlmock.NewRows([]string{"username_exists", "email_exists"}).AddRow(usernameExists, emailExists)
		mock.ExpectQuery(existQuery).WithArgs(username, email).WillReturnRows(rows)
	}

	err := repo.CheckUserExists(username, email)

	if expectedErr != nil {
		assert.Error(t, err)
		if expectedErr != sql.ErrConnDone {
			assert.Equal(t, expectedErr, err)
		}
	} else {
		assert.NoError(t, err)
	}
}

func TestCheckUserExistsScenarios(t *testing.T) {
	testCases := []struct {
		name           string
		usernameExists bool
		emailExists    bool
		expectedErr    error
	}{
		{"UsernameExists", true, false, customerrors.ErrUsernameAlreadyExists},
		{"EmailExists", false, true, customerrors.ErrEmailAlreadyExists},
		{"BothExist", true, true, customerrors.ErrUsernameAlreadyExists}, // Username error takes precedence
		{"NoneExist", false, false, nil},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			testCheckUserExists(t, tc.usernameExists, tc.emailExists, tc.expectedErr)
		})
	}
}

func TestCheckUserExistsDbError(t *testing.T) {
	testCheckUserExists(t, false, false, sql.ErrConnDone)
}

// Helper for SaveUser scenarios
func testSaveUser(t *testing.T, role string, shouldError bool) {
	db, mock, repo := setupMockRepo(t)
	defer db.Close()

	username := "testuser"
	password := "password123"

	if shouldError {
		mock.ExpectExec("INSERT INTO users").
			WithArgs(username, emailString, sqlmock.AnyArg(), role).
			WillReturnError(sql.ErrConnDone)
	} else {
		mock.ExpectExec("INSERT INTO users \\(username, email, password_hash, role\\) VALUES \\(\\$1, \\$2, \\$3, \\$4\\)").
			WithArgs(username, emailString, sqlmock.AnyArg(), role).
			WillReturnResult(sqlmock.NewResult(1, 1))
	}

	err := repo.SaveUser(username, password, emailString, role)

	if shouldError {
		assert.Error(t, err)
	} else {
		assert.NoError(t, err)
	}
}

func TestSaveUserScenarios(t *testing.T) {
	testCases := []struct {
		name        string
		role        string
		shouldError bool
	}{
		{"EmptyRole", "", false},
		{"WithRole", "admin", false},
		{"DbError", "", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			testSaveUser(t, tc.role, tc.shouldError)
		})
	}
}

// Helper for GetUserByCredentials scenarios
func testGetUserByCredentials(t *testing.T, role string, wrongPassword bool, dbError error) {
	db, mock, repo := setupMockRepo(t)
	defer db.Close()

	username := "testuser"
	password := "password123"
	usePassword := password

	if wrongPassword {
		usePassword = "wrongpassword"
	}

	columns := []string{"id", "username", "email", "password_hash", "role", "created_at", "updated_at", "is_active"}

	if dbError != nil {
		mock.ExpectQuery(selectUserQuery).
			WithArgs(username).
			WillReturnError(dbError)
	} else {
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		mock.ExpectQuery(selectUserQuery).
			WithArgs(username).
			WillReturnRows(
				sqlmock.NewRows(columns).
					AddRow(1, username, emailString, string(hashedPassword), role, date, date, true),
			)
	}

	user, err := repo.GetUserByCredentials(username, usePassword)

	if dbError != nil || wrongPassword {
		assert.Error(t, err)
		assert.Nil(t, user)
	} else {
		assert.NoError(t, err)
		assert.NotNil(t, user)
		assert.Equal(t, username, user.Username)
		assert.Equal(t, role, user.Role)
	}
}

func TestGetUserByCredentialsScenarios(t *testing.T) {
	testCases := []struct {
		name          string
		role          string
		wrongPassword bool
		dbError       error
	}{
		{"CorrectCredentials", defaultRole, false, nil},
		{"AdminRole", "admin", false, nil},
		{"IncorrectPassword", defaultRole, true, nil},
		{"UserNotFound", defaultRole, false, sql.ErrNoRows},
		{"DbError", defaultRole, false, sql.ErrConnDone},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			testGetUserByCredentials(t, tc.role, tc.wrongPassword, tc.dbError)
		})
	}
}
