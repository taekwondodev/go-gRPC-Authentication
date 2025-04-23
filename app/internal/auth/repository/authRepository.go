package repository

import (
	customerrors "app/internal/customErrors"
	"app/internal/models"
	"database/sql"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type UserRepository interface {
	CheckUserExists(username, email string) error
	SaveUser(username, password, email, role string) (uuid.UUID, error)
	GetUserByCredentials(username, password string) (*models.User, error)
}

type UserRepositoryImpl struct {
	db *sql.DB
}

func NewUserRepository(db *sql.DB) UserRepository {
	return &UserRepositoryImpl{db: db}
}

func (r *UserRepositoryImpl) CheckUserExists(username, email string) error {
	query := `
        SELECT 
            EXISTS(SELECT 1 FROM users WHERE username = $1) AS username_exists,
            EXISTS(SELECT 1 FROM users WHERE email = $2) AS email_exists
    `
	var usernameExists, emailExists bool
	err := r.db.QueryRow(query, username, email).Scan(&usernameExists, &emailExists)
	if err != nil {
		return err
	}

	switch {
	case usernameExists:
		return customerrors.ErrUsernameAlreadyExists
	case emailExists:
		return customerrors.ErrEmailAlreadyExists
	default:
		return nil
	}
}

func (r *UserRepositoryImpl) SaveUser(username, password, email, role string) (uuid.UUID, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return uuid.Nil, err
	}

	query := "INSERT INTO users (username, email, password_hash, role) VALUES ($1, $2, $3, $4) RETURNING sub"
	var sub uuid.UUID
	err = r.db.QueryRow(
		query,
		username,
		email,
		string(hashedPassword),
		role,
	).Scan(&sub)

	if err != nil {
		return uuid.Nil, err
	}

	return sub, nil
}

func (r *UserRepositoryImpl) GetUserByCredentials(username, password string) (*models.User, error) {
	var user models.User
	query := `
        SELECT sub, username, email, password_hash, role, created_at, updated_at, is_active
        FROM users
        WHERE username = $1
    `

	err := r.db.QueryRow(query, username).Scan(
		&user.Sub,
		&user.Username,
		&user.Email,
		&user.PasswordHash,
		&user.Role,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.IsActive,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, customerrors.ErrUserNotFound
		}
		return nil, err
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	if err != nil {
		if err == bcrypt.ErrMismatchedHashAndPassword {
			return nil, customerrors.ErrInvalidCredentials
		}
		return nil, err
	}

	return &user, nil
}
