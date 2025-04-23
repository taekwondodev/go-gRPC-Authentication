package customerrors

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

type Error struct {
	Code    int
	Message string
}

func (e *Error) Error() string {
	return fmt.Sprintf("rpc error: code = %d desc = %s", e.Code, e.Message)
}

var (
	ErrUsernameAlreadyExists = &Error{Code: 6, Message: "username already exists"}
	ErrEmailAlreadyExists    = &Error{Code: 6, Message: "email already exists"}
	ErrInvalidCredentials    = &Error{Code: 16, Message: "invalid credentials"}
	ErrUserNotFound          = &Error{Code: 5, Message: "user not found"}
	ErrHttpMethodNotAllowed  = &Error{Code: 12, Message: "http method not allowed"}
	ErrBadRequest            = &Error{Code: 3, Message: "bad request"}
	ErrInvalidEmail          = &Error{Code: 3, Message: "invalid email"}
	ErrInvalidPassword       = &Error{Code: 3, Message: "password must be at least 8 characters long, contain at least one uppercase letter, one lowercase letter, one number, and one special character"}
	ErrInternalServer        = &Error{Code: 13, Message: "internal server error"}
	ErrDbUnreacheable        = &Error{Code: 14, Message: "database unreachable"}
	ErrDbSSLHandshakeFailed  = &Error{Code: 14, Message: "database SSL handshake failed"}
	ErrDbTimeout             = &Error{Code: 14, Message: "database timeout"}
)

func GetCode(err error) int {
	if customErr, ok := err.(*Error); ok {
		return customErr.Code
	}

	switch {
	case err == jwt.ErrSignatureInvalid, err == jwt.ErrTokenExpired:
		return 16

	default:
		return 13
	}
}

func GetMessage(err error) string {
	if customErr, ok := err.(*Error); ok {
		return customErr.Message
	} else {
		return err.Error()
	}
}
