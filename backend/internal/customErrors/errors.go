package customerrors

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string {
	return fmt.Sprintf("%d: %s", e.Code, e.Message)
}

var (
	ErrUsernameAlreadyExists = &Error{Code: 409, Message: "username already exists"}
	ErrEmailAlreadyExists    = &Error{Code: 409, Message: "email already exists"}
	ErrInvalidCredentials    = &Error{Code: 401, Message: "invalid credentials"}
	ErrUserNotFound          = &Error{Code: 404, Message: "user not found"}
	ErrHttpMethodNotAllowed  = &Error{Code: 405, Message: "http method not allowed"}
	ErrBadRequest            = &Error{Code: 400, Message: "bad request"}
	ErrInternalServer        = &Error{Code: 500, Message: "internal server error"}
	ErrDbUnreacheable        = &Error{Code: 503, Message: "database unreachable"}
	ErrDbSSLHandshakeFailed  = &Error{Code: 502, Message: "database SSL handshake failed"}
	ErrDbTimeout             = &Error{Code: 504, Message: "database timeout"}
)

func GetStatus(err error) int {
	if customErr, ok := err.(*Error); ok {
		return customErr.Code
	}

	switch {
	case err == jwt.ErrSignatureInvalid, err == jwt.ErrTokenExpired:
		return 401

	default:
		return 500
	}
}

func GetMessage(err error) string {
	if customErr, ok := err.(*Error); ok {
		return customErr.Message
	} else {
		return err.Error()
	}
}
