package dto

import "github.com/go-playground/validator/v10"

type AuthRequest struct {
	Username string `json:"username" validate:"required"`
	Password string `json:"password" validate:"required,min=8"`
	Email    string `json:"email" validate:"omitzero,email"`
	Role     string `json:"role" validate:"omitzero"`
}

func (a *AuthRequest) Validate() error {
	validate := validator.New()
	return validate.Struct(a)
}

type AuthResponse struct {
	Message      string `json:"message"`
	AccessToken  string `json:"accessToken,omitzero"`
	RefreshToken string `json:"refreshToken,omitzero"`
}
