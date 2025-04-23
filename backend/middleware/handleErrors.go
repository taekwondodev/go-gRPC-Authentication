package middleware

import (
	customerrors "backend/customErrors"
	"encoding/json"
	"net/http"
)

type HandlerFunc func(w http.ResponseWriter, r *http.Request) error

func ErrorHandler(h HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := h(w, r); err != nil {
			handleHttpError(w, err)
		}
	}
}

func handleHttpError(w http.ResponseWriter, err error) {
	status := customerrors.GetStatus(err)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	res := &customerrors.Error{
		Code:    status,
		Message: customerrors.GetMessage(err),
	}

	json.NewEncoder(w).Encode(res)
}
