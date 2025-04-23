package api

import (
	"backend/controller"
	"backend/middleware"
	"net/http"
)

var router *http.ServeMux

func SetupRoutes(authController *controller.AuthController) *http.ServeMux {
	router = http.NewServeMux()

	setupAuthRoutes(authController)
	setupSystemRoutes(authController)

	return router
}

func applyMiddleware(h middleware.HandlerFunc) http.HandlerFunc {
	return middleware.ErrorHandler(
		middleware.TrustProxyMiddleware(
			middleware.LoggingMiddleware(h),
		),
	)
}

func setupAuthRoutes(authController *controller.AuthController) {
	router.Handle("POST /register", applyMiddleware(authController.Register))
	router.Handle("POST /login", applyMiddleware(authController.Login))
	router.Handle("POST /refresh", applyMiddleware(authController.Refresh))
}

func setupSystemRoutes(authController *controller.AuthController) {
	router.Handle("GET /healthz", applyMiddleware(authController.HealthCheck))
}
