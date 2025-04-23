package middleware

import "net/http"

func TrustProxyMiddleware(next HandlerFunc) HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		// 1. Check if the request is coming from a trusted proxy
		if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
			r.URL.Scheme = proto
		}

		// 2. Fix the host
		if host := r.Header.Get("X-Forwarded-Host"); host != "" {
			r.Host = host
		}

		// 3. Next handler
		return next(w, r)
	}
}
