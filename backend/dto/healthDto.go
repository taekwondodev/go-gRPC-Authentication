package dto

type HealthResponse struct {
	Status   string `json:"status"`
	Database string `json:"database"`
	SslMode  string `json:"ssl_mode"`
}
