<div align="center">

# go-gRPC-Authentication

[![Go](https://img.shields.io/badge/Go-1.24.3+-00ADD8?logo=go)](https://golang.org)
[![Docker](https://img.shields.io/badge/Docker-2496ED?logo=docker&logoColor=white)](https://www.docker.com/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-4169E1?logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![Flyway](https://img.shields.io/badge/Flyway-CC0200?logo=flyway&logoColor=white)](https://flywaydb.org/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![SonarCloud](https://img.shields.io/badge/SonarCloud-F3702A?logo=sonarcloud&logoColor=white)](https://sonarcloud.io/)
[![Build Status](https://img.shields.io/github/actions/workflow/status/taekwondodev/go-gRPC-Authentication/docker-publish.yml?branch=master&logo=github&label=Build)](https://github.com/taekwondodev/go-gRPC-Authentication/actions)
[![Latest Tag](https://img.shields.io/github/v/tag/taekwondodev/go-gRPC-Authentication?logo=git&color=green&label=Latest%20Tag)](https://github.com/taekwondodev/go-gRPC-Authentication/tags)

Authentication Microservice gRPC in Go with JWT, Docker, PostgreSQL and End-to-End Encryption

</div>

## Features

- gRPC API with Protocol Buffers
- gRPC interceptors for error handling and logging
- JWT Authentication (Access + Refresh tokens)
- PostgreSQL with TLS 1.3 (verify-full mode)
- Docker with internal network isolation
- Flyway migrations with certificate verification
- Unit testing
- Hardware-grade encryption for database connections

## Requirements

- Install [Docker](https://docs.docker.com/engine/install/)

**Note: For local development also:**

- Install Go:

```bash
# Linux
sudo apt install golang-go

# MacOS
brew install go
```

- Install protoc compiler:

```bash
# Linux
apt install -y protobuf-compiler

# MacOS
brew install protobuf
```

- Install go protobuf plugins:

```bash
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.28
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.2

# Add the PATH in the configuration terminal file
export PATH="$PATH:$(go env GOPATH)/bin"
```

## gRPC Services

The service exposes the following gRPC methods:

```protobuf
service AuthService {
  rpc Register (RegisterRequest) returns (AuthResponse);
  rpc Login (LoginRequest) returns (AuthResponse);
  rpc RefreshToken (RefreshTokenRequest) returns (AuthResponse);
  rpc ValidateToken (ValidateTokenRequest) returns (ValidateTokenResponse);
  rpc Healthz(HealthzRequest) returns (HealthzResponse);
}
```

For complete proto definition see: proto/auth.proto

## Usage

1. Download the docker-compose.yml and the configuration script files:

```bash
# Create a directory for the project
mkdir auth && cd auth

# Download the compose file
curl -O https://raw.githubusercontent.com/taekwondodev/go-gRPC-Authentication/master/docker-compose.yml

# Download the setup.sh file
curl -O https://raw.githubusercontent.com/taekwondodev/go-gRPC-Authentication/master/setup.sh
```

Or

Clone the project (local development):

```bash
git clone https://github.com/taekwondodev/go-gRPC-Authentication.git
```

## Configuration

Run the command in the main directory:

```bash
./setup.sh
```

## Deployment

Run the command in the main directory:

```bash
docker compose up -d
```

## Project Structure

```
go-gRPC-Authentication/
├── app/
│   ├── gen/                                  # Generated Protobuf files
|   |   ├── auth_grpc.pb.go
|   |   ├── auth.pb.go
│   ├── internal/
|   |   ├── auth/
|   |   |   ├── grpc/                         # gRPC Handlers
|   |   |   |   ├── server.go
|   |   |   |   ├── server_test.go
|   |   |   ├── repository/                   # Database Interaction
|   |   |   |   ├── authRepository.go
|   |   |   |   ├── authRepository_test.go
|   |   |   ├── service/                      # Business Logic
|   |   |   |   ├── authService.go
|   |   |   |   ├── authService_test.go
|   |   ├── config/                           # Configuration
|   |   |   ├── grpcServer.go
|   |   |   ├── jwt.go
|   |   |   ├── postgres.go
|   |   ├── customErrors/                     # Custom Errors
|   |   |   ├── errors.go
|   |   ├── interceptors/                     # gRPC Interceptors
|   |   |   ├── handleErrors.go
|   |   |   ├── logging.go
|   |   ├── models/                           # Database Models
|   |   |   ├── user.go
|   ├── proto/
|   |   ├── auth.proto                        # Protocol buffers definition
|   ├── Dockerfile
|   ├── go.mod
|   ├── main.go
├── migrations/                               # SQL Script Migrations
├── postgres/                                 # SSL Certificates
├── docker-compose.yml
```

## Testing

To test the repository with automated test run the command in the app directory:

```bash
go test -v -mod=readonly ./...
```

**Note: Only for local development**
