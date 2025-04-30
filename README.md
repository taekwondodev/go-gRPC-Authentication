# go-gRPC-Authentication
[![Go](https://img.shields.io/badge/Go-1.24.2+-00ADD8?logo=go)](https://golang.org)

Authentication Microservice gRPC in Go with JWT, Docker, PostgreSQL and End-to-End Encryption

## Features
- gRPC API with Protocol Buffers
- JWT Authentication (Access + Refresh tokens)
- PostgreSQL with TLS 1.3 (verify-full mode)  
- Docker with internal network isolation 
- Flyway migrations with certificate verification  
- Unit testing  
- Hardware-grade encryption for database connections
- gRPC interceptors for error handling and logging

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
docker build -f Dockerfile.test -t myapp-test .
docker run --rm myapp-test
```

**Note: Only for local development**