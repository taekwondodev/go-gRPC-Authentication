# go-REST-Authentication
[![Go](https://img.shields.io/badge/Go-1.24.2+-00ADD8?logo=go)](https://golang.org)

Auth Microservice gRPC in Go with JWT, Docker, PostgreSQL and End-to-End TLS Encryption

## API Endpoints

[![Open in Swagger Editor](https://img.shields.io/badge/Swagger-Editor-%23Clojure?style=for-the-badge&logo=swagger)](https://editor.swagger.io/?url=https://raw.githubusercontent.com/taekwondodev/go-REST-Authentication/master/backend/api/openapi.yaml)

- [Raw OpenAPI Spec](./backend/api/openapi.yaml)

## Features
- JWT Authentication (Access + Refresh tokens)
- PostgreSQL with TLS 1.3 (verify-full mode)  
- Docker with internal network isolation 
- Flyway migrations with certificate verification  
- Unit testing  
- Hardware-grade encryption for database connections

## Requirements

- Install [Docker](https://docs.docker.com/engine/install/)
- Install [Go](https://go.dev/dl/) (optional, only for local development)

## Usage

### Microservice

1. Download the docker-compose.yml and the migration script files:
  ```bash
  # Create a directory for the project
  mkdir auth && cd auth

  # Download the compose file
  curl -O https://raw.githubusercontent.com/taekwondodev/go-REST-Authentication/microservice/docker-compose.yml

  # Create the migration directory
  mkdir -p migrations && cd migrations

  # Download the script sql file
  curl -O https://raw.githubusercontent.com/taekwondodev/go-REST-Authentication/microservice/migrations/V1__Create_User_table.sql
  ```
  Or

  Clone the project:
   
  ```bash
  git clone https://github.com/taekwondodev/go-REST-Template.git
  ```

### Template

  Clone the project:

  ```bash
  git clone https://github.com/taekwondodev/go-REST-Template.git
  ```

### Configuration

### Deployment

Run the command in the main directory:
   
  ```bash
  docker compose up -d
  ```

## Project Structure

```
go-REST-template/
├── backend/
│   ├── api/             # Handle Server and Router Configs
│   ├── config/          # Application configuration (JWT, Database, Environment Variables)
│   ├── controller/      # Handle HTTP Requests
│   ├── customErrors/    # Handle Custom Errors
│   ├── dto/             # Data Transfer Objects (Request and Response)
│   ├── middleware/      # Middleware
│   ├── models/          # Database Models
│   ├── repository/      # Handle Database Interaction
│   ├── service/         # Handle Controller Business Logic
│   ├── Dockerfile       
│   ├── go.mod           
│   ├── go.sum           
│   ├── main.go  
├── migrations/          # SQL Script Migrations
├── postgres/            # SSL Certificates  
├── test/                # Unit Testing    
├── Dockerfile.test        
├── docker-compose.yml   
```

**Note**: If you run this repo as a Microservice you can skip this.

## Testing

To test the repository with automated test run the command in the main directory:

```bash
# Build the image
docker build -f Dockerfile.test -t myapp-test .

# Execute
docker run --rm myapp-test
```

**Note**: If you run this repo as a Microservice you can skip this.

## Acknowledgments

If you want to use this template, mention me in the README file or leave me a ⭐. Thank you!
