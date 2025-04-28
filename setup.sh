#!/bin/bash

# Output color
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if script is executable
if [[ ! -x "$0" ]]; then
    echo -e "${YELLOW}Making script executable...${NC}"
    chmod +x "$0"
fi

echo -e "${YELLOW}Starting configuration...${NC}"

## 1. Postgres SSL
echo -e "${GREEN}[1/4] Postgres SSL...${NC}"

mkdir -p postgres/ssl
cd postgres/ssl

echo -e "${YELLOW}Generating SSL Certs...${NC}"

# Check if openssl is installed
if ! command -v openssl &> /dev/null; then
    echo -e "${RED}Error: openssl is not installed. Please install it first.${NC}"
    exit 1
fi

openssl req -new -x509 -days 3650 -nodes -newkey rsa:2048 \
  -keyout ca.key -out ca.crt -subj "/CN=PostgreSQL Internal CA"

cat > openssl.cnf <<'EOF'
[req]
default_bits       = 2048
distinguished_name = req_distinguished_name
req_extensions     = req_ext
prompt             = no

[req_distinguished_name]
commonName = postgres

[req_ext]
subjectAltName = DNS:postgres
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
EOF

openssl req -new -nodes -newkey rsa:2048 \
  -keyout server.key -out server.csr \
  -config openssl.cnf

openssl x509 -req -in server.csr -days 3650 \
  -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -extfile openssl.cnf -extensions req_ext

chmod 600 server.key
chmod 644 server.crt ca.crt
rm server.csr openssl.cnf

cd ../..

## 2. Migrations Setup
echo -e "${GREEN}[2/4] Setting up migrations...${NC}"
mkdir -p migrations

cat > migrations/V1__Create_User_table.sql <<EOF
CREATE TABLE users (
    sub UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(50) NOT NULL UNIQUE CHECK (LENGTH(username) >= 3),
    email VARCHAR(255) NOT NULL UNIQUE CHECK (email ~* '^[A-Za-z0-9._%-]+@[A-Za-z0-9.-]+[.][A-Za-z]+$'),
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'user',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_active BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE INDEX idx_user_username ON users (username);
CREATE INDEX idx_user_email ON users (email);
CREATE INDEX idx_user_username_password ON users (username, password_hash);
CREATE INDEX idx_user_role ON users (role);

CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_user_updated_at
BEFORE UPDATE ON users
FOR EACH ROW
EXECUTE FUNCTION update_updated_at();
EOF

echo -e "${YELLOW}Migration file created at migrations/V1__Create_User_table.sql${NC}"

## 3. JWT Secret
echo -e "${GREEN}[3/4] Generating JWT Secret...${NC}"
JWT_SECRET=$(openssl rand -hex 32)
echo -e "${YELLOW}JWT Secret generated: ${JWT_SECRET}${NC}"

## 4. File .env
echo -e "${GREEN}[4/4] Creating file .env...${NC}"

if [ -f .env ]; then
    echo -e "${RED}Attention: the .env file already exist. Do you want to overwrite it? (y/n)${NC}"
    read -r response
    if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        rm .env
    else
        echo -e "${YELLOW}Skip creating file .env${NC}"
        exit 0
    fi
fi

cat > .env <<EOF
# Authentication
JWT_SECRET=${JWT_SECRET}  # Required for token signing

# Database Configuration
DB_HOST=postgres                    # Container name (don't change for compose)
DB_PORT=5432                        # Default PostgreSQL port
POSTGRES_USER=your_db_user          # Database username
POSTGRES_PASSWORD=your_db_password  # Database password
POSTGRES_DB=your_db_name            # Database name

# SSL Settings 
DB_SSLMODE=verify-full
DB_SSLROOTCERT=/etc/ssl/certs/postgres-ca.crt              
POSTGRES_URL=jdbc:postgresql://\${DB_HOST}:\${DB_PORT}/\${POSTGRES_DB}?sslmode=verify-full&sslrootcert=/flyway/conf/ca.crt
EOF

echo -e "${YELLOW}File .env created. Remember to change the default values!${NC}"

## 5. Optional: Protobuf Generation
echo -e "${YELLOW}Do you want to generate Protobuf files? (Only needed for local development) (y/n)${NC}"
read -r generate_proto
if [[ "$generate_proto" =~ ^([yY][eE][sS]|[yY])$ ]]; then
    if ! command -v protoc &> /dev/null; then
        echo -e "${RED}Error: protoc is not installed. Please install it first.${NC}"
        exit 1
    fi
    echo -e "${GREEN}Generating Protobuf files...${NC}"
    mkdir -p app/gen
    cd app || exit
    protoc --proto_path=proto --go_out=gen --go_opt=paths=source_relative --go-grpc_out=gen --go-grpc_opt=paths=source_relative proto/auth.proto
    cd ../
    echo -e "${GREEN}Protobuf files generated successfully!${NC}"
else
    echo -e "${YELLOW}Skipping Protobuf generation${NC}"
fi

echo -e "${GREEN}Configuration completed successfully!${NC}"