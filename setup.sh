#!/bin/bash

# Output color
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Starting configuration...${NC}"

## 1. Postgres SSL
echo -e "${GREEN}[1/4] Postgres SSL...${NC}"

mkdir -p postgres/ssl
cd postgres/ssl

echo -e "${YELLOW}Generating SSL Certs...${NC}"

openssl req -new -x509 -days 3650 -nodes -newkey rsa:2048 \
  -keyout ca.key -out ca.crt -subj "/CN=PostgreSQL Internal CA"

openssl req -new -nodes -newkey rsa:2048 \
  -keyout server.key -out server.csr \
  -config openssl.cnf

openssl x509 -req -in server.csr -days 3650 \
  -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -extfile openssl.cnf -extensions req_ext

chmod 600 server.key
chmod 644 server.crt ca.crt
rm server.csr

cd ../..

## 2. JWT Secret
echo -e "${GREEN}[2/4] Generating JWT Secret...${NC}"
JWT_SECRET=$(openssl rand -hex 32)
echo -e "${YELLOW}JWT Secret generated: ${JWT_SECRET}${NC}"

## 3. File .env
echo -e "${GREEN}[3/4] Creating file .env...${NC}"

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

## 4. Protobuf
echo -e "${GREEN}[4/4] Compilating Protobuf files...${NC}"
cd app

protoc --proto_path=proto --go_out=gen --go_opt=paths=source_relative --go-grpc_out=gen --go-grpc_opt=paths=source_relative proto/auth.proto

cd ../
echo -e "${GREEN}Configuration completed successfully!${NC}"