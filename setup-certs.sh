#!/bin/bash

set -e # Exit if error occurs

echo "=== Start generating certs and protobuf ==="

# 1. Create SSL certs for PostgreSQL
echo "Creating SSL certs for PostgreSQL..."
mkdir -p postgres/ssl
pushd postgres/ssl > /dev/null

# Create CA for PostgreSQL
openssl req -new -x509 -days 3650 -nodes -newkey rsa:2048 \
  -keyout ca.key -out ca.crt -subj "/CN=PostgreSQL Internal CA"

# Create server cert for PostgreSQL
openssl req -new -nodes -newkey rsa:2048 \
  -keyout server.key -out server.csr \
  -config openssl.cnf

openssl x509 -req -in server.csr -days 3650 \
-CA ca.crt -CAkey ca.key -CAcreateserial \
-out server.crt -extfile openssl.cnf -extensions req_ext

chmod 600 server.key
chmod 644 server.crt ca.crt
rm server.csr
popd > /dev/null

# 2. Create certs mTLS per gRPC
echo "Generando certificati mTLS per gRPC..."
mkdir -p app/certs
pushd app/certs > /dev/null

# Create CA for mTLS
openssl req -x509 -newkey rsa:4096 -keyout ca.key -out ca.crt -days 365 -nodes -subj "/CN=AuthService CA"

# Create server cert for mTLS
openssl req -newkey rsa:4096 -nodes -keyout server.key -out server.csr -subj "/CN=auth-service"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365

# Genera certificato client (opzionale, per mTLS completo)
# openssl req -newkey rsa:4096 -nodes -keyout client.key -out client.csr -subj "/CN=client"
# openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365

chmod 600 *.key
chmod 644 *.crt
rm *.csr
popd > /dev/null

# 3. Create gRPC code from protobuf
echo "Creating gRPC code from protobuf..."
mkdir -p gen
protoc --proto_path=proto \
  --go_out=gen --go_opt=paths=source_relative \
  --go-grpc_out=gen --go-grpc_opt=paths=source_relative \
  proto/auth.proto

echo "=== Operations completed successfully ==="
echo "Certs generated in:"
echo "  - postgres/ssl/"
echo "  - app/certs/"
echo "gRPC code generated in: gen/"