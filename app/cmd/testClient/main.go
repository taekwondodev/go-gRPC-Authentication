package testclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"log"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func main() {
	cert, err := tls.LoadX509KeyPair("certs/client.crt", "certs/client.key")
	if err != nil {
		log.Fatal(err)
	}

	caCert, err := ioutil.ReadFile("certs/ca.crt")
	if err != nil {
		log.Fatal(err)
	}

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
	}

	conn, err := grpc.Dial(
		"localhost:50051",
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	client := pb.NewAuthServiceClient(conn)
	resp, err := client.Login(context.Background(), &pb.LoginRequest{
		Email:    "test@example.com",
		Password: "password",
	})
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Token: %s", resp.Token)
}
