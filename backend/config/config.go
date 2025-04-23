package config

import (
	"fmt"
	"log"
	"os"
)

var JwtSecret []byte
var DbURL string
var DbConnStr string

func LoadEnv() {
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET not defined")
	}
	JwtSecret = []byte(jwtSecret)

	DbConnStr = fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s sslrootcert=%s",
		os.Getenv("DB_HOST"),
		os.Getenv("DB_PORT"),
		os.Getenv("POSTGRES_USER"),
		os.Getenv("POSTGRES_PASSWORD"),
		os.Getenv("POSTGRES_DB"),
		os.Getenv("DB_SSLMODE"),
		os.Getenv("DB_SSLROOTCERT"),
	)
	if DbConnStr == "" {
		log.Fatal("DB connection string not defined")
	}
}
