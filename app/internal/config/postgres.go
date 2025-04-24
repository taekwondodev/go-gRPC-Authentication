package config

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	_ "github.com/lib/pq"
)

type postgres struct {
	Db        *sql.DB
	dbConnStr string
}

func NewPostgres() *postgres {
	connStr := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s sslrootcert=%s",
		os.Getenv("DB_HOST"),
		os.Getenv("DB_PORT"),
		os.Getenv("POSTGRES_USER"),
		os.Getenv("POSTGRES_PASSWORD"),
		os.Getenv("POSTGRES_DB"),
		os.Getenv("DB_SSLMODE"),
		os.Getenv("DB_SSLROOTCERT"),
	)
	if connStr == "" {
		log.Fatal("DB connection string not defined")
	}

	return &postgres{
		Db:        nil,
		dbConnStr: connStr,
	}
}

func (p *postgres) InitDB() {
	var err error

	p.Db, err = sql.Open("postgres", p.dbConnStr)
	if err != nil {
		log.Fatal("Error connection to database: ", err)
	}

	p.Db.SetMaxOpenConns(25)
	p.Db.SetMaxIdleConns(10)
	p.Db.SetConnMaxLifetime(5 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err = p.Db.PingContext(ctx); err != nil {
		if strings.Contains(err.Error(), "certificate") {
			log.Fatal("SSL verification failed: ", err)
		}
		log.Fatal("Error ping to database:", err)
	}

	log.Println("Connection to database successfully!")
}

func (p *postgres) CloseDB() {
	if p.Db == nil {
		return
	}

	p.Db.Close()
	log.Println("Connection to database closed!")
}
