package config

import (
	"context"
	"database/sql"
	"log"
	"strings"
	"time"

	_ "github.com/lib/pq"
)

var Db *sql.DB

func InitDB() {
	var err error

	Db, err = sql.Open("postgres", DbConnStr)
	if err != nil {
		log.Fatal("Error connection to database: ", err)
	}

	Db.SetMaxOpenConns(25)
	Db.SetMaxIdleConns(10)
	Db.SetConnMaxLifetime(5 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err = Db.PingContext(ctx); err != nil {
		if strings.Contains(err.Error(), "certificate") {
			log.Fatal("SSL verification failed: ", err)
		}
		log.Fatal("Error ping to database:", err)
	}

	log.Println("Connection to database successfully!")
}

func CloseDB() {
	if Db == nil {
		return
	}

	Db.Close()
	log.Println("Connection to database closed!")
}
