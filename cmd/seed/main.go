package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/FCS-Seva/false-positives-rbpo/internal/database"
	"github.com/FCS-Seva/false-positives-rbpo/internal/seed"
)

func main() {
	if os.Getenv("DATABASE_URL") == "" || os.Getenv("SEED_PASSWORD") == "" {
		log.Fatal("set DATABASE_URL and SEED_PASSWORD (12..256 bytes)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := database.Open(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatal("database connection failed")
	}
	defer db.Close()
	if err := seed.Apply(ctx, db, os.Getenv("SEED_PASSWORD")); err != nil {
		log.Fatal("seed failed; check password length and database setup")
	}
	log.Print("four demonstration accounts prepared; previous sessions revoked")
}
