//go:build integration

package ratelimit

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPostgresLimiterCoordinatesInstances(t *testing.T) {
	url := os.Getenv("IDENTITYMESH_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("IDENTITYMESH_TEST_DATABASE_URL not configured")
	}
	db, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, _ = db.Exec(context.Background(), `DELETE FROM rate_limit_windows`)
	a, b := Postgres{DB: db}, Postgres{DB: db}
	key := "synthetic-client:login"
	for i, limiter := range []Postgres{a, b, a} {
		allowed, _, err := limiter.Allow(context.Background(), key, 2, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if allowed != (i < 2) {
			t.Fatalf("request %d allowed=%v", i+1, allowed)
		}
	}
}
