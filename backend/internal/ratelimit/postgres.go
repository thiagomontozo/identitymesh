package ratelimit

import (
	"context"
	"crypto/sha256"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Limiter interface {
	Allow(context.Context, string, int, time.Duration) (bool, time.Duration, error)
}

// Postgres coordinates fixed-window limits across every API instance sharing
// the database. Keys are SHA-256 hashed before persistence so raw IP/session
// identifiers do not become durable operational data.
type Postgres struct{ DB *pgxpool.Pool }

func (p Postgres) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, time.Duration, error) {
	if p.DB == nil {
		return false, 0, errors.New("distributed rate limiter database is unavailable")
	}
	if key == "" || limit < 1 || window < time.Second {
		return false, 0, errors.New("invalid rate limit parameters")
	}
	now := time.Now().UTC()
	windowSeconds := int64(window / time.Second)
	started := time.Unix((now.Unix()/windowSeconds)*windowSeconds, 0).UTC()
	expires := started.Add(window)
	hash := sha256.Sum256([]byte(key))
	var count int
	err := p.DB.QueryRow(ctx, `
INSERT INTO rate_limit_windows(key_hash,window_started_at,request_count,expires_at)
VALUES($1,$2,1,$3)
ON CONFLICT(key_hash,window_started_at) DO UPDATE
SET request_count=rate_limit_windows.request_count+1,
    expires_at=greatest(rate_limit_windows.expires_at,EXCLUDED.expires_at)
RETURNING request_count`, hash[:], started, expires).Scan(&count)
	if err != nil {
		return false, 0, err
	}
	retry := time.Until(expires)
	if retry < 0 {
		retry = 0
	}
	return count <= limit, retry, nil
}

func (p Postgres) Cleanup(ctx context.Context) error {
	_, err := p.DB.Exec(ctx, `DELETE FROM rate_limit_windows WHERE expires_at < now()-interval '5 minutes'`)
	return err
}
