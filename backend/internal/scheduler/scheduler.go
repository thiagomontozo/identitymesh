package scheduler

import (
	"context"
	"hash/fnv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Task func(context.Context) error
type Scheduler struct {
	DB       *pgxpool.Pool
	Interval time.Duration
	Name     string
	Task     Task
}

func (s Scheduler) Run(ctx context.Context) {
	if s.Interval <= 0 {
		s.Interval = time.Minute
	}
	ticker := time.NewTicker(s.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.once(ctx)
		}
	}
}
func (s Scheduler) once(ctx context.Context) {
	conn, err := s.DB.Acquire(ctx)
	if err != nil {
		return
	}
	defer conn.Release()
	h := fnv.New64a()
	_, _ = h.Write([]byte("identitymesh:" + s.Name))
	key := int64(h.Sum64())
	var locked bool
	if conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", key).Scan(&locked) != nil || !locked {
		return
	}
	defer conn.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", key)
	_ = s.Task(ctx)
}
