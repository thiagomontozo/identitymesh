package workers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type DistributedJob struct {
	ID, OrganizationID, Kind string
	Payload                  json.RawMessage
	Attempts, MaxAttempts    int
}

type DistributedHandler func(context.Context, DistributedJob) error

type DistributedQueue struct {
	DB           *pgxpool.Pool
	WorkerID     string
	Lease        time.Duration
	PollInterval time.Duration
	Logger       *slog.Logger
	handlers     map[string]DistributedHandler
	wg           sync.WaitGroup
}

func NewDistributedQueue(db *pgxpool.Pool, workerID string, lease, poll time.Duration, logger *slog.Logger) (*DistributedQueue, error) {
	if db == nil {
		return nil, errors.New("distributed worker database is required")
	}
	if workerID == "" {
		workerID = uuid.NewString()
	}
	if lease < 10*time.Second {
		lease = 2 * time.Minute
	}
	if poll < 50*time.Millisecond {
		poll = 500 * time.Millisecond
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &DistributedQueue{DB: db, WorkerID: workerID, Lease: lease, PollInterval: poll, Logger: logger, handlers: map[string]DistributedHandler{}}, nil
}

func (q *DistributedQueue) Register(kind string, handler DistributedHandler) error {
	if kind == "" || handler == nil {
		return errors.New("distributed job kind and handler are required")
	}
	if _, exists := q.handlers[kind]; exists {
		return fmt.Errorf("handler already registered for %s", kind)
	}
	q.handlers[kind] = handler
	return nil
}

func (q *DistributedQueue) Enqueue(ctx context.Context, organizationID, kind string, payload any, idempotencyKey string, priority int) (string, bool, error) {
	if organizationID == "" || q.handlers[kind] == nil || idempotencyKey == "" {
		return "", false, errors.New("invalid distributed job")
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", false, err
	}
	id := uuid.NewString()
	var returned string
	err = q.DB.QueryRow(ctx, `
INSERT INTO distributed_jobs(id,organization_id,kind,payload,idempotency_key,priority)
VALUES($1,$2,$3,$4,$5,$6)
ON CONFLICT(organization_id,idempotency_key) DO UPDATE SET idempotency_key=EXCLUDED.idempotency_key
RETURNING id`, id, organizationID, kind, raw, idempotencyKey, priority).Scan(&returned)
	if err != nil {
		return "", false, err
	}
	return returned, returned == id, nil
}

func (q *DistributedQueue) Start(ctx context.Context, concurrency int) {
	if concurrency < 1 {
		concurrency = 1
	}
	for i := 0; i < concurrency; i++ {
		q.wg.Add(1)
		go q.run(ctx)
	}
}

func (q *DistributedQueue) Wait() { q.wg.Wait() }

func (q *DistributedQueue) run(ctx context.Context) {
	defer q.wg.Done()
	ticker := time.NewTicker(q.PollInterval)
	defer ticker.Stop()
	for {
		job, err := q.claim(ctx)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) && ctx.Err() == nil {
			q.Logger.Error("distributed job claim failed", "workerId", q.WorkerID, "error", err.Error())
		}
		if err == nil {
			q.execute(ctx, job)
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (q *DistributedQueue) claim(ctx context.Context) (DistributedJob, error) {
	var job DistributedJob
	err := q.DB.QueryRow(ctx, `
WITH candidate AS (
  SELECT id FROM distributed_jobs
  WHERE (status='QUEUED' AND available_at<=now())
     OR (status='RUNNING' AND lease_until<now())
  ORDER BY priority DESC, created_at
  FOR UPDATE SKIP LOCKED
  LIMIT 1
)
UPDATE distributed_jobs j
SET status='RUNNING', lease_owner=$1, lease_until=now()+make_interval(secs=>$2),
    attempts=j.attempts+1, started_at=coalesce(j.started_at,now())
FROM candidate
WHERE j.id=candidate.id
RETURNING j.id,j.organization_id,j.kind,j.payload,j.attempts,j.max_attempts`, q.WorkerID, int(q.Lease/time.Second)).Scan(&job.ID, &job.OrganizationID, &job.Kind, &job.Payload, &job.Attempts, &job.MaxAttempts)
	return job, err
}

func (q *DistributedQueue) execute(parent context.Context, job DistributedJob) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(q.Lease / 3)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				_, _ = q.DB.Exec(ctx, `UPDATE distributed_jobs SET lease_until=now()+make_interval(secs=>$1) WHERE id=$2 AND status='RUNNING' AND lease_owner=$3`, int(q.Lease/time.Second), job.ID, q.WorkerID)
			}
		}
	}()
	handler := q.handlers[job.Kind]
	var err error
	if handler == nil {
		err = fmt.Errorf("no handler registered for %s", job.Kind)
	} else {
		err = handler(ctx, job)
	}
	close(done)
	if err == nil {
		_, err = q.DB.Exec(parent, `UPDATE distributed_jobs SET status='SUCCEEDED',completed_at=now(),lease_owner=NULL,lease_until=NULL,last_error_code=NULL,last_error_summary=NULL WHERE id=$1 AND lease_owner=$2`, job.ID, q.WorkerID)
		if err != nil && parent.Err() == nil {
			q.Logger.Error("distributed job completion failed", "jobId", job.ID, "error", err.Error())
		}
		return
	}
	status := "QUEUED"
	if job.Attempts >= job.MaxAttempts {
		status = "DEAD"
	}
	backoffSeconds := 1 << min(job.Attempts, 8)
	_, updateErr := q.DB.Exec(parent, `UPDATE distributed_jobs SET status=$1,available_at=now()+make_interval(secs=>$2),lease_owner=NULL,lease_until=NULL,last_error_code='JOB_HANDLER_FAILED',last_error_summary=left($3,500),completed_at=CASE WHEN $1='DEAD' THEN now() ELSE NULL END WHERE id=$4 AND lease_owner=$5`, status, backoffSeconds, err.Error(), job.ID, q.WorkerID)
	if updateErr != nil && parent.Err() == nil {
		q.Logger.Error("distributed job retry update failed", "jobId", job.ID, "error", updateErr.Error())
	}
}
