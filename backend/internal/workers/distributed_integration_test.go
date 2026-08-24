//go:build integration

package workers

import (
	"context"
	"encoding/json"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestDistributedQueueClaimsOnceAcrossWorkers(t *testing.T) {
	url := os.Getenv("IDENTITYMESH_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("IDENTITYMESH_TEST_DATABASE_URL not configured")
	}
	db, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var org string
	if err = db.QueryRow(context.Background(), `INSERT INTO organizations(name) VALUES($1) RETURNING id`, "Queue "+uuid.NewString()).Scan(&org); err != nil {
		t.Fatal(err)
	}
	defer db.Exec(context.Background(), `DELETE FROM organizations WHERE id=$1`, org)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls atomic.Int32
	handler := func(context.Context, DistributedJob) error { calls.Add(1); return nil }
	a, _ := NewDistributedQueue(db, "worker-a", 10*time.Second, 20*time.Millisecond, nil)
	b, _ := NewDistributedQueue(db, "worker-b", 10*time.Second, 20*time.Millisecond, nil)
	_ = a.Register("CONNECTOR_SYNC", handler)
	_ = b.Register("CONNECTOR_SYNC", handler)
	a.Start(ctx, 1)
	b.Start(ctx, 1)
	id, created, err := a.Enqueue(ctx, org, "CONNECTOR_SYNC", json.RawMessage(`{"connectorId":"synthetic"}`), "same-operation", 100)
	if err != nil || !created || id == "" {
		t.Fatalf("enqueue: id=%q created=%v err=%v", id, created, err)
	}
	duplicateID, created, err := b.Enqueue(ctx, org, "CONNECTOR_SYNC", map[string]string{"connectorId": "synthetic"}, "same-operation", 100)
	if err != nil || created || duplicateID != id {
		t.Fatalf("duplicate: id=%q created=%v err=%v", duplicateID, created, err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && calls.Load() == 0 {
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	a.Wait()
	b.Wait()
	if calls.Load() != 1 {
		t.Fatalf("handler calls=%d, want 1", calls.Load())
	}
}
