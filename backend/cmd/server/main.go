package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/thiagomontozo/identitymesh/backend/internal/assurance"
	"github.com/thiagomontozo/identitymesh/backend/internal/config"
	"github.com/thiagomontozo/identitymesh/backend/internal/database"
	"github.com/thiagomontozo/identitymesh/backend/internal/httpapi"
	"github.com/thiagomontozo/identitymesh/backend/internal/notifier"
	"github.com/thiagomontozo/identitymesh/backend/internal/ratelimit"
	"github.com/thiagomontozo/identitymesh/backend/internal/scheduler"
	"github.com/thiagomontozo/identitymesh/backend/internal/secure"
	"github.com/thiagomontozo/identitymesh/backend/internal/workers"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg, err := config.Load()
	if err != nil {
		log.Error("configuration rejected", "error", err.Error())
		os.Exit(1)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	db, err := openDatabase(ctx, cfg.DatabaseURL, 60*time.Second, log)
	if err != nil {
		log.Error("database unavailable", "error", err.Error())
		os.Exit(1)
	}
	defer db.Close()
	migrationDir := os.Getenv("IDENTITYMESH_MIGRATIONS_DIR")
	if migrationDir == "" {
		migrationDir = "migrations"
	}
	if err = db.Migrate(ctx, migrationDir); err != nil {
		log.Error("migration failed", "error", err.Error())
		os.Exit(1)
	}
	if err = db.Bootstrap(ctx, cfg.BootstrapEmail, cfg.BootstrapPassword); err != nil {
		log.Error("bootstrap failed", "error", err.Error())
		os.Exit(1)
	}
	var secrets secure.SecretStore
	if cfg.SecretProvider == "VAULT_TRANSIT" {
		secrets, err = secure.NewVaultTransitStore(cfg.VaultAddress, cfg.VaultToken, cfg.VaultNamespace, cfg.VaultTransitMount, cfg.VaultTransitKey, cfg.Environment != "production", cfg.SyncTimeout)
	} else {
		secrets, err = secure.NewAESGCMStore(cfg.MasterKey)
	}
	if err != nil {
		log.Error("secret store failed", "error", err.Error())
		os.Exit(1)
	}
	notifiers := notifier.Fanout{notifier.InApp{DB: db.Pool}}
	if cfg.WebhookURL != "" {
		webhook, webhookErr := notifier.NewWebhook(cfg.WebhookURL, cfg.WebhookSecret, cfg.Environment != "production", cfg.SyncTimeout)
		if webhookErr != nil {
			log.Error("webhook notifier configuration rejected", "error", webhookErr.Error())
			os.Exit(1)
		}
		notifiers = append(notifiers, webhook)
	}
	svc := &assurance.Service{DB: db, Secrets: secrets, Clock: assurance.RealClock{}, AllowHTTP: cfg.Environment != "production", Timeout: cfg.SyncTimeout, Notifier: notifiers}
	syncPool := workers.New(cfg.MaxConcurrentSyncs, cfg.MaxConcurrentSyncs*4)
	actionPool := workers.New(cfg.MaxConcurrentActs, cfg.MaxConcurrentActs*4)
	syncPool.Start(ctx, cfg.MaxConcurrentSyncs)
	actionPool.Start(ctx, cfg.MaxConcurrentActs)
	defer syncPool.Stop()
	defer actionPool.Stop()
	distributedQueue, err := workers.NewDistributedQueue(db.Pool, cfg.WorkerID, cfg.WorkerLease, cfg.WorkerPollInterval, log)
	if err != nil {
		log.Error("distributed job queue failed", "error", err.Error())
		os.Exit(1)
	}
	_ = distributedQueue.Register("CONNECTOR_SYNC", func(jobCtx context.Context, job workers.DistributedJob) error {
		var payload struct{ ConnectorID, RequestID string }
		if decodeErr := json.Unmarshal(job.Payload, &payload); decodeErr != nil {
			return decodeErr
		}
		return runPoolJob(jobCtx, syncPool, func(workerCtx context.Context) error {
			_, syncErr := svc.SyncConnector(workerCtx, job.OrganizationID, payload.ConnectorID, payload.RequestID)
			return syncErr
		})
	})
	_ = distributedQueue.Register("LIFECYCLE_EXECUTE", func(jobCtx context.Context, job workers.DistributedJob) error {
		var payload struct{ CaseID, ActorUserID string }
		if decodeErr := json.Unmarshal(job.Payload, &payload); decodeErr != nil {
			return decodeErr
		}
		return runPoolJob(jobCtx, actionPool, func(workerCtx context.Context) error {
			_, executeErr := svc.ExecuteAndVerify(workerCtx, job.OrganizationID, payload.CaseID, payload.ActorUserID)
			return executeErr
		})
	})
	if cfg.JobMode == "DISTRIBUTED" {
		distributedQueue.Start(ctx, cfg.MaxConcurrentSyncs+cfg.MaxConcurrentActs)
		defer distributedQueue.Wait()
	}
	maintenance := scheduler.Scheduler{DB: db.Pool, Name: "access-review-deadlines", Interval: time.Minute, Task: func(taskCtx context.Context) error {
		_, taskErr := db.Pool.Exec(taskCtx, `UPDATE access_review_campaigns SET status='OVERDUE' WHERE status='ACTIVE' AND due_at IS NOT NULL AND due_at<now()`)
		return taskErr
	}}
	go maintenance.Run(ctx)
	scheduledSyncs := scheduler.Scheduler{DB: db.Pool, Name: "connector-synchronization", Interval: time.Minute, Task: func(taskCtx context.Context) error {
		rows, queryErr := db.Pool.Query(taskCtx, `SELECT organization_id,id FROM identity_connectors WHERE enabled AND read_enabled AND type IN ('SCIM_2_0','LDAP_DIRECTORY','ENTRA_ID','OKTA','GOOGLE_WORKSPACE','GITHUB') AND last_sync_status NOT IN ('QUEUED','RUNNING') AND ((sync_interval='HOURLY' AND (last_sync_at IS NULL OR last_sync_at<now()-interval '1 hour')) OR (sync_interval='DAILY' AND (last_sync_at IS NULL OR last_sync_at<now()-interval '1 day')))`)
		if queryErr != nil {
			return queryErr
		}
		type dueConnector struct{ orgID, connectorID string }
		var due []dueConnector
		for rows.Next() {
			var item dueConnector
			if queryErr = rows.Scan(&item.orgID, &item.connectorID); queryErr != nil {
				rows.Close()
				return queryErr
			}
			due = append(due, item)
		}
		rows.Close()
		for _, item := range due {
			tag, updateErr := db.Pool.Exec(taskCtx, `UPDATE identity_connectors SET last_sync_status='QUEUED',updated_at=now() WHERE organization_id=$1 AND id=$2 AND last_sync_status NOT IN ('QUEUED','RUNNING')`, item.orgID, item.connectorID)
			if updateErr != nil || tag.RowsAffected() == 0 {
				continue
			}
			requestID := uuid.NewString()
			var submitErr error
			if cfg.JobMode == "DISTRIBUTED" {
				_, _, submitErr = distributedQueue.Enqueue(taskCtx, item.orgID, "CONNECTOR_SYNC", map[string]string{"connectorId": item.connectorID, "requestId": requestID}, "scheduled-sync:"+item.connectorID+":"+time.Now().UTC().Format("200601021504"), 50)
			} else {
				job := item
				submitErr = syncPool.Submit(func(workerCtx context.Context) error {
					_, syncErr := svc.SyncConnector(workerCtx, job.orgID, job.connectorID, requestID)
					return syncErr
				})
			}
			if submitErr != nil {
				_, _ = db.Pool.Exec(taskCtx, `UPDATE identity_connectors SET last_sync_status='PARTIAL',updated_at=now() WHERE organization_id=$1 AND id=$2`, item.orgID, item.connectorID)
			}
		}
		return nil
	}}
	go scheduledSyncs.Run(ctx)
	rateLimiter := ratelimit.Postgres{DB: db.Pool}
	rateLimitCleanup := scheduler.Scheduler{DB: db.Pool, Name: "rate-limit-cleanup", Interval: 5 * time.Minute, Task: rateLimiter.Cleanup}
	go rateLimitCleanup.Run(ctx)
	api := httpapi.New(db, svc, secrets, log, cfg.AllowedOrigin, cfg.SecureCookies, cfg.RequirePrivilegedMFA, cfg.MaxCSVBytes, syncPool, actionPool, distributedQueue, cfg.JobMode, rateLimiter, cfg.TrustedProxyCIDRs)
	server := &http.Server{Addr: cfg.HTTPAddr, Handler: api.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 2 * time.Minute, IdleTimeout: 60 * time.Second}
	go func() {
		log.Info("IdentityMesh API started", "address", cfg.HTTPAddr, "environment", cfg.Environment)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("http server failed", "error", err.Error())
			cancel()
		}
	}()
	<-ctx.Done()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Error("graceful shutdown timed out", "error", err.Error())
	}
	log.Info("IdentityMesh stopped")
}

func openDatabase(parent context.Context, databaseURL string, timeout time.Duration, log *slog.Logger) (*database.Store, error) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	delay := 250 * time.Millisecond
	for {
		store, err := database.Open(ctx, databaseURL)
		if err == nil {
			return store, nil
		}
		if ctx.Err() != nil {
			return nil, err
		}
		log.Warn("database connection pending", "retryIn", delay.String(), "error", err.Error())
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, err
		case <-timer.C:
		}
		if delay < 5*time.Second {
			delay *= 2
			if delay > 5*time.Second {
				delay = 5 * time.Second
			}
		}
	}
}

func runPoolJob(ctx context.Context, pool *workers.Pool, job workers.Job) error {
	done := make(chan error, 1)
	if err := pool.Submit(func(workerCtx context.Context) error {
		err := job(workerCtx)
		done <- err
		return err
	}); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return err
	}
}
