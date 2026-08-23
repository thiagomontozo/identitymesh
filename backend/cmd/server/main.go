package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/thiagomontozo/identitymesh/backend/internal/assurance"
	"github.com/thiagomontozo/identitymesh/backend/internal/config"
	"github.com/thiagomontozo/identitymesh/backend/internal/database"
	"github.com/thiagomontozo/identitymesh/backend/internal/httpapi"
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
	db, err := database.Open(ctx, cfg.DatabaseURL)
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
	secrets, err := secure.NewAESGCMStore(cfg.MasterKey)
	if err != nil {
		log.Error("secret store failed", "error", err.Error())
		os.Exit(1)
	}
	svc := &assurance.Service{DB: db, Secrets: secrets, Clock: assurance.RealClock{}, AllowHTTP: cfg.Environment != "production", Timeout: cfg.SyncTimeout}
	syncPool := workers.New(cfg.MaxConcurrentSyncs, cfg.MaxConcurrentSyncs*4)
	actionPool := workers.New(cfg.MaxConcurrentActs, cfg.MaxConcurrentActs*4)
	syncPool.Start(ctx, cfg.MaxConcurrentSyncs)
	actionPool.Start(ctx, cfg.MaxConcurrentActs)
	defer syncPool.Stop()
	defer actionPool.Stop()
	maintenance := scheduler.Scheduler{DB: db.Pool, Name: "access-review-deadlines", Interval: time.Minute, Task: func(taskCtx context.Context) error {
		_, taskErr := db.Pool.Exec(taskCtx, `UPDATE access_review_campaigns SET status='OVERDUE' WHERE status='ACTIVE' AND due_at IS NOT NULL AND due_at<now()`)
		return taskErr
	}}
	go maintenance.Run(ctx)
	api := httpapi.New(db, svc, secrets, log, cfg.AllowedOrigin, cfg.SecureCookies, cfg.RequirePrivilegedMFA, cfg.MaxCSVBytes, syncPool, actionPool)
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
