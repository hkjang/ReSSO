package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hkjang/ReSSO/internal/config"
	"github.com/hkjang/ReSSO/internal/cryptoutil"
	"github.com/hkjang/ReSSO/internal/httpserver"
	"github.com/hkjang/ReSSO/internal/observability"
	"github.com/hkjang/ReSSO/internal/store"
	"github.com/hkjang/ReSSO/internal/version"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "healthcheck" {
		client := &http.Client{Timeout: 3 * time.Second}
		response, err := client.Get("http://127.0.0.1:8080/health/ready")
		if err != nil || response.StatusCode != http.StatusOK {
			os.Exit(1)
		}
		_ = response.Body.Close()
		return
	}
	console := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
	bootstrapLogger := slog.New(console)
	cfg, err := config.Load()
	if err != nil {
		bootstrapLogger.Error("configuration validation failed", "error", err)
		os.Exit(1)
	}
	sealer, err := cryptoutil.NewSealer(cfg.EncryptionKey)
	if err != nil {
		bootstrapLogger.Error("encryption service initialization failed", "error", err)
		os.Exit(1)
	}
	startupCtx, startupCancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer startupCancel()
	data, err := store.Open(startupCtx, cfg.PostgresDSN, sealer)
	if err != nil {
		bootstrapLogger.Error("database initialization failed", "error", err)
		os.Exit(1)
	}
	defer data.Close()
	if err := store.Migrate(startupCtx, data.Pool); err != nil {
		bootstrapLogger.Error("database migration failed", "error", err)
		os.Exit(1)
	}
	bootstrap, err := data.Bootstrap(startupCtx, cfg.BootstrapAdmin, cfg.BootstrapAdminPassword)
	if err != nil {
		bootstrapLogger.Error("service bootstrap failed", "error", err)
		os.Exit(1)
	}
	realms, err := data.ListRealms(startupCtx)
	if err != nil {
		bootstrapLogger.Error("realm loading failed", "error", err)
		os.Exit(1)
	}
	for _, realm := range realms {
		if err := data.EnsureActiveSigningKey(startupCtx, realm.ID); err != nil {
			bootstrapLogger.Error("realm signing key initialization failed", "realm", realm.Name, "error", err)
			os.Exit(1)
		}
	}

	logger := slog.New(observability.NewDBHandler(console, data, "resso"))
	slog.SetDefault(logger)
	logger.Info("ReSSO starting", "version", version.Version, "commit", version.Commit,
		"listen", cfg.ListenAddress, "bootstrap_admin_created", bootstrap.Created)

	app := httpserver.New(data, logger)
	httpServer := &http.Server{
		Addr:              cfg.ListenAddress,
		Handler:           app.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelError),
	}

	runCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go maintenance(runCtx, data, logger)
	go func() {
		<-runCtx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			logger.Error("graceful shutdown failed", "error", err)
		}
	}()

	err = httpServer.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("HTTP server stopped unexpectedly", "error", err)
		os.Exit(1)
	}
	logger.Info("ReSSO stopped")
}

func maintenance(ctx context.Context, data *store.Store, logger *slog.Logger) {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cleanupCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
			err := data.PruneOperationalData(cleanupCtx)
			cancel()
			if err != nil {
				logger.Warn("operational data retention cleanup failed", "error", err)
			}
		}
	}
}
