package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/hkjang/ReSSO/internal/backchannel"
	"github.com/hkjang/ReSSO/internal/config"
	"github.com/hkjang/ReSSO/internal/cryptoutil"
	"github.com/hkjang/ReSSO/internal/httpserver"
	"github.com/hkjang/ReSSO/internal/observability"
	"github.com/hkjang/ReSSO/internal/oidc"
	"github.com/hkjang/ReSSO/internal/store"
	"github.com/hkjang/ReSSO/internal/version"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "healthcheck" {
		probeCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		request, err := http.NewRequestWithContext(probeCtx, http.MethodGet, healthCheckURL(), nil)
		if err != nil {
			os.Exit(1)
		}
		response, err := http.DefaultClient.Do(request)
		if err != nil || response.StatusCode != http.StatusOK {
			os.Exit(1)
		}
		_ = response.Body.Close()
		return
	}
	if len(os.Args) > 1 && (os.Args[1] == "admin" || os.Args[1] == "crypto") {
		if err := runMaintenanceCommand(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
			_, _ = os.Stderr.WriteString("ReSSO maintenance command failed: " + err.Error() + "\n")
			os.Exit(1)
		}
		return
	}
	console := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
	bootstrapLogger := slog.New(console)
	cfg, err := config.Load()
	if err != nil {
		bootstrapLogger.Error("configuration validation failed", "error", err)
		os.Exit(1)
	}
	sealer, err := newSealer(cfg)
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
	if indexed, indexErr := data.EnsureSearchIndexes(startupCtx); indexErr != nil {
		bootstrapLogger.Warn("optional user search indexes could not be created", "error", indexErr)
	} else if !indexed {
		bootstrapLogger.Info("pg_trgm is not installed; user search uses a sequential scan")
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

	metrics := observability.NewRegistry()
	logMirror := observability.NewDBHandler(console, data, "resso", metrics)
	logger := slog.New(logMirror)
	slog.SetDefault(logger)
	logger.Info("ReSSO starting", "version", version.Version, "commit", version.Commit,
		"listen", cfg.ListenAddress, "bootstrap_admin_created", bootstrap.Created)

	runCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	app := httpserver.New(data, logger, cfg.TrustedProxyCIDRs, metrics)

	// Relying parties that registered a back-channel logout URI are notified
	// whenever a session ends, including administrative revocations.
	logoutNotifier := backchannel.New(runCtx, data, &oidc.Service{Store: data}, logger, app.Metrics())
	data.OnSessionRevoked = logoutNotifier.SessionRevoked

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

	go maintenance(runCtx, data, logger)
	go federationMaintenance(runCtx, data, logger, app.Metrics())
	go func() {
		<-runCtx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			logger.Error("graceful shutdown failed", "error", err)
		}
		logoutNotifier.Wait(10 * time.Second)
		// Write out the buffered log records before the process exits, so the
		// administration log does not lose the last seconds before a restart.
		logMirror.Close(5 * time.Second)
	}()

	err = httpServer.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("HTTP server stopped unexpectedly", "error", err)
		os.Exit(1)
	}
	logger.Info("ReSSO stopped")
}

// healthCheckURL follows LISTEN_ADDRESS so the container health check probes
// the port the server actually bound.
func healthCheckURL() string {
	address := strings.TrimSpace(os.Getenv(config.EnvListenAddress))
	if address == "" {
		address = config.DefaultListenAddress
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "http://127.0.0.1:8080/health/ready"
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port) + "/health/ready"
}

func newSealer(cfg config.Config) (*cryptoutil.Sealer, error) {
	if cfg.LegacySingleKey {
		return cryptoutil.NewSealer(cfg.DataEncryptionKeys[0].Material)
	}
	dataKeys := make([]cryptoutil.NamedKey, 0, len(cfg.DataEncryptionKeys))
	for _, key := range cfg.DataEncryptionKeys {
		dataKeys = append(dataKeys, cryptoutil.NamedKey{ID: key.ID, Material: key.Material})
	}
	digestKeys := make([]cryptoutil.NamedKey, 0, len(cfg.DigestKeys))
	for _, key := range cfg.DigestKeys {
		digestKeys = append(digestKeys, cryptoutil.NamedKey{ID: key.ID, Material: key.Material})
	}
	return cryptoutil.NewKeyring(dataKeys, digestKeys)
}

func federationMaintenance(ctx context.Context, data *store.Store, logger *slog.Logger, metrics *observability.Registry) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			claimCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			ids, err := data.ClaimDueLDAPFederations(claimCtx, 5)
			cancel()
			if err != nil {
				logger.Warn("claim due LDAP federations failed", "error", err)
				continue
			}
			for _, id := range ids {
				syncCtx, syncCancel := context.WithTimeout(ctx, 10*time.Minute)
				summary, syncErr := data.SyncLDAPFederation(syncCtx, id)
				syncCancel()
				if errors.Is(syncErr, store.ErrSyncInProgress) {
					// An administrator started this provider by hand; skipping
					// is the correct outcome, not a failure.
					metrics.Add(httpserver.MetricFederationSync, 1, "skipped")
					logger.Info("scheduled LDAP federation sync skipped: already running", "federation_id", id)
					continue
				}
				if syncErr != nil {
					metrics.Add(httpserver.MetricFederationSync, 1, "failure")
					logger.Error("scheduled LDAP federation sync failed", "federation_id", id,
						"read", summary.Read, "failed", summary.Failed, "error", syncErr)
					continue
				}
				metrics.Add(httpserver.MetricFederationSync, 1, "success")
				logger.Info("scheduled LDAP federation sync completed", "federation_id", id,
					"read", summary.Read, "added", summary.Added, "updated", summary.Updated, "disabled", summary.Disabled)
			}
		}
	}
}

func maintenance(ctx context.Context, data *store.Store, logger *slog.Logger) {
	prune := func() {
		cleanupCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		if err := data.PruneOperationalData(cleanupCtx); err != nil {
			logger.Warn("operational data retention cleanup failed", "error", err)
		}
	}
	// Run once shortly after startup. Waiting a full day for the first pass
	// meant a service that restarts daily never collected expired
	// authorization codes, revoked token records or rate-limit buckets at all.
	startup := time.NewTimer(time.Minute)
	defer startup.Stop()
	select {
	case <-ctx.Done():
		return
	case <-startup.C:
		prune()
	}
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			prune()
		}
	}
}
