package httpserver

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/hkjang/ReSSO/internal/backchannel"
	"github.com/hkjang/ReSSO/internal/observability"
)

const (
	metricRequests       = "resso_http_requests_total"
	metricRequestTime    = "resso_http_request_duration_seconds"
	metricTokens         = "resso_tokens_issued_total"
	metricLogins         = "resso_login_attempts_total"
	metricClientAuth     = "resso_client_auth_failures_total"
	metricLogoutNotices  = backchannel.MetricName
	MetricFederationSync = "resso_federation_sync_total"
	metricFederationSync = MetricFederationSync
)

func newMetrics() *observability.Registry {
	registry := observability.NewRegistry()
	registry.Counter(metricRequests, "HTTP requests handled, by route pattern, method and status.",
		"route", "method", "status")
	registry.Histogram(metricRequestTime, "HTTP request duration in seconds, by route pattern.",
		observability.DefaultLatencyBounds, "route")
	registry.Counter(metricTokens, "OIDC tokens issued, by grant type.", "grant_type")
	registry.Counter(metricLogins, "Browser login attempts, by outcome.", "result")
	registry.Counter(metricClientAuth, "Failed OIDC client authentications.", "realm")
	registry.Counter(metricLogoutNotices, "Back-channel logout deliveries, by outcome.", "result")
	registry.Counter(metricFederationSync, "Scheduled LDAP federation syncs, by outcome.", "result")
	return registry
}

func (s *Server) serveMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	s.metrics.WritePrometheus(w)
}

// routePattern reports the matched chi pattern rather than the raw path, so
// that per-Realm and per-identifier paths do not create unbounded series.
func routePattern(r *http.Request) string {
	if context := chi.RouteContext(r.Context()); context != nil {
		if pattern := context.RoutePattern(); pattern != "" {
			return pattern
		}
	}
	return "unmatched"
}

func statusLabel(status int) string {
	if status == 0 {
		return "0"
	}
	return strconv.Itoa(status)
}
