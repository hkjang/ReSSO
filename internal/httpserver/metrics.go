package httpserver

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/hkjang/ReSSO/internal/backchannel"
	"github.com/hkjang/ReSSO/internal/observability"
)

const (
	metricRequests    = "resso_http_requests_total"
	metricRequestTime = "resso_http_request_duration_seconds"
	metricTokens      = "resso_tokens_issued_total"
	// Issuance failing is not an issuance, so it cannot share the counter
	// above without making "issued" mean something else. It needs a signal of
	// its own: a signing key that will not open takes every token request with
	// it, and the counter of successes simply goes flat — which is what a
	// quiet night looks like.
	metricTokenErrors = "resso_token_errors_total"
	metricLogins      = "resso_login_attempts_total"
	metricClientAuth  = "resso_client_auth_failures_total"
	// metricIntrospectionErrors counts the introspections the service could
	// not judge, as opposed to the ones it judged dead. Both answer 200 with
	// active=false, so without this series the two are the same call in every
	// signal the service publishes.
	metricIntrospectionErrors = "resso_introspection_errors_total"
	metricLogoutNotices       = backchannel.MetricName
	MetricFederationSync      = "resso_federation_sync_total"
	metricFederationSync      = MetricFederationSync
)

// registerMetrics declares this package's series on a shared registry.
func registerMetrics(registry *observability.Registry) {
	registry.Counter(metricRequests, "HTTP requests handled, by route pattern, method and status.",
		"route", "method", "status")
	registry.Histogram(metricRequestTime, "HTTP request duration in seconds, by route pattern.",
		observability.DefaultLatencyBounds, "route")
	registry.Counter(metricTokens, "OIDC tokens issued, by grant type.", "grant_type")
	registry.Counter(metricTokenErrors, "Token requests the service could not fulfil, by grant type.", "grant_type")
	registry.Counter(metricLogins, "Browser login attempts, by outcome.", "result")
	registry.Counter(metricClientAuth, "Failed OIDC client authentications.", "realm")
	registry.Counter(metricIntrospectionErrors,
		"Introspections the service could not judge, by the lookup that failed.", "stage")
	registry.Counter(metricLogoutNotices, "Back-channel logout deliveries, by outcome.", "result")
	registry.Counter(metricFederationSync, "Scheduled LDAP federation syncs, by outcome.", "result")
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

// methodLabel bounds the request method as a metric label.
//
// The value arrives on the request line and any RFC 7230 token is accepted as
// a method, so recording it as given let an unauthenticated caller create one
// time series per request. The registry never reclaims a series and every one
// is written on every scrape, so the cost lands twice: memory that only grows,
// and a /metrics response that eventually becomes the operator's problem.
// Methods this service does not serve are worth counting, but only together.
func methodLabel(method string) string {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut,
		http.MethodPatch, http.MethodDelete, http.MethodOptions:
		return method
	}
	return "other"
}

func statusLabel(status int) string {
	if status == 0 {
		return "0"
	}
	return strconv.Itoa(status)
}
