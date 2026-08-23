// Package httpserver exposes ReSSO's OIDC endpoints, administrative and
// personal REST APIs, MCP endpoint and the embedded single-page console.
package httpserver

import (
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/hkjang/ReSSO/internal/observability"
	"github.com/hkjang/ReSSO/internal/oidc"
	"github.com/hkjang/ReSSO/internal/ratelimit"
	"github.com/hkjang/ReSSO/internal/store"
	"github.com/hkjang/ReSSO/webui"
)

const (
	sessionCookieName = "resso_session"
	csrfCookieName    = "resso_csrf"

	// Client credential guessing is bounded per instance rather than in
	// PostgreSQL: these endpoints run on every token refresh of every relying
	// party, so they must not take a lock per call. See internal/ratelimit.
	//
	// The two buckets answer different questions. The per-client bucket is the
	// precise control on guessing one client's secret. The per-address bucket
	// only bounds spraying across many client identifiers, so it is far more
	// tolerant: relying parties commonly share one egress address, and a
	// single client with a stale secret must not lock out its neighbours. A
	// blocked attempt is not counted, so one client's failures stop feeding
	// the address bucket once that client is blocked on its own.
	clientAuthMaxFailures  = 20
	addressAuthMaxFailures = 200
	clientAuthWindow       = 5 * time.Minute
	clientAuthTrackedKeys  = 8192
)

type Server struct {
	store              *store.Store
	oidc               *oidc.Service
	logger             *slog.Logger
	trustedProxyCIDRs  []*net.IPNet
	clientAuthLimiter  *ratelimit.FailureLimiter
	addressAuthLimiter *ratelimit.FailureLimiter
	metrics            *observability.Registry
}

// New builds the HTTP surface. Pass the registry the rest of the process
// reports to; a nil registry gets a private one, which suits tests.
func New(data *store.Store, logger *slog.Logger, trustedProxyCIDRs []*net.IPNet, metrics *observability.Registry) *Server {
	if metrics == nil {
		metrics = observability.NewRegistry()
	}
	registerMetrics(metrics)
	return &Server{store: data, oidc: &oidc.Service{Store: data}, logger: logger,
		trustedProxyCIDRs:  trustedProxyCIDRs,
		clientAuthLimiter:  ratelimit.NewFailureLimiter(clientAuthMaxFailures, clientAuthWindow, clientAuthTrackedKeys),
		addressAuthLimiter: ratelimit.NewFailureLimiter(addressAuthMaxFailures, clientAuthWindow, clientAuthTrackedKeys),
		metrics:            metrics}
}

// Metrics exposes the registry so that background workers outside the HTTP
// layer, such as the scheduled federation sync, can record outcomes too.
func (s *Server) Metrics() *observability.Registry { return s.metrics }

func (s *Server) Handler() http.Handler {
	router := chi.NewRouter()
	router.Use(middleware.StripSlashes)
	router.Use(s.commonMiddleware)
	router.Get("/health/live", s.live)
	router.Get("/health/ready", s.ready)
	// Scraping requires the same admin:read authorization as the rest of the
	// administrative API, so operational detail is not exposed to anyone who
	// can reach the port. Prometheus supports bearer token authorization.
	router.With(s.requireSessionOrAPIKey, s.requireAdmin).Get("/metrics", s.serveMetrics)
	router.Get("/api/v1/meta", s.meta)
	router.Route("/api/v1/auth", func(r chi.Router) {
		r.Get("/challenge/{token}", s.authChallenge)
		r.Post("/login", s.login)
		r.With(s.requireSession).Post("/logout", s.browserLogout)
	})

	router.Route("/realms/{realm}", func(r chi.Router) {
		r.Use(s.oidcCORS)
		r.Get("/.well-known/openid-configuration", s.discovery)
		r.Route("/protocol/openid-connect", func(r chi.Router) {
			r.Options("/*", s.oidcOptions)
			r.Get("/auth", s.authorization)
			r.Post("/token", s.token)
			r.Get("/userinfo", s.userInfo)
			r.Post("/userinfo", s.userInfo)
			r.Get("/certs", s.jwks)
			r.Get("/logout", s.oidcLogout)
			r.Post("/logout", s.oidcLogout)
			r.Post("/token/introspect", s.introspect)
			r.Post("/revoke", s.revoke)
		})
	})

	router.Route("/api/v1", func(r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(s.requireSessionOrAPIKey)
			r.Get("/me", s.me)
			r.Put("/me/profile", s.updateMyProfile)
			r.Put("/me/password", s.changeMyPassword)
			r.Get("/me/sessions", s.mySessions)
			r.Delete("/me/sessions/{id}", s.revokeMySession)
			r.Get("/me/api-keys", s.listMyAPIKeys)
			r.Post("/me/api-keys", s.createMyAPIKey)
			r.Post("/me/api-keys/{id}/rotate", s.rotateMyAPIKey)
			r.Delete("/me/api-keys/{id}", s.revokeMyAPIKey)
			r.Get("/me/approval-capability", s.myApprovalCapability)
			r.Get("/me/requestable-roles", s.myRequestableRoles)
			r.Get("/me/requests", s.listMyRequests)
			r.Post("/me/requests", s.createMyRequest)
			r.Get("/me/reviews", s.listMyReviews)
			r.Post("/me/reviews/{requestID}/decision", s.decideMyReview)
		})
	})

	router.Route("/api/admin/v1", func(r chi.Router) {
		r.Use(s.requireSessionOrAPIKey)
		r.Use(s.requireAdmin)
		s.adminRoutes(r)
	})
	router.Get("/api/openapi.json", s.openAPISpec)
	router.Get("/.well-known/oauth-protected-resource", s.mcpProtectedResource)
	router.Post("/mcp", s.mcp)
	router.Get("/mcp", s.mcpMethodNotAllowed)

	// The console is a single-page application, so anything the routes above
	// did not claim is one of its own paths and gets the document.
	router.Handle("/*", s.spaHandler())

	// Everything that reaches this point is inside a mounted API subtree —
	// the catch-all above answers every unclaimed path at the root — so it is
	// a request to this service's API for something that is not there.
	//
	// chi answers those itself with `404 page not found` in plain text, and a
	// path that exists for another method with an empty 405 carrying no body
	// at all. Every other refusal this service makes is a JSON object with
	// error, message and trace_id, and the OpenAPI document promises that
	// shape for 4XX on every operation. A caller that mistyped a path, or
	// called one that a later version removed, is exactly the caller whose
	// error handling then fails on the response it was written to read.
	router.NotFound(func(w http.ResponseWriter, r *http.Request) {
		writeError(w, r, http.StatusNotFound, "not_found", "요청한 경로가 없습니다.")
	})
	router.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed",
			"이 경로는 해당 HTTP 메서드를 받지 않습니다.")
	})
	return router
}

func (s *Server) oidcOptions(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) spaHandler() http.Handler {
	dist, err := fs.Sub(webui.Files(), "dist")
	if err != nil {
		panic(err)
	}
	files := http.FileServer(http.FS(dist))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path != "" {
			if file, err := dist.Open(path); err == nil {
				_ = file.Close()
				if strings.Contains(path, ".") {
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				}
				files.ServeHTTP(w, r)
				return
			}
		}
		w.Header().Set("Cache-Control", "no-cache")
		r.URL.Path = "/"
		files.ServeHTTP(w, r)
	})
}
