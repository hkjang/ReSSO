package httpserver

import (
	"io/fs"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/hkjang/ReSSO/internal/oidc"
	"github.com/hkjang/ReSSO/internal/store"
	"github.com/hkjang/ReSSO/webui"
)

const (
	sessionCookieName = "resso_session"
	csrfCookieName    = "resso_csrf"
)

type Server struct {
	store        *store.Store
	oidc         *oidc.Service
	logger       *slog.Logger
	loginLimiter *loginLimiter
}

func New(data *store.Store, logger *slog.Logger) *Server {
	return &Server{store: data, oidc: &oidc.Service{Store: data}, logger: logger, loginLimiter: newLoginLimiter()}
}

func (s *Server) Handler() http.Handler {
	router := chi.NewRouter()
	router.Use(middleware.StripSlashes)
	router.Use(s.commonMiddleware)
	router.Get("/health/live", s.live)
	router.Get("/health/ready", s.ready)
	router.Get("/api/v1/meta", s.meta)
	router.Route("/api/v1/auth", func(r chi.Router) {
		r.Get("/challenge/{token}", s.authChallenge)
		r.Post("/login", s.login)
		r.With(s.requireSession).Post("/logout", s.browserLogout)
	})

	router.Route("/realms/{realm}", func(r chi.Router) {
		r.Get("/.well-known/openid-configuration", s.discovery)
		r.Route("/protocol/openid-connect", func(r chi.Router) {
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
			r.Use(s.requireSession)
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
		r.Use(s.requireSession)
		r.Use(s.requirePlatformAdmin)
		s.adminRoutes(r)
	})
	router.Get("/api/openapi.json", s.openAPISpec)
	router.Get("/.well-known/oauth-protected-resource", s.mcpProtectedResource)
	router.Post("/mcp", s.mcp)
	router.Get("/mcp", s.mcpMethodNotAllowed)

	router.Handle("/*", s.spaHandler())
	return router
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
