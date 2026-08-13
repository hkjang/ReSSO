package httpserver

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/hkjang/ReSSO/internal/domain"
)

type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (r *statusRecorder) WriteHeader(status int) {
	if r.status == 0 {
		r.status = status
	}
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Write(body []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(body)
	r.bytes += n
	return n, err
}

func (s *Server) commonMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		traceID := strings.TrimSpace(r.Header.Get("X-Request-ID"))
		if traceID == "" || len(traceID) > 64 {
			traceID = uuid.NewString()
		}
		ctx := context.WithValue(r.Context(), traceIDKey, traceID)
		w.Header().Set("X-Request-ID", traceID)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
		if requestIsSecure(r) {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		start := time.Now()
		recorder := &statusRecorder{ResponseWriter: w}
		defer func() {
			if recovered := recover(); recovered != nil {
				s.logger.Error("http handler panic", "trace_id", traceID, "panic", recovered, "stack", string(debug.Stack()))
				if recorder.status == 0 {
					writeError(recorder, r.WithContext(ctx), http.StatusInternalServerError, "internal_error", "요청을 처리하지 못했습니다.")
				}
			}
			level := slog.LevelInfo
			if recorder.status >= 500 {
				level = slog.LevelError
			} else if recorder.status >= 400 {
				level = slog.LevelWarn
			}
			s.logger.Log(ctx, level, "http request", "trace_id", traceID, "method", r.Method,
				"path", r.URL.Path, "status", recorder.status, "bytes", recorder.bytes,
				"duration_ms", time.Since(start).Milliseconds(), "remote_ip", clientIP(r))
		}()
		next.ServeHTTP(recorder, r.WithContext(ctx))
	})
}

func (s *Server) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authenticated, err := s.store.SessionByToken(r.Context(), sessionCookie(r))
		if err != nil {
			writeError(w, r, http.StatusUnauthorized, "authentication_required", "로그인이 필요합니다.")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
			if !s.store.ValidateCSRF(authenticated, r.Header.Get("X-CSRF-Token")) {
				writeError(w, r, http.StatusForbidden, "invalid_csrf", "요청 검증 토큰이 올바르지 않습니다.")
				return
			}
		}
		sid := authenticated.Session.ID
		principal := domain.Principal{UserID: authenticated.User.ID, RealmID: authenticated.User.RealmID,
			Username: authenticated.User.Username, PlatformAdmin: authenticated.User.PlatformAdmin, SessionID: &sid}
		ctx := context.WithValue(r.Context(), sessionKey, authenticated)
		ctx = context.WithValue(ctx, principalKey, principal)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) requirePlatformAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, ok := principalFrom(r.Context())
		if !ok || !principal.PlatformAdmin {
			writeError(w, r, http.StatusForbidden, "insufficient_permission", "서비스 관리자 권한이 필요합니다.")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func requestIsSecure(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}
