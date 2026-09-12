package httpserver

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"runtime/debug"
	"slices"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/hkjang/ReSSO/internal/domain"
	"github.com/hkjang/ReSSO/internal/store"
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
		// The console document replaces this with a wider one while a tracking
		// snippet is on for that path (see serveConsoleDocument); everything
		// else keeps it as written.
		w.Header().Set("Content-Security-Policy", basePolicy)
		if s.requestIsSecure(r) {
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
			elapsed := time.Since(start)
			route := routePattern(r)
			s.metrics.Add(metricRequests, 1, route, methodLabel(r.Method), statusLabel(recorder.status))
			s.metrics.Observe(metricRequestTime, elapsed.Seconds(), route)
			s.logger.Log(ctx, level, "http request", "trace_id", traceID, "method", r.Method,
				"path", r.URL.Path, "status", recorder.status, "bytes", recorder.bytes,
				"duration_ms", elapsed.Milliseconds(), "remote_ip", s.clientIP(r))
		}()
		next.ServeHTTP(recorder, r.WithContext(ctx))
	})
}

func (s *Server) oidcCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Announced whether or not the origin turns out to be allowed, because
		// what varies is the answer, not the allowed case of it. Adding it only
		// on the allowed path let a shared cache treat a response whose
		// Access-Control-Allow-Origin names one registered origin as the answer
		// for every origin — and the JWKS is served public and cacheable, so it
		// is the one response here a cache actually keeps.
		w.Header().Add("Vary", "Origin")
		origin := strings.TrimRight(strings.TrimSpace(r.Header.Get("Origin")), "/")
		if origin != "" {
			if realm, err := s.realmFromPath(r); err == nil {
				if allowed, allowErr := s.store.WebOriginAllowed(r.Context(), realm.ID, origin); allowErr == nil && allowed {
					w.Header().Set("Access-Control-Allow-Origin", origin)
					w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
					w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
					w.Header().Set("Access-Control-Max-Age", "600")
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// isSafeMethod reports whether a request only reads, and therefore needs no
// CSRF token and may be authorized by a read-scoped API key.
func isSafeMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions
}

// sessionContext validates the browser session cookie, enforces CSRF on
// state-changing methods, and returns a request carrying the session and the
// derived principal. It reports false after writing the response itself.
func (s *Server) sessionContext(w http.ResponseWriter, r *http.Request,
	authenticated store.AuthenticatedSession) (*http.Request, bool) {
	if !isSafeMethod(r.Method) && !s.store.ValidateCSRF(authenticated, r.Header.Get("X-CSRF-Token")) {
		writeError(w, r, http.StatusForbidden, "invalid_csrf", "요청 검증 토큰이 올바르지 않습니다.")
		return nil, false
	}
	sid := authenticated.Session.ID
	principal := domain.Principal{UserID: authenticated.User.ID, RealmID: authenticated.User.RealmID,
		Username: authenticated.User.Username, PlatformAdmin: authenticated.User.PlatformAdmin,
		RealmAdmin: authenticated.RealmAdmin, SessionID: &sid,
		AuthenticatedAt: authenticated.AuthenticatedAt}
	ctx := context.WithValue(r.Context(), sessionKey, authenticated)
	ctx = context.WithValue(ctx, principalKey, principal)
	return r.WithContext(ctx), true
}

func (s *Server) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authenticated, err := s.store.SessionByToken(r.Context(), sessionCookie(r))
		if err != nil {
			writeError(w, r, http.StatusUnauthorized, "authentication_required", "로그인이 필요합니다.")
			return
		}
		request, ok := s.sessionContext(w, r, authenticated)
		if !ok {
			return
		}
		next.ServeHTTP(w, request)
	})
}

func (s *Server) requireSessionOrAPIKey(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if authenticated, err := s.store.SessionByToken(r.Context(), sessionCookie(r)); err == nil {
			request, ok := s.sessionContext(w, r, authenticated)
			if !ok {
				return
			}
			next.ServeHTTP(w, request)
			return
		}
		// An API key is read-only authorization; changing state always
		// requires a browser session so that CSRF protection applies.
		if !isSafeMethod(r.Method) {
			writeError(w, r, http.StatusUnauthorized, "browser_session_required", "변경 요청에는 브라우저 로그인이 필요합니다.")
			return
		}
		principal, err := s.store.AuthenticateAPIKey(r.Context(), bearerToken(r))
		if err != nil || !slices.Contains(principal.Scopes, "api:read") {
			w.Header().Set("WWW-Authenticate", `Bearer scope="api:read"`)
			writeError(w, r, http.StatusUnauthorized, "authentication_required", "로그인 또는 api:read 범위의 API 키가 필요합니다.")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey, principal)))
	})
}

func (s *Server) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, ok := principalFrom(r.Context())
		if !ok || (!principal.PlatformAdmin && !principal.RealmAdmin) {
			writeError(w, r, http.StatusForbidden, "insufficient_permission", "관리자 권한이 필요합니다.")
			return
		}
		if principal.SessionID == nil && !slices.Contains(principal.Scopes, "admin:read") {
			writeError(w, r, http.StatusForbidden, "insufficient_permission", "admin:read 범위가 필요합니다.")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// protectedActionWindow is how long confirming a password holds good for.
//
// Short enough that a stolen session found unattended has usually missed it,
// long enough to complete a piece of work without re-typing a password between
// every step of it. One value rather than a per-Realm setting: it governs what
// an administrator may do to the Realms, so a Realm cannot be the thing that
// sets it.
const protectedActionWindow = 5 * time.Minute

// requireRecentAuthentication guards the actions that hand out access rather
// than merely use it.
//
// A console session is a bearer credential: whoever holds the cookie is the
// administrator until it expires. That is an acceptable trade for reading a
// dashboard and a poor one for resetting somebody's password, granting a role,
// rotating a client secret or minting an API key — each of which turns a
// borrowed session into access that outlives it. Asking for the password again
// costs the legitimate administrator five seconds once every five minutes, and
// costs an attacker holding only a cookie everything.
//
// An API key can never satisfy this. It proves possession of a secret, which
// is the thing in question, not who is holding it — and state-changing
// requests already require a browser session, so this refusal is a second
// line rather than the first.
func (s *Server) requireRecentAuthentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, ok := principalFrom(r.Context())
		if !ok || principal.SessionID == nil || principal.AuthenticatedAt.IsZero() ||
			time.Since(principal.AuthenticatedAt) > protectedActionWindow {
			// The console turns this exact code into the password prompt and
			// then repeats the request, so the code is the contract and the
			// message is for everyone reaching the API another way.
			writeError(w, r, http.StatusForbidden, "reauthentication_required",
				"보호된 작업입니다. 비밀번호를 다시 확인한 뒤 진행하세요.")
			return
		}
		next.ServeHTTP(w, r)
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

func (s *Server) requireRealmAccess(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, ok := principalFrom(r.Context())
		realmID, err := uuid.Parse(chi.URLParam(r, "realmID"))
		if err != nil {
			writeError(w, r, http.StatusBadRequest, "invalid_id", "Realm ID가 올바르지 않습니다.")
			return
		}
		if !ok || (!principal.PlatformAdmin && principal.RealmID != realmID) {
			writeError(w, r, http.StatusForbidden, "insufficient_permission", "이 Realm을 관리할 권한이 없습니다.")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requestIsSecure(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	remote := remoteIP(r)
	if remote == nil || !s.isTrustedProxy(remote) {
		return false
	}
	values := strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")
	return len(values) > 0 && strings.EqualFold(strings.TrimSpace(values[len(values)-1]), "https")
}

func remoteIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return net.ParseIP(strings.TrimSpace(host))
}

func (s *Server) isTrustedProxy(ip net.IP) bool {
	for _, network := range s.trustedProxyCIDRs {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func (s *Server) clientIP(r *http.Request) string {
	remote := remoteIP(r)
	if remote == nil {
		return r.RemoteAddr
	}
	if !s.isTrustedProxy(remote) {
		return remote.String()
	}
	candidate := remote
	if rawForwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); rawForwarded != "" {
		forwarded := strings.Split(rawForwarded, ",")
		for i := len(forwarded) - 1; i >= 0; i-- {
			parsed := net.ParseIP(strings.TrimSpace(forwarded[i]))
			if parsed == nil {
				return remote.String()
			}
			candidate = parsed
			if !s.isTrustedProxy(parsed) {
				return parsed.String()
			}
		}
	}
	if realIP := net.ParseIP(strings.TrimSpace(r.Header.Get("X-Real-IP"))); realIP != nil {
		return realIP.String()
	}
	return candidate.String()
}
