package httpserver

import (
	"context"
	"net/http"

	"github.com/hkjang/ReSSO/internal/domain"
	"github.com/hkjang/ReSSO/internal/store"
)

type contextKey string

const (
	principalKey contextKey = "principal"
	sessionKey   contextKey = "session"
	traceIDKey   contextKey = "trace_id"
)

func principalFrom(ctx context.Context) (domain.Principal, bool) {
	principal, ok := ctx.Value(principalKey).(domain.Principal)
	return principal, ok
}

func sessionFrom(ctx context.Context) (store.AuthenticatedSession, bool) {
	session, ok := ctx.Value(sessionKey).(store.AuthenticatedSession)
	return session, ok
}

func traceIDFrom(ctx context.Context) string {
	value, _ := ctx.Value(traceIDKey).(string)
	return value
}

func sessionCookie(r *http.Request) string {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return ""
	}
	return cookie.Value
}
