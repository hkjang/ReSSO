package httpserver

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/hkjang/ReSSO/internal/config"
	"github.com/hkjang/ReSSO/internal/domain"
	"github.com/hkjang/ReSSO/internal/store"
)

func (s *Server) authChallenge(w http.ResponseWriter, r *http.Request) {
	request, err := s.store.AuthorizationRequestByToken(r.Context(), chi.URLParam(r, "token"))
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	realm, err := s.store.RealmByID(r.Context(), request.RealmID)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	client, err := s.store.ClientByID(r.Context(), request.ClientID)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"realm":      map[string]any{"name": realm.Name, "display_name": realm.DisplayName},
		"client":     map[string]any{"client_id": client.ClientID, "name": client.Name},
		"expires_at": request.ExpiresAt,
	})
}

type loginRequest struct {
	Realm    string `json:"realm"`
	Username string `json:"username"`
	Password string `json:"password"`
	Request  string `json:"request"`
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var input loginRequest
	if !decodeJSON(w, r, &input) {
		return
	}
	ip := s.clientIP(r)
	ipDecision, rateErr := s.store.ConsumeLoginRateLimit(r.Context(), "login/ip/"+ip, 100, 5*time.Minute)
	if rateErr != nil {
		s.logger.Error("login IP rate limit failed", "trace_id", traceIDFrom(r.Context()), "error", rateErr)
		writeError(w, r, http.StatusInternalServerError, "internal_error", "로그인을 처리하지 못했습니다.")
		return
	}
	if !ipDecision.Allowed {
		if ipDecision.Attempts == 101 {
			s.audit(r, nil, nil, strings.TrimSpace(input.Username), "LOGIN_RATE_LIMITED", "FAILURE", "user", "", map[string]any{"bucket": "ip"})
		}
		writeLoginRateLimited(w, r, ipDecision.RetryAfterSeconds)
		return
	}
	var authRequest *store.AuthorizationRequest
	var realm domain.Realm
	var err error
	if input.Request != "" {
		pending, lookupErr := s.store.AuthorizationRequestByToken(r.Context(), input.Request)
		if lookupErr != nil {
			writeError(w, r, http.StatusBadRequest, "expired_request", "로그인 요청이 만료되었거나 이미 사용되었습니다.")
			return
		}
		authRequest = &pending
		realm, err = s.store.RealmByID(r.Context(), pending.RealmID)
	} else {
		if strings.TrimSpace(input.Realm) == "" {
			input.Realm = config.DefaultBootstrapRealm
		}
		realm, err = s.store.RealmByName(r.Context(), input.Realm)
	}
	if err != nil {
		writeError(w, r, http.StatusUnauthorized, "invalid_credentials", "아이디 또는 비밀번호가 올바르지 않습니다.")
		return
	}
	accountBucket := "login/account/" + realm.ID.String() + "/" + strings.ToLower(strings.TrimSpace(input.Username))
	accountDecision, accountErr := s.store.CheckLoginRateLimit(r.Context(), accountBucket, 30, 5*time.Minute)
	if accountErr != nil {
		s.logger.Error("login account rate limit failed", "trace_id", traceIDFrom(r.Context()), "error", accountErr)
		writeError(w, r, http.StatusInternalServerError, "internal_error", "로그인을 처리하지 못했습니다.")
		return
	}
	if !accountDecision.Allowed {
		writeLoginRateLimited(w, r, accountDecision.RetryAfterSeconds)
		return
	}
	result, err := s.store.Authenticate(r.Context(), realm, input.Username, input.Password)
	if err != nil {
		s.logger.Error("password authentication failed", "trace_id", traceIDFrom(r.Context()), "error", err)
		writeError(w, r, http.StatusInternalServerError, "internal_error", "로그인을 처리하지 못했습니다.")
		return
	}
	if !result.Success {
		failureDecision, rateErr := s.store.RecordLoginFailure(r.Context(), accountBucket, 30, 5*time.Minute)
		if rateErr != nil {
			s.logger.Error("record login failure rate limit failed", "trace_id", traceIDFrom(r.Context()), "error", rateErr)
			writeError(w, r, http.StatusInternalServerError, "internal_error", "로그인을 처리하지 못했습니다.")
			return
		}
		s.audit(r, &realm.ID, nil, strings.TrimSpace(input.Username), "LOGIN_FAILURE", "FAILURE", "user", "", map[string]any{
			"reason": result.FailureReason, "rate_limited": !failureDecision.Allowed,
		})
		if !failureDecision.Allowed {
			writeLoginRateLimited(w, r, failureDecision.RetryAfterSeconds)
			return
		}
		message := "아이디 또는 비밀번호가 올바르지 않습니다."
		writeError(w, r, http.StatusUnauthorized, "invalid_credentials", message)
		return
	}
	if err := s.store.ResetLoginRateLimit(r.Context(), accountBucket); err != nil {
		s.logger.Error("reset login failure rate limit failed", "trace_id", traceIDFrom(r.Context()), "error", err)
		writeError(w, r, http.StatusInternalServerError, "internal_error", "로그인을 처리하지 못했습니다.")
		return
	}
	authMethod := result.AuthMethod
	if authMethod == "" {
		authMethod = "password"
	}
	newSession, err := s.store.CreateSession(r.Context(), realm.ID, result.User.ID,
		time.Duration(result.SessionSeconds)*time.Second, s.clientIP(r), r.UserAgent(), authMethod)
	if err != nil {
		s.logger.Error("create browser session failed", "trace_id", traceIDFrom(r.Context()), "error", err)
		writeError(w, r, http.StatusInternalServerError, "internal_error", "로그인을 처리하지 못했습니다.")
		return
	}
	s.setBrowserCookies(w, r, newSession.Token, newSession.CSRFToken, newSession.Session.ExpiresAt)
	response := map[string]any{"authenticated": true, "csrf_token": newSession.CSRFToken, "redirect_to": "/"}
	if authRequest != nil {
		consumed, err := s.store.ConsumeAuthorizationRequest(r.Context(), input.Request)
		if err != nil {
			_ = s.store.RevokeSession(r.Context(), newSession.Session.ID)
			s.clearBrowserCookies(w, r)
			writeError(w, r, http.StatusConflict, "request_already_used", "로그인 요청이 이미 처리되었습니다.")
			return
		}
		code, err := s.store.CreateAuthorizationCode(r.Context(), store.AuthorizationCode{
			RealmID: consumed.RealmID, ClientID: consumed.ClientID, UserID: result.User.ID,
			SessionID: newSession.Session.ID, RedirectURI: consumed.RedirectURI, Scope: consumed.Scope,
			Nonce: consumed.Nonce, CodeChallenge: consumed.CodeChallenge, CodeChallengeMethod: consumed.CodeChallengeMethod,
		})
		if err != nil {
			writeError(w, r, http.StatusInternalServerError, "internal_error", "인가 코드를 생성하지 못했습니다.")
			return
		}
		response["redirect_to"] = authorizationRedirect(consumed.RedirectURI, code, consumed.State, realm.IssuerURL, newSession.Session.ID)
	}
	s.audit(r, &realm.ID, &result.User.ID, result.User.Username, "LOGIN_SUCCESS", "SUCCESS", "session", newSession.Session.ID.String(), nil)
	writeJSON(w, http.StatusOK, response)
}

func writeLoginRateLimited(w http.ResponseWriter, r *http.Request, retryAfterSeconds int) {
	if retryAfterSeconds < 1 {
		retryAfterSeconds = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds))
	writeError(w, r, http.StatusTooManyRequests, "rate_limited", "로그인 요청이 너무 많습니다. 잠시 후 다시 시도하세요.")
}

func (s *Server) setBrowserCookies(w http.ResponseWriter, r *http.Request, session, csrf string, expires time.Time) {
	secure := s.requestIsSecure(r)
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: session, Path: "/", Expires: expires,
		MaxAge: int(time.Until(expires).Seconds()), HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode})
	http.SetCookie(w, &http.Cookie{Name: csrfCookieName, Value: csrf, Path: "/", Expires: expires,
		MaxAge: int(time.Until(expires).Seconds()), HttpOnly: false, Secure: secure, SameSite: http.SameSiteStrictMode})
}

func (s *Server) clearBrowserCookies(w http.ResponseWriter, r *http.Request) {
	for _, name := range []string{sessionCookieName, csrfCookieName} {
		http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", MaxAge: -1, Expires: time.Unix(1, 0),
			HttpOnly: name == sessionCookieName, Secure: s.requestIsSecure(r), SameSite: http.SameSiteLaxMode})
	}
}

func authorizationRedirect(target, code, state, issuer string, sessionID uuid.UUID) string {
	parsed, _ := url.Parse(target)
	query := parsed.Query()
	query.Set("code", code)
	if state != "" {
		query.Set("state", state)
	}
	query.Set("iss", issuer)
	query.Set("session_state", sessionID.String())
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func (s *Server) browserLogout(w http.ResponseWriter, r *http.Request) {
	session, _ := sessionFrom(r.Context())
	_ = s.store.RevokeSession(r.Context(), session.Session.ID)
	s.clearBrowserCookies(w, r)
	s.audit(r, &session.User.RealmID, &session.User.ID, session.User.Username, "LOGOUT", "SUCCESS", "session", session.Session.ID.String(), nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) audit(r *http.Request, realmID, actorID *uuid.UUID, actorName, eventType, result, targetType, targetID string, detail map[string]any) {
	err := s.store.WriteAudit(r.Context(), store.AuditEvent{RealmID: realmID, ActorID: actorID, ActorName: actorName,
		EventType: eventType, Result: result, TargetType: targetType, TargetID: targetID,
		IPAddress: s.clientIP(r), UserAgent: r.UserAgent(), TraceID: traceIDFrom(r.Context()), Detail: detail})
	if err != nil && !errors.Is(err, contextCanceled(r)) {
		s.logger.Warn("write audit event failed", "trace_id", traceIDFrom(r.Context()), "error", err)
	}
}

func userAuditDetail(before, after domain.User) map[string]any {
	return map[string]any{
		"email_changed":         !strings.EqualFold(strings.TrimSpace(before.Email), strings.TrimSpace(after.Email)),
		"email_verified_before": before.EmailVerified,
		"email_verified_after":  after.EmailVerified,
		"enabled_before":        before.Enabled,
		"enabled_after":         after.Enabled,
	}
}

func contextCanceled(r *http.Request) error { return r.Context().Err() }
