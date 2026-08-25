package httpserver

import (
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/hkjang/ReSSO/internal/store"
)

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	principal, _ := principalFrom(r.Context())
	user, err := s.store.UserByID(r.Context(), principal.UserID)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	roles, _ := s.store.RealmRolesForUser(r.Context(), user.ID)
	response := map[string]any{
		"user":       user,
		"roles":      roles,
		"csrf_token": cookieValue(r, csrfCookieName),
		"permissions": map[string]bool{"platform_admin": principal.PlatformAdmin,
			"realm_admin": principal.RealmAdmin, "admin": principal.PlatformAdmin || principal.RealmAdmin},
	}
	// The console needs the Realm's own policy to validate a new password
	// before submitting it, instead of guessing a minimum length and letting
	// the server reject the request.
	if realm, realmErr := s.store.RealmByID(r.Context(), user.RealmID); realmErr == nil {
		response["password_policy"] = map[string]any{
			"min_length":           realm.PasswordMinLength,
			"max_login_attempts":   realm.MaxLoginAttempts,
			"lockout_seconds":      realm.LockoutSeconds,
			"idle_timeout_seconds": realm.IdleTimeoutSeconds,
		}
	}
	writeJSON(w, http.StatusOK, response)
}

func cookieValue(r *http.Request, name string) string {
	cookie, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return cookie.Value
}

func (s *Server) updateMyProfile(w http.ResponseWriter, r *http.Request) {
	principal, _ := principalFrom(r.Context())
	var input store.UpdateProfileInput
	if !decodeJSON(w, r, &input) {
		return
	}
	current, err := s.store.UserByID(r.Context(), principal.UserID)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	user, err := s.store.UpdateProfile(r.Context(), principal.UserID, input)
	if err != nil {
		if errors.Is(err, store.ErrFederationReadOnly) {
			writeError(w, r, http.StatusConflict, "federation_read_only", "READ_ONLY LDAP 계정은 원본 디렉터리에서 수정하세요.")
			return
		}
		if errors.Is(err, store.ErrFederationOperation) {
			writeError(w, r, http.StatusBadGateway, "ldap_update_failed", "LDAP 디렉터리에서 프로필을 변경하지 못했습니다.")
			return
		}
		writeStoreError(w, r, err)
		return
	}
	s.audit(r, &principal.RealmID, &principal.UserID, principal.Username, "PROFILE_UPDATE", "SUCCESS", "user", principal.UserID.String(), userAuditDetail(current, user))
	writeJSON(w, http.StatusOK, user)
}

func (s *Server) changeMyPassword(w http.ResponseWriter, r *http.Request) {
	principal, _ := principalFrom(r.Context())
	var input struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	if err := s.store.ChangePassword(r.Context(), principal.UserID, input.CurrentPassword, input.NewPassword, false); err != nil {
		if errors.Is(err, store.ErrFederationPasswordExternal) {
			writeError(w, r, http.StatusConflict, "federation_password_external", "비밀번호는 원본 LDAP 디렉터리에서 변경하세요.")
			return
		}
		if errors.Is(err, store.ErrFederationOperation) {
			writeError(w, r, http.StatusBadGateway, "ldap_password_update_failed", "LDAP 디렉터리에서 비밀번호를 변경하지 못했습니다.")
			return
		}
		writeStoreError(w, r, err)
		return
	}
	ended, detail := s.endOtherSessions(r, principal.UserID, principal.SessionID)
	s.audit(r, &principal.RealmID, &principal.UserID, principal.Username, "PASSWORD_CHANGE",
		partialIfNot(ended), "user", principal.UserID.String(), detail)
	writeSessionsEnded(w, ended, detail,
		"비밀번호는 변경되었지만 다른 기기의 세션을 종료하지 못했습니다. `내 세션`에서 직접 종료하세요.",
		"비밀번호는 변경되었고 다른 기기의 세션도 종료했지만, 그 세션의 Refresh Token을 폐기하지 못했습니다. 연동 애플리케이션에서 계속 사용될 수 있습니다.")
}

// endOtherSessions ends the sessions a password change is meant to end and
// reports whether it worked.
//
// The password has already changed by the time this runs and cannot be taken
// back, so a failure here is no reason to refuse the request. It is every
// reason not to answer that the whole thing went fine, which is what both
// callers did: the error was dropped on the floor, the audit entry said
// SUCCESS, and the response was 204. Someone changing their password because
// they believe it is known, or an administrator resetting a compromised
// account, was told the other sessions were gone while they were still live —
// and the console states that promise on the page.
func (s *Server) endOtherSessions(r *http.Request, userID uuid.UUID, except *uuid.UUID) (bool, map[string]any) {
	err := s.store.RevokeAllUserSessions(r.Context(), userID, except)
	if err == nil {
		return true, nil
	}
	s.logger.Error("other sessions could not be fully ended after a password change",
		"trace_id", traceIDFrom(r.Context()), "user_id", userID, "error", err)
	if errors.Is(err, store.ErrRefreshTokensNotRevoked) {
		return false, map[string]any{"other_sessions_ended": true, "refresh_tokens_revoked": false, "error": err.Error()}
	}
	return false, map[string]any{"other_sessions_ended": false, "error": err.Error()}
}

// endSession revokes one session and reports whether it worked.
//
// A logout that fails to revoke is the most misleading failure the service
// has. The browser cookies are cleared either way, so the person sees
// themselves signed out — while the session stays live, every relying party
// holding a refresh token bound to it goes on renewing, and no back-channel
// logout is sent, because sending it is what the revocation does. Logging out
// is the one "make it stop" a person has, and it stopped nothing.
//
// The response is deliberately not turned into an error. The cookies are gone
// by then and there is nothing the person could do differently, so refusing
// would only leave them looking at a failure they cannot act on while being no
// more signed in than before. The audit entry is the handle that does help: it
// reads PARTIAL and names the session, so an administrator can end it from the
// console and knows to look at the relying parties.
func (s *Server) endSession(r *http.Request, sessionID uuid.UUID) (bool, map[string]any) {
	err := s.store.RevokeSession(r.Context(), sessionID)
	if err == nil {
		return true, nil
	}
	s.logger.Error("session could not be fully revoked on logout",
		"trace_id", traceIDFrom(r.Context()), "session_id", sessionID, "error", err)
	// Which half failed decides what the trail is entitled to say. Recording
	// session_revoked:false for a session that was revoked would send whoever
	// reads it to end a session that is already gone, while the refresh tokens
	// that are still live go unmentioned.
	if errors.Is(err, store.ErrRefreshTokensNotRevoked) {
		return false, map[string]any{"session_revoked": true, "refresh_tokens_revoked": false, "error": err.Error()}
	}
	return false, map[string]any{"session_revoked": false, "error": err.Error()}
}

// partialIfNot names an outcome that is neither a clean success nor a failure:
// the request did what it was asked, and something it carries with it did not.
func partialIfNot(ok bool) string {
	if ok {
		return "SUCCESS"
	}
	return "PARTIAL"
}

// writeSessionsEnded answers 204 when everything was done, and 200 with what
// was not when it was not. The unchanged status on the ordinary path keeps the
// contract these two endpoints already had.
// writeSessionEnded answers a request to end one session. It is separate from
// writeSessionsEnded because the two describe different things: there are no
// other sessions here, only this one and the refresh tokens issued from it,
// and answering with a field named other_sessions_ended would describe the
// request as something it was not.
func writeSessionEnded(w http.ResponseWriter, revokedTokens bool, message string) {
	if revokedTokens {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"session_ended": true, "refresh_tokens_revoked": false, "message": message})
}

func writeSessionsEnded(w http.ResponseWriter, ended bool, detail map[string]any, notEnded, tokensSurvived string) {
	if ended {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	// The two ways this can fall short need different sentences, and saying
	// the wrong one is worse than saying nothing. When the sessions did end
	// and only their refresh tokens survived, "the other sessions could not be
	// ended" sends somebody who changed their password because they think it
	// is known to go looking for sessions to close, and find none — while what
	// actually survived goes unmentioned.
	sessionsEnded, _ := detail["other_sessions_ended"].(bool)
	message := notEnded
	if sessionsEnded {
		message = tokensSurvived
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"other_sessions_ended": sessionsEnded, "refresh_tokens_revoked": false, "message": message})
}

func (s *Server) mySessions(w http.ResponseWriter, r *http.Request) {
	principal, _ := principalFrom(r.Context())
	sessions, _, err := s.store.ListSessions(r.Context(), nil, &principal.UserID, "", 100)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": sessions, "current_session_id": principal.SessionID})
}

func (s *Server) revokeMySession(w http.ResponseWriter, r *http.Request) {
	principal, _ := principalFrom(r.Context())
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_id", "세션 ID가 올바르지 않습니다.")
		return
	}
	// Ownership is decided by the revoking statement itself. A session that is
	// not this person's is reported as absent rather than refused, so the
	// answer says nothing about whether it exists.
	err = s.store.RevokeOwnedSession(r.Context(), id, principal.UserID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, r, http.StatusNotFound, "not_found", "세션을 찾을 수 없습니다.")
		return
	}
	// The session ending and its refresh tokens being revoked fail separately.
	// Treating the second as a failure of the whole thing answered an error
	// for a session that had ended, recorded nothing, and — when it was this
	// browser's own session — left the cookies in place for a session that no
	// longer works, so the next request fails in a way nobody can read.
	var detail map[string]any
	ended := err == nil
	switch {
	case err != nil && !errors.Is(err, store.ErrRefreshTokensNotRevoked):
		writeStoreError(w, r, err)
		return
	case err != nil:
		s.logger.Error("session ended without revoking its refresh tokens",
			"trace_id", traceIDFrom(r.Context()), "session_id", id, "error", err)
		detail = map[string]any{"session_revoked": true, "refresh_tokens_revoked": false, "error": err.Error()}
	}
	s.audit(r, &principal.RealmID, &principal.UserID, principal.Username, "SESSION_REVOKE",
		partialIfNot(ended), "session", id.String(), detail)
	if principal.SessionID != nil && *principal.SessionID == id {
		s.clearBrowserCookies(w, r)
	}
	writeSessionEnded(w, ended,
		"세션은 종료했지만 이 세션의 Refresh Token을 폐기하지 못했습니다. 연동 애플리케이션에서 계속 사용될 수 있습니다.")
}

func (s *Server) listMyAPIKeys(w http.ResponseWriter, r *http.Request) {
	principal, _ := principalFrom(r.Context())
	keys, err := s.store.ListPersonalAPIKeys(r.Context(), principal.UserID)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": keys})
}

func validAPIKeyScopes(scopes []string, platformAdmin bool) bool {
	allowed := []string{"api:read", "mcp:read"}
	if platformAdmin {
		allowed = append(allowed, "admin:read")
	}
	if len(scopes) == 0 {
		return false
	}
	for _, scope := range scopes {
		if !slices.Contains(allowed, scope) {
			return false
		}
	}
	return true
}

func (s *Server) createMyAPIKey(w http.ResponseWriter, r *http.Request) {
	principal, _ := principalFrom(r.Context())
	var input struct {
		Name        string   `json:"name"`
		Scopes      []string `json:"scopes"`
		ExpiresDays int      `json:"expires_days"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	if !validAPIKeyScopes(input.Scopes, principal.PlatformAdmin || principal.RealmAdmin) || input.ExpiresDays < 1 || input.ExpiresDays > 365 {
		writeError(w, r, http.StatusBadRequest, "invalid_api_key", "권한 범위 또는 만료 기간(1~365일)이 올바르지 않습니다.")
		return
	}
	expires := time.Now().UTC().Add(time.Duration(input.ExpiresDays) * 24 * time.Hour)
	created, err := s.store.CreatePersonalAPIKey(r.Context(), principal.UserID, input.Name, input.Scopes, &expires, nil)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "api_key_creation_failed", err.Error())
		return
	}
	s.audit(r, &principal.RealmID, &principal.UserID, principal.Username, "API_KEY_CREATE", "SUCCESS", "api_key", created.Key.ID.String(), map[string]any{"scopes": input.Scopes})
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) rotateMyAPIKey(w http.ResponseWriter, r *http.Request) {
	principal, _ := principalFrom(r.Context())
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_id", "API 키 ID가 올바르지 않습니다.")
		return
	}
	created, err := s.store.RotatePersonalAPIKey(r.Context(), principal.UserID, id)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	s.audit(r, &principal.RealmID, &principal.UserID, principal.Username, "API_KEY_ROTATE", "SUCCESS", "api_key", created.Key.ID.String(), map[string]any{"rotated_from": id})
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) revokeMyAPIKey(w http.ResponseWriter, r *http.Request) {
	principal, _ := principalFrom(r.Context())
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_id", "API 키 ID가 올바르지 않습니다.")
		return
	}
	if err := s.store.RevokePersonalAPIKey(r.Context(), principal.UserID, id); err != nil {
		writeStoreError(w, r, err)
		return
	}
	s.audit(r, &principal.RealmID, &principal.UserID, principal.Username, "API_KEY_REVOKE", "SUCCESS", "api_key", id.String(), nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) myApprovalCapability(w http.ResponseWriter, r *http.Request) {
	principal, _ := principalFrom(r.Context())
	enabled, err := s.store.ApprovalEnabled(r.Context(), principal.RealmID)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": enabled})
}

func (s *Server) myRequestableRoles(w http.ResponseWriter, r *http.Request) {
	principal, _ := principalFrom(r.Context())
	enabled, err := s.store.ApprovalEnabled(r.Context(), principal.RealmID)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	if !enabled {
		writeError(w, r, http.StatusNotFound, "approval_disabled", "이 Realm에는 승인 절차가 설정되어 있지 않습니다.")
		return
	}
	roles, err := s.store.ListRoles(r.Context(), principal.RealmID)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": roles})
}

func (s *Server) listMyRequests(w http.ResponseWriter, r *http.Request) {
	principal, _ := principalFrom(r.Context())
	requests, more, err := s.store.ListApprovalRequests(r.Context(), nil, &principal.UserID, nil)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": requests, "truncated": more})
}

func (s *Server) createMyRequest(w http.ResponseWriter, r *http.Request) {
	principal, _ := principalFrom(r.Context())
	var input struct {
		RoleID uuid.UUID `json:"role_id"`
		Reason string    `json:"reason"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	user, err := s.store.UserByID(r.Context(), principal.UserID)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	request, err := s.store.CreateRoleApprovalRequest(r.Context(), user, input.RoleID, input.Reason)
	if err != nil {
		if err == store.ErrNotFound {
			writeError(w, r, http.StatusNotFound, "approval_disabled", "이 Realm에는 검토·승인 절차가 설정되어 있지 않습니다.")
		} else {
			writeError(w, r, http.StatusBadRequest, "invalid_request", err.Error())
		}
		return
	}
	s.audit(r, &principal.RealmID, &principal.UserID, principal.Username, "APPROVAL_REQUEST_CREATE", "SUCCESS", "approval", request.ID.String(), nil)
	writeJSON(w, http.StatusCreated, request)
}

func (s *Server) listMyReviews(w http.ResponseWriter, r *http.Request) {
	principal, _ := principalFrom(r.Context())
	requests, more, err := s.store.ListApprovalRequests(r.Context(), nil, nil, &principal.UserID)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": requests, "truncated": more})
}

func (s *Server) decideMyReview(w http.ResponseWriter, r *http.Request) {
	principal, _ := principalFrom(r.Context())
	requestID, ok := parseUUIDParam(w, r, "requestID")
	if !ok {
		return
	}
	var input struct {
		Decision string `json:"decision"`
		Note     string `json:"note"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	if input.Decision != "approve" && input.Decision != "reject" {
		writeError(w, r, http.StatusBadRequest, "invalid_decision", "approve 또는 reject를 지정하세요.")
		return
	}
	request, err := s.store.DecideApprovalRequest(r.Context(), requestID, principal.UserID,
		principal.PlatformAdmin, false, uuid.Nil, input.Decision == "approve", input.Note)
	if err != nil {
		writeError(w, r, http.StatusForbidden, "decision_failed", err.Error())
		return
	}
	s.audit(r, &request.RealmID, &principal.UserID, principal.Username, "TEAM_LEAD_APPROVAL_DECISION", "SUCCESS",
		"approval", request.ID.String(), map[string]any{"decision": request.Status})
	writeJSON(w, http.StatusOK, request)
}
