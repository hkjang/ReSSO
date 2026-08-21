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
	writeJSON(w, http.StatusOK, map[string]any{
		"user":       user,
		"roles":      roles,
		"csrf_token": cookieValue(r, csrfCookieName),
		"permissions": map[string]bool{"platform_admin": principal.PlatformAdmin,
			"realm_admin": principal.RealmAdmin, "admin": principal.PlatformAdmin || principal.RealmAdmin},
	})
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
		writeError(w, r, http.StatusBadRequest, "password_change_failed", err.Error())
		return
	}
	_ = s.store.RevokeAllUserSessions(r.Context(), principal.UserID, principal.SessionID)
	s.audit(r, &principal.RealmID, &principal.UserID, principal.Username, "PASSWORD_CHANGE", "SUCCESS", "user", principal.UserID.String(), nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) mySessions(w http.ResponseWriter, r *http.Request) {
	principal, _ := principalFrom(r.Context())
	sessions, err := s.store.ListSessions(r.Context(), nil, &principal.UserID, 100)
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
	sessions, err := s.store.ListSessions(r.Context(), nil, &principal.UserID, 500)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	owned := false
	for _, session := range sessions {
		owned = owned || session.ID == id
	}
	if !owned {
		writeError(w, r, http.StatusNotFound, "not_found", "세션을 찾을 수 없습니다.")
		return
	}
	if err := s.store.RevokeSession(r.Context(), id); err != nil {
		writeStoreError(w, r, err)
		return
	}
	s.audit(r, &principal.RealmID, &principal.UserID, principal.Username, "SESSION_REVOKE", "SUCCESS", "session", id.String(), nil)
	if principal.SessionID != nil && *principal.SessionID == id {
		s.clearBrowserCookies(w, r)
	}
	w.WriteHeader(http.StatusNoContent)
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
	requests, err := s.store.ListApprovalRequests(r.Context(), nil, &principal.UserID, nil)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": requests})
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
	requests, err := s.store.ListApprovalRequests(r.Context(), nil, nil, &principal.UserID)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": requests})
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
