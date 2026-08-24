package httpserver

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/hkjang/ReSSO/internal/store"
)

func (s *Server) adminListLDAPFederations(w http.ResponseWriter, r *http.Request) {
	realmID, ok := parseUUIDParam(w, r, "realmID")
	if !ok {
		return
	}
	items, err := s.store.ListLDAPFederations(r.Context(), realmID)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) adminGetLDAPFederation(w http.ResponseWriter, r *http.Request) {
	realmID, federationID, ok := federationParams(w, r)
	if !ok {
		return
	}
	item, err := s.store.LDAPFederationByID(r.Context(), federationID)
	if err != nil || item.RealmID != realmID {
		writeStoreError(w, r, store.ErrNotFound)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) adminCreateLDAPFederation(w http.ResponseWriter, r *http.Request) {
	realmID, ok := parseUUIDParam(w, r, "realmID")
	if !ok {
		return
	}
	var input store.LDAPFederationInput
	if !decodeJSON(w, r, &input) {
		return
	}
	item, err := s.store.CreateLDAPFederation(r.Context(), realmID, input)
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeStoreError(w, r, err)
			return
		}
		writeError(w, r, http.StatusBadRequest, "ldap_federation_creation_failed", err.Error())
		return
	}
	principal, _ := principalFrom(r.Context())
	s.audit(r, &realmID, &principal.UserID, principal.Username, "LDAP_FEDERATION_CREATE", "SUCCESS",
		"user_federation", item.ID.String(), map[string]any{"name": item.Name, "vendor": item.Vendor})
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) adminUpdateLDAPFederation(w http.ResponseWriter, r *http.Request) {
	realmID, federationID, ok := federationParams(w, r)
	if !ok {
		return
	}
	current, err := s.store.LDAPFederationByID(r.Context(), federationID)
	if err != nil || current.RealmID != realmID {
		writeStoreError(w, r, store.ErrNotFound)
		return
	}
	var input store.LDAPFederationInput
	if !decodeJSON(w, r, &input) {
		return
	}
	item, err := s.store.UpdateLDAPFederation(r.Context(), federationID, input)
	// Disabling a provider signs its people out, and that can fall short after
	// the provider is already disabled. Answering a failure for it would
	// describe a change that happened as one that did not, and leave the trail
	// without the entry saying the provider was switched off.
	signedOut := !errors.Is(err, store.ErrUsersNotSignedOut)
	if err != nil && signedOut {
		if errors.Is(err, store.ErrConflict) {
			writeStoreError(w, r, err)
			return
		}
		writeError(w, r, http.StatusBadRequest, "ldap_federation_update_failed", err.Error())
		return
	}
	detail := map[string]any{"enabled": item.Enabled, "edit_mode": item.EditMode}
	if !signedOut {
		s.logger.Error("a disabled LDAP provider's people were not signed out everywhere",
			"trace_id", traceIDFrom(r.Context()), "federation_id", federationID, "error", err)
		detail["users_signed_out"] = false
		detail["error"] = err.Error()
	}
	principal, _ := principalFrom(r.Context())
	s.audit(r, &realmID, &principal.UserID, principal.Username, "LDAP_FEDERATION_UPDATE",
		partialIfNot(signedOut), "user_federation", item.ID.String(), detail)
	writeJSON(w, http.StatusOK, item)
}

func (s *Server) adminDeleteLDAPFederation(w http.ResponseWriter, r *http.Request) {
	realmID, federationID, ok := federationParams(w, r)
	if !ok {
		return
	}
	item, err := s.store.LDAPFederationByID(r.Context(), federationID)
	if err != nil || item.RealmID != realmID {
		writeStoreError(w, r, store.ErrNotFound)
		return
	}
	unlinkUsers := r.URL.Query().Get("unlink_users") == "true"
	err = s.store.DeleteLDAPFederation(r.Context(), federationID, unlinkUsers)
	// Only a conflict means what this message says. Answering it for every
	// failure told an administrator to clear the imported users when that was
	// not the problem — and clearing them is a destructive step to take on a
	// wrong diagnosis.
	switch {
	case errors.Is(err, store.ErrConflict):
		writeError(w, r, http.StatusConflict, "ldap_federation_in_use",
			"가져온 사용자가 남아 있어 삭제할 수 없습니다. 공급자를 비활성화하거나 연결된 사용자를 먼저 정리하세요.")
		return
	case err != nil && !errors.Is(err, store.ErrUsersNotSignedOut):
		writeStoreError(w, r, err)
		return
	}
	signedOut := err == nil
	detail := map[string]any{"name": item.Name, "users_unlinked": unlinkUsers}
	if !signedOut {
		s.logger.Error("an unlinked LDAP provider's people were not signed out everywhere",
			"trace_id", traceIDFrom(r.Context()), "federation_id", federationID, "error", err)
		detail["users_signed_out"] = false
		detail["error"] = err.Error()
	}
	principal, _ := principalFrom(r.Context())
	s.audit(r, &realmID, &principal.UserID, principal.Username, "LDAP_FEDERATION_DELETE",
		partialIfNot(signedOut), "user_federation", federationID.String(), detail)
	if !signedOut {
		writeJSON(w, http.StatusOK, map[string]any{"deleted": true, "users_signed_out": false,
			"message": "공급자는 삭제했지만 연결된 계정을 모든 애플리케이션에서 로그아웃시키지 못했습니다. 관리 → 세션에서 확인하세요."})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) adminTestLDAPConnection(w http.ResponseWriter, r *http.Request) {
	realmID, federationID, ok := federationParams(w, r)
	if !ok || !s.ensureFederationRealm(w, r, realmID, federationID) {
		return
	}
	started := time.Now()
	err := s.store.TestLDAPFederation(r.Context(), federationID)
	principal, _ := principalFrom(r.Context())
	result := "SUCCESS"
	if err != nil {
		result = "FAILURE"
	}
	s.audit(r, &realmID, &principal.UserID, principal.Username, "LDAP_CONNECTION_TEST", result,
		"user_federation", federationID.String(), map[string]any{"duration_ms": time.Since(started).Milliseconds()})
	if err != nil {
		writeError(w, r, http.StatusUnprocessableEntity, "ldap_connection_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"connected": true, "duration_ms": time.Since(started).Milliseconds()})
}

func (s *Server) adminTestLDAPAuthentication(w http.ResponseWriter, r *http.Request) {
	realmID, federationID, ok := federationParams(w, r)
	if !ok || !s.ensureFederationRealm(w, r, realmID, federationID) {
		return
	}
	var input struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	if strings.TrimSpace(input.Username) == "" || input.Password == "" {
		writeError(w, r, http.StatusBadRequest, "invalid_request", "사용자 아이디와 비밀번호가 필요합니다.")
		return
	}
	result, err := s.store.TestLDAPAuthentication(r.Context(), federationID, input.Username, input.Password)
	principal, _ := principalFrom(r.Context())
	auditResult := "SUCCESS"
	if err != nil {
		auditResult = "FAILURE"
	}
	s.audit(r, &realmID, &principal.UserID, principal.Username, "LDAP_AUTHENTICATION_TEST", auditResult,
		"user_federation", federationID.String(), map[string]any{"test_username": strings.TrimSpace(input.Username)})
	if err != nil {
		writeError(w, r, http.StatusUnauthorized, "ldap_authentication_failed", "LDAP 사용자 인증에 실패했습니다.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": true, "user": result})
}

// ldapSyncTimeout bounds a manually started run. It matches the window after
// which store.SyncLDAPFederation treats a claim as abandoned.
const ldapSyncTimeout = 30 * time.Minute

func (s *Server) adminSyncLDAPFederation(w http.ResponseWriter, r *http.Request) {
	realmID, federationID, ok := federationParams(w, r)
	if !ok || !s.ensureFederationRealm(w, r, realmID, federationID) {
		return
	}
	// A full synchronization walks the entire directory and routinely outlives
	// the server's write timeout, so running it inside the request left the
	// administrator staring at a failed request while the work continued, with
	// nothing to stop them starting a second one. It is started here and
	// followed through the provider's own last_sync fields instead.
	if running, err := s.store.LDAPSyncRunning(r.Context(), federationID); err != nil {
		writeStoreError(w, r, err)
		return
	} else if running {
		writeError(w, r, http.StatusConflict, "sync_in_progress", "이미 동기화가 진행 중입니다. 완료된 뒤 다시 시도하세요.")
		return
	}
	principal, _ := principalFrom(r.Context())
	s.audit(r, &realmID, &principal.UserID, principal.Username, "LDAP_FEDERATION_SYNC_STARTED", "SUCCESS",
		"user_federation", federationID.String(), nil)
	// Detach from the request so writing the response does not cancel the run,
	// while keeping the trace identifier for the log lines it produces.
	syncCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), ldapSyncTimeout)
	traceID := traceIDFrom(r.Context())
	go func() {
		defer cancel()
		summary, err := s.store.SyncLDAPFederation(syncCtx, federationID)
		// The response above sends the administrator to the provider's own
		// last_sync fields to follow this. When the run could not record its
		// outcome, those fields are the one place that will not say so, and
		// neither will the audit trail — so this line is all that is left.
		if summary.RecordError != "" {
			s.logger.Error("LDAP federation sync finished but its outcome was not recorded; "+
				"the provider still shows the previous run and the audit trail has no entry for this one",
				"trace_id", traceID, "federation_id", federationID, "read", summary.Read,
				"added", summary.Added, "disabled", summary.Disabled, "error", summary.RecordError)
		}
		if err != nil {
			s.logger.Error("LDAP federation sync failed", "trace_id", traceID, "federation_id", federationID,
				"read", summary.Read, "failed", summary.Failed, "error", err)
			return
		}
		s.logger.Info("LDAP federation sync completed", "trace_id", traceID, "federation_id", federationID,
			"read", summary.Read, "added", summary.Added, "updated", summary.Updated, "disabled", summary.Disabled)
	}()
	writeJSON(w, http.StatusAccepted, map[string]any{"status": "RUNNING",
		"message": "동기화를 시작했습니다. 진행 상황은 목록의 동기화 상태에서 확인할 수 있습니다."})
}

func federationParams(w http.ResponseWriter, r *http.Request) (uuid.UUID, uuid.UUID, bool) {
	realmID, ok := parseUUIDParam(w, r, "realmID")
	if !ok {
		return uuid.Nil, uuid.Nil, false
	}
	federationID, ok := parseUUIDParam(w, r, "federationID")
	return realmID, federationID, ok
}

func (s *Server) ensureFederationRealm(w http.ResponseWriter, r *http.Request, realmID, federationID uuid.UUID) bool {
	item, err := s.store.LDAPFederationByID(r.Context(), federationID)
	if err != nil || item.RealmID != realmID {
		writeStoreError(w, r, store.ErrNotFound)
		return false
	}
	return true
}
