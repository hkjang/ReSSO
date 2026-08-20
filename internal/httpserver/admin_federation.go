package httpserver

import (
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
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "ldap_federation_update_failed", err.Error())
		return
	}
	principal, _ := principalFrom(r.Context())
	s.audit(r, &realmID, &principal.UserID, principal.Username, "LDAP_FEDERATION_UPDATE", "SUCCESS",
		"user_federation", item.ID.String(), map[string]any{"enabled": item.Enabled, "edit_mode": item.EditMode})
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
	if err := s.store.DeleteLDAPFederation(r.Context(), federationID, unlinkUsers); err != nil {
		writeError(w, r, http.StatusConflict, "ldap_federation_in_use", "가져온 사용자가 남아 있어 삭제할 수 없습니다. 공급자를 비활성화하거나 연결된 사용자를 먼저 정리하세요.")
		return
	}
	principal, _ := principalFrom(r.Context())
	s.audit(r, &realmID, &principal.UserID, principal.Username, "LDAP_FEDERATION_DELETE", "SUCCESS",
		"user_federation", federationID.String(), map[string]any{"name": item.Name, "users_unlinked": unlinkUsers})
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

func (s *Server) adminSyncLDAPFederation(w http.ResponseWriter, r *http.Request) {
	realmID, federationID, ok := federationParams(w, r)
	if !ok || !s.ensureFederationRealm(w, r, realmID, federationID) {
		return
	}
	summary, err := s.store.SyncLDAPFederation(r.Context(), federationID)
	principal, _ := principalFrom(r.Context())
	result := "SUCCESS"
	if err != nil {
		result = "FAILURE"
	}
	s.audit(r, &realmID, &principal.UserID, principal.Username, "LDAP_FEDERATION_SYNC", result,
		"user_federation", federationID.String(), map[string]any{"read": summary.Read, "added": summary.Added,
			"updated": summary.Updated, "failed": summary.Failed, "disabled": summary.Disabled})
	if err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": "ldap_sync_failed", "message": err.Error(),
			"trace_id": traceIDFrom(r.Context()), "summary": summary})
		return
	}
	writeJSON(w, http.StatusOK, summary)
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
