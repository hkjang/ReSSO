package httpserver

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/hkjang/ReSSO/internal/domain"
	"github.com/hkjang/ReSSO/internal/mail"
)

// Mail exposes the notification service so the process can hand it to the
// background workers and wait for it on shutdown.
func (s *Server) Mail() *mail.Service { return s.mail }

// mailView is what the settings screen reads: every setting without the
// password, whether a password is set, and the switches it can flip.
func (s *Server) mailView(ctx context.Context) (map[string]any, error) {
	values, err := s.store.MailSettings(ctx)
	if err != nil {
		return nil, err
	}
	password, _ := values[mail.KeyPassword].(string)
	return map[string]any{
		"settings":     mail.View(values),
		"password_set": strings.TrimSpace(password) != "",
		"events":       mail.Events,
	}, nil
}

func (s *Server) adminGetMail(w http.ResponseWriter, r *http.Request) {
	view, err := s.mailView(r.Context())
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

// adminUpdateMail saves the settings. The password is separate from the
// rest: absent or empty leaves the stored one alone, so saving the screen
// never needs it typed again, and clear_password removes it.
func (s *Server) adminUpdateMail(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Settings      map[string]any `json:"settings"`
		Password      string         `json:"password"`
		ClearPassword bool           `json:"clear_password"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	values := map[string]any{}
	for key, value := range input.Settings {
		if key == mail.KeyPassword {
			// The view never carries it, so a client echoing the view back
			// cannot be saying anything about it.
			continue
		}
		values[key] = value
	}
	if password := strings.TrimSpace(input.Password); password != "" {
		values[mail.KeyPassword] = password
	}
	principal, _ := principalFrom(r.Context())
	if err := s.store.SaveMailSettings(r.Context(), values, &principal.UserID); err != nil {
		writeStoreError(w, r, err)
		return
	}
	if input.ClearPassword && strings.TrimSpace(input.Password) == "" {
		if err := s.store.ClearMailPassword(r.Context()); err != nil {
			writeStoreError(w, r, err)
			return
		}
	}
	view, err := s.mailView(r.Context())
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	// Which keys changed, never their values: the host and sender are not
	// secret, but the password is, and a trail that names one is easier
	// to keep than one that has to decide.
	changed := make([]string, 0, len(values))
	for key := range values {
		changed = append(changed, key)
	}
	enabled, _ := view["settings"].(map[string]any)[mail.KeyEnabled].(bool)
	s.audit(r, nil, &principal.UserID, principal.Username, "MAIL_SETTINGS_UPDATE", "SUCCESS", "platform_setting", "mail",
		map[string]any{"enabled": enabled, "changed": changed, "password_cleared": input.ClearPassword})
	writeJSON(w, http.StatusOK, view)
}

// adminSendTestMail proves the relay works with the saved settings before
// anybody depends on it. The outcome is answered in the response and, like
// every other send, recorded.
func (s *Server) adminSendTestMail(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Recipient string `json:"recipient"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	recipient := strings.TrimSpace(input.Recipient)
	if !strings.Contains(recipient, "@") {
		writeError(w, r, http.StatusBadRequest, "invalid_recipient", "받는 사람은 메일 주소여야 합니다.")
		return
	}
	principal, _ := principalFrom(r.Context())
	err := s.mail.SendNow(r.Context(), mail.TestMessage(), principal.UserID, recipient)
	s.audit(r, nil, &principal.UserID, principal.Username, "MAIL_TEST_SEND", auditResult(err), "mail", recipient, nil)
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, map[string]any{"sent": true, "recipient": recipient})
	case errors.Is(err, mail.ErrDisabled):
		writeError(w, r, http.StatusConflict, "mail_disabled", "메일 알림이 꺼져 있습니다. 먼저 켜고 저장하세요.")
	case errors.Is(err, mail.ErrInvalid):
		writeError(w, r, http.StatusBadRequest, "mail_invalid", err.Error())
	default:
		// The relay's answer is the whole point of the test, so it is
		// passed through — it names the step that failed and what the
		// relay said, which is what fixes the settings.
		writeError(w, r, http.StatusBadGateway, "mail_send_failed", err.Error())
	}
}

func auditResult(err error) string {
	if err != nil {
		return "FAILURE"
	}
	return "SUCCESS"
}

func (s *Server) adminListMailDeliveries(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	page, err := s.store.ListMailDeliveries(r.Context(), r.URL.Query().Get("status"), limit)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}

// notifyApprovalRequested tells whoever can decide a new request that it is
// waiting. Everything here is best effort: the request was created, and the
// mail is a courtesy the requester's response does not depend on.
func (s *Server) notifyApprovalRequested(r *http.Request, request domain.ApprovalRequest) {
	// The lookups below outlive the response only by moments, but the
	// request context ends with the response and must not end them.
	ctx := context.WithoutCancel(r.Context())
	reviewers, err := s.store.ApprovalReviewers(ctx, request)
	if err != nil {
		s.logger.Warn("approval reviewers could not be resolved for the notification mail",
			"trace_id", traceIDFrom(ctx), "request_id", request.ID, "error", err)
		return
	}
	requester, realm, role, err := s.store.ApprovalRequestNames(ctx, request)
	if err != nil {
		s.logger.Warn("approval request names could not be resolved for the notification mail",
			"trace_id", traceIDFrom(ctx), "request_id", request.ID, "error", err)
		return
	}
	s.mail.Notify(ctx, mail.ApprovalRequested(requester, realm, role, request.Reason, request.ID.String()), request.RequesterID, reviewers)
}

// notifyApprovalDecided tells the requester. The reviewer is the actor, so a
// request an administrator both raised and decided sends nothing.
func (s *Server) notifyApprovalDecided(r *http.Request, request domain.ApprovalRequest, reviewerID uuid.UUID) {
	ctx := context.WithoutCancel(r.Context())
	_, realm, role, err := s.store.ApprovalRequestNames(ctx, request)
	if err != nil {
		s.logger.Warn("approval request names could not be resolved for the notification mail",
			"trace_id", traceIDFrom(ctx), "request_id", request.ID, "error", err)
		return
	}
	s.mail.Notify(ctx, mail.ApprovalDecided(realm, role, request.Status, request.DecisionNote, request.ID.String()),
		reviewerID, []uuid.UUID{request.RequesterID})
}
