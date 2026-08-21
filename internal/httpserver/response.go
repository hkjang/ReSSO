package httpserver

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/hkjang/ReSSO/internal/store"
)

type apiError struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	TraceID string `json:"trace_id,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	writeJSON(w, status, apiError{Error: code, Message: message, TraceID: traceIDFrom(r.Context())})
}

func writeStoreError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, store.ErrInvalidInput):
		writeError(w, r, http.StatusBadRequest, "invalid_input", "입력값이 올바르지 않습니다.")
	case errors.Is(err, store.ErrNotFound):
		writeError(w, r, http.StatusNotFound, "not_found", "요청한 항목을 찾을 수 없습니다.")
	case errors.Is(err, store.ErrConflict):
		writeError(w, r, http.StatusConflict, "conflict", "동일한 항목이 이미 존재합니다.")
	default:
		writeError(w, r, http.StatusInternalServerError, "internal_error", "요청을 처리하지 못했습니다.")
	}
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_request", "요청 본문 형식이 올바르지 않습니다.")
		return false
	}
	return true
}
