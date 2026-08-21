package httpserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hkjang/ReSSO/internal/store"
)

func TestWriteStoreErrorMapsInvalidInputToBadRequest(t *testing.T) {
	request := httptest.NewRequest(http.MethodPut, "/api/v1/me/profile", nil)
	response := httptest.NewRecorder()
	writeStoreError(response, request, fmt.Errorf("%w: invalid email", store.ErrInvalidInput))

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d; want %d", response.Code, http.StatusBadRequest)
	}
	var body apiError
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Error != "invalid_input" {
		t.Fatalf("error code = %q; want invalid_input", body.Error)
	}
}
