package httpserver

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
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

// Every refusal this service makes is a JSON object with error, message and
// trace_id, and the OpenAPI document promises that shape for 4XX on every
// operation. Two paths did not keep it, both of them chi's defaults: an
// unrouted API path answered `404 page not found` in plain text, and a path
// that exists for another method answered 405 with no body at all — that one
// because the CORS preflight is registered as a wildcard across the protocol
// endpoints, so an unknown sub-path matches the pattern and fails on the
// method.
//
// The caller who meets these is the one who mistyped a path or called one a
// later version removed, which is exactly the caller whose error handling then
// fails on the response it was written to read.
func TestUnroutedPathsKeepTheErrorContract(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(New(nil, logger, nil, nil).Handler())
	t.Cleanup(server.Close)
	client := server.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	for _, refusal := range []struct {
		path       string
		wantStatus int
		wantError  string
	}{
		{"/api/v1/nonexistent", http.StatusNotFound, "not_found"},
		// The administration subtree authenticates before it resolves, so an
		// unauthenticated caller is refused rather than told which paths
		// exist. That is the right order, and it keeps the same shape.
		{"/api/admin/v1/realms/00000000-0000-0000-0000-000000000000/nothing-here",
			http.StatusUnauthorized, "authentication_required"},
		{"/realms/master/protocol/openid-connect/nonexistent",
			http.StatusMethodNotAllowed, "method_not_allowed"},
	} {
		response, err := client.Get(server.URL + refusal.path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if response.StatusCode != refusal.wantStatus {
			t.Errorf("%s answered %d, want %d", refusal.path, response.StatusCode, refusal.wantStatus)
		}
		if contentType := response.Header.Get("Content-Type"); !strings.HasPrefix(contentType, "application/json") {
			t.Errorf("%s answered with %q, want JSON", refusal.path, contentType)
		}
		var decoded struct {
			Error   string `json:"error"`
			Message string `json:"message"`
			TraceID string `json:"trace_id"`
		}
		if err := json.Unmarshal(body, &decoded); err != nil {
			t.Errorf("%s did not answer with a decodable body: %s", refusal.path, body)
			continue
		}
		if decoded.Error != refusal.wantError || decoded.Message == "" || decoded.TraceID == "" {
			t.Errorf("%s answered %+v, want the standard three fields", refusal.path, decoded)
		}
	}

	// And the console still gets its document for its own routes, which is
	// what the change had to leave alone: those match the catch-all rather
	// than reaching the handlers above.
	for _, appPath := range []string{"/", "/admin/users", "/nonexistent"} {
		response, err := client.Get(server.URL + appPath)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK || !strings.Contains(string(body), "<!doctype html>") {
			t.Errorf("%s answered %d %.40s, want the console document",
				appPath, response.StatusCode, body)
		}
	}
}

// Nothing is broken here today; this holds a hazard shut. /api/v1/meta is
// registered on the parent router and /api/v1 is mounted as a subtree
// afterwards, and mounting a subtree is the kind of change that can take a
// sibling route with it. The route it would take is the one the smoke test
// calls first, and the one release-image.sh documents as how somebody holding
// an archive finds the commit it was built from.
//
// TestOpenAPICoversEveryRegisteredRoute cannot see this: it walks the router,
// so a route the router still lists but no longer serves looks present. This
// asks the handler instead, which is what a caller does.
func TestPublicRoutesAreReachableAndNotShadowed(t *testing.T) {
	handler := New(nil, slog.New(slog.DiscardHandler), nil, nil).Handler()
	for _, unauthenticated := range []struct {
		path string
		want int
	}{
		// Reachable without credentials and without a store.
		{"/api/openapi.json", http.StatusOK},
		// Registered on the parent router beside a mounted subtree.
		{"/api/v1/meta", http.StatusOK},
	} {
		request := httptest.NewRequest(http.MethodGet, unauthenticated.path, nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != unauthenticated.want {
			t.Errorf("GET %s = %d, want %d; a route the router reports is not one a caller can reach",
				unauthenticated.path, response.Code, unauthenticated.want)
		}
	}
	// The mounted subtree still answers: it refuses for want of credentials
	// rather than for want of a route.
	request := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Errorf("GET /api/v1/me = %d, want %d", response.Code, http.StatusUnauthorized)
	}
}
