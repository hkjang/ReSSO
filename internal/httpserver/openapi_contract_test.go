package httpserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

func TestOpenAPIIncludesUserMutationContracts(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/api/openapi.json", nil)
	response := httptest.NewRecorder()
	(&Server{}).openAPISpec(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d; want %d", response.Code, http.StatusOK)
	}
	var spec map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &spec); err != nil {
		t.Fatal(err)
	}
	paths := spec["paths"].(map[string]any)
	userPath, ok := paths["/api/admin/v1/realms/{realmID}/users/{userID}"].(map[string]any)
	if !ok || userPath["put"] == nil {
		t.Fatalf("user PUT path missing: %#v", userPath)
	}
	if parameters, ok := userPath["parameters"].([]any); !ok || len(parameters) != 2 {
		t.Fatalf("user path parameters = %#v; want realmID and userID", userPath["parameters"])
	}
	passwordPath, ok := paths["/api/admin/v1/realms/{realmID}/users/{userID}/password"].(map[string]any)
	if !ok || passwordPath["put"] == nil {
		t.Fatalf("password PUT path missing: %#v", passwordPath)
	}
	components := spec["components"].(map[string]any)
	schemas := components["schemas"].(map[string]any)
	for _, name := range []string{"OptionalEmail", "User", "CreateUserInput", "UpdateUserInput", "UpdateProfileInput", "ResetPasswordInput"} {
		if schemas[name] == nil {
			t.Errorf("schema %q missing", name)
		}
	}
	for path, rawPath := range paths {
		pathItem := rawPath.(map[string]any)
		declared := map[string]bool{}
		if parameters, ok := pathItem["parameters"].([]any); ok {
			for _, rawParameter := range parameters {
				parameter := rawParameter.(map[string]any)
				if parameter["in"] == "path" {
					declared[parameter["name"].(string)] = true
				}
			}
		}
		remaining := path
		for {
			start := strings.IndexByte(remaining, '{')
			if start < 0 {
				break
			}
			end := strings.IndexByte(remaining[start:], '}')
			if end < 0 {
				t.Fatalf("malformed path template %q", path)
			}
			name := remaining[start+1 : start+end]
			if !declared[name] {
				t.Errorf("path %q does not declare parameter %q", path, name)
			}
			remaining = remaining[start+end+1:]
		}
	}
}

// TestOpenAPICoversEveryRegisteredRoute walks the router and fails when a route
// the server answers is absent from the document it publishes as its contract.
// Twenty-five routes were missing when this was written, including login and
// logout, so a client generated from the document covered about half the API.
func TestOpenAPICoversEveryRegisteredRoute(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/api/openapi.json", nil)
	response := httptest.NewRecorder()
	(&Server{}).openAPISpec(response, request)
	var spec map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &spec); err != nil {
		t.Fatal(err)
	}
	paths, ok := spec["paths"].(map[string]any)
	if !ok {
		t.Fatal("spec has no paths object")
	}

	router, ok := New(nil, nil, nil, nil).Handler().(*chi.Mux)
	if !ok {
		t.Fatal("handler is not a chi router")
	}
	var missing []string
	walkErr := chi.Walk(router, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		// The OIDC protocol contract lives in each Realm's discovery document,
		// and the SPA fallback is not an API route.
		route = strings.TrimSuffix(route, "/")
		if !strings.HasPrefix(route, "/api/") {
			return nil
		}
		item, ok := paths[route].(map[string]any)
		if !ok {
			missing = append(missing, method+" "+route)
			return nil
		}
		if item[strings.ToLower(method)] == nil {
			missing = append(missing, method+" "+route)
		}
		return nil
	})
	if walkErr != nil {
		t.Fatal(walkErr)
	}
	if len(missing) > 0 {
		t.Fatalf("routes missing from the OpenAPI document:\n  %s", strings.Join(missing, "\n  "))
	}
}

// The console offers this document as the API contract and the service
// promises a consistent error format, so every operation has to describe what
// a refusal looks like — and every schema it points at has to exist, since a
// dangling $ref breaks generation for the whole document, not just one path.
func TestOpenAPIDescribesErrorsAndResolvesEveryReference(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/api/openapi.json", nil)
	response := httptest.NewRecorder()
	(&Server{}).openAPISpec(response, request)
	var document map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	components, _ := document["components"].(map[string]any)
	schemas, _ := components["schemas"].(map[string]any)
	if _, ok := schemas["Error"]; !ok {
		t.Fatal("the document defines no Error schema")
	}

	paths, _ := document["paths"].(map[string]any)
	if len(paths) == 0 {
		t.Fatal("the document defines no paths")
	}
	for path, rawItem := range paths {
		item, _ := rawItem.(map[string]any)
		for method, rawOperation := range item {
			if method == "parameters" {
				continue
			}
			operation, _ := rawOperation.(map[string]any)
			responses, _ := operation["responses"].(map[string]any)
			for _, status := range []string{"4XX", "5XX"} {
				response, ok := responses[status].(map[string]any)
				if !ok {
					t.Errorf("%s %s does not describe a %s response", method, path, status)
					continue
				}
				if _, ok := response["content"]; !ok {
					t.Errorf("%s %s describes %s without a body schema", method, path, status)
				}
			}
		}
	}

	for _, ref := range collectRefs(document) {
		name, found := strings.CutPrefix(ref, "#/components/schemas/")
		if !found {
			t.Errorf("unexpected reference form: %s", ref)
			continue
		}
		if _, ok := schemas[name]; !ok {
			t.Errorf("the document references a schema it does not define: %s", name)
		}
	}
}

// collectRefs walks the decoded document and returns every $ref value.
func collectRefs(node any) []string {
	switch typed := node.(type) {
	case map[string]any:
		refs := make([]string, 0)
		for key, value := range typed {
			if key == "$ref" {
				if ref, ok := value.(string); ok {
					refs = append(refs, ref)
				}
				continue
			}
			refs = append(refs, collectRefs(value)...)
		}
		return refs
	case []any:
		refs := make([]string, 0)
		for _, value := range typed {
			refs = append(refs, collectRefs(value)...)
		}
		return refs
	}
	return nil
}

// The method label comes off the request line, and any RFC 7230 token is a
// valid method. Recording it verbatim let an unauthenticated caller mint a new
// time series per request: memory the registry never reclaims, and a /metrics
// response that grows with it until the operator's own scrape is the problem.
func TestMethodLabelIsBounded(t *testing.T) {
	for _, method := range []string{
		http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut,
		http.MethodPatch, http.MethodDelete, http.MethodOptions,
	} {
		if got := methodLabel(method); got != method {
			t.Errorf("methodLabel(%q) = %q, want it unchanged", method, got)
		}
	}
	for _, invented := range []string{"QUUX", "PROPFIND", "x", "", strings.Repeat("A", 64)} {
		if got := methodLabel(invented); got != "other" {
			t.Errorf("methodLabel(%q) = %q, want other", invented, got)
		}
	}
}

// Six operations can finish having done what was asked while a second step
// fell short — ending sessions, revoking the refresh tokens issued from them,
// signing a provider's accounts out. Each answers 200 with a body describing
// that instead of the 204 or the plain item a caller would otherwise expect,
// and each records PARTIAL in the trail.
//
// This is the step that kept getting missed. The store learned to report the
// shortfall, then the handlers, then the responses, then the screens — and the
// document that clients are generated from was last each time. A client built
// from a document that promises only 204 has no place to put the sentence
// saying the accounts are still signed in elsewhere.
func TestPartialOutcomesAreDeclaredWhereTheyCanHappen(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/api/openapi.json", nil)
	response := httptest.NewRecorder()
	(&Server{}).openAPISpec(response, request)
	var document map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	paths, _ := document["paths"].(map[string]any)
	components, _ := document["components"].(map[string]any)
	schemas, _ := components["schemas"].(map[string]any)

	for _, partial := range []struct{ path, method string }{
		{"/api/v1/me/password", "put"},
		{"/api/admin/v1/realms/{realmID}/users/{userID}/password", "put"},
		{"/api/v1/auth/logout", "post"},
		{"/api/v1/me/sessions/{id}", "delete"},
		{"/api/admin/v1/realms/{realmID}/sessions/{sessionID}", "delete"},
		{"/api/admin/v1/realms/{realmID}/user-federations/{federationID}", "put"},
		{"/api/admin/v1/realms/{realmID}/user-federations/{federationID}", "delete"},
	} {
		item, ok := paths[partial.path].(map[string]any)
		if !ok {
			t.Errorf("%s is not in the document at all", partial.path)
			continue
		}
		operation, ok := item[partial.method].(map[string]any)
		if !ok {
			t.Errorf("%s %s is not in the document", partial.method, partial.path)
			continue
		}
		responses, _ := operation["responses"].(map[string]any)
		success, ok := responses["200"].(map[string]any)
		if !ok {
			t.Errorf("%s %s can answer 200 with what fell short, and the document does not say so",
				partial.method, partial.path)
			continue
		}
		content, ok := success["content"].(map[string]any)
		if !ok {
			t.Errorf("%s %s declares 200 without a body, so a client has nowhere to read the reason",
				partial.method, partial.path)
			continue
		}
		media, _ := content["application/json"].(map[string]any)
		schema, _ := media["schema"].(map[string]any)
		ref, _ := schema["$ref"].(string)
		name, found := strings.CutPrefix(ref, "#/components/schemas/")
		if !found || schemas[name] == nil {
			t.Errorf("%s %s declares a 200 body the document does not define: %q",
				partial.method, partial.path, ref)
		}
	}
}

// The other direction. TestOpenAPICoversEveryRegisteredRoute walks the router
// and requires the document to describe what it finds, which cannot notice a
// path the document describes and nothing serves - deleting a route makes that
// test pass, because there is one less route to look up. What is left is a
// document that sends whoever follows it to a 404 while insisting the endpoint
// is there, and a generated client with a method that cannot work. Both
// directions are needed for the document to mean anything.
func TestOpenAPIDescribesNothingThatIsNotThere(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/api/openapi.json", nil)
	response := httptest.NewRecorder()
	(&Server{}).openAPISpec(response, request)
	var spec map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &spec); err != nil {
		t.Fatal(err)
	}
	paths, ok := spec["paths"].(map[string]any)
	if !ok {
		t.Fatal("spec has no paths object")
	}

	router, ok := New(nil, nil, nil, nil).Handler().(*chi.Mux)
	if !ok {
		t.Fatal("handler is not a chi router")
	}
	type key struct{ method, route string }
	served := map[key]bool{}
	if err := chi.Walk(router, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		served[key{strings.ToLower(method), strings.TrimSuffix(route, "/")}] = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var phantom []string
	for path, raw := range paths {
		item, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		for method := range item {
			switch method {
			case "get", "put", "post", "delete", "patch", "head", "options":
			default:
				continue
			}
			if !served[key{method, path}] {
				phantom = append(phantom, strings.ToUpper(method)+" "+path)
			}
		}
	}
	if len(phantom) > 0 {
		t.Errorf("documented but no route serves them (%d):\n  %s", len(phantom), strings.Join(phantom, "\n  "))
	}
}
