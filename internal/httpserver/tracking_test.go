package httpserver

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hkjang/ReSSO/internal/store"
	"github.com/hkjang/ReSSO/internal/tracking"
)

// Off is the default, and off has to mean the policy this service shipped
// with — not a policy that merely lacks the snippet's origins. A person
// turning tracking off is entitled to the narrow policy back.
func TestTheBasePolicyIsWhatEveryPathGetsWhileTrackingIsOff(t *testing.T) {
	if got := policyFor(tracking.Default(), "/", "n"); got != basePolicy {
		t.Errorf("policy while off = %s", got)
	}
	on := tracking.Config{Enabled: true, Provider: tracking.ProviderMomento, MomentoURL: "https://momento.corp.example",
		MomentoSiteID: "S", MomentoProxy: true}.Normalized()
	if got := policyFor(on, "/admin/users", "n"); got != basePolicy {
		t.Errorf("the console got a widened policy without include_admin: %s", got)
	}
	page := policyFor(on, "/login", "n0nce")
	for _, want := range []string{"script-src 'self' 'nonce-n0nce'", "report-uri " + cspReportPath, "frame-ancestors 'none'"} {
		if !strings.Contains(page, want) {
			t.Errorf("the page policy lacks %s: %s", want, page)
		}
	}
	if scriptDirective(page) != "script-src 'self' 'nonce-n0nce'" {
		t.Errorf("the page policy loosened scripts: %s", page)
	}
	if strings.Contains(page, "momento.corp.example") {
		t.Errorf("the proxied setup named the collector: %s", page)
	}
	direct := on
	direct.MomentoProxy = false
	if got := policyFor(direct, "/login", "n"); !strings.Contains(got, "connect-src 'self' https://momento.corp.example") {
		t.Errorf("the direct setup does not allow the collector: %s", got)
	}
}

func TestTheSnippetLandsWhereThePlacementSays(t *testing.T) {
	page := []byte("<!doctype html><html><head><title>x</title></head><body><div id=\"root\"></div></body></html>")
	head := string(injectSnippet(page, "<script>1</script>", tracking.PlacementHead))
	if !strings.Contains(head, "<script>1</script>\n</head>") {
		t.Errorf("head placement = %s", head)
	}
	body := string(injectSnippet(page, "<script>1</script>", tracking.PlacementBody))
	if !strings.Contains(body, "<script>1</script>\n</body>") {
		t.Errorf("body placement = %s", body)
	}
	if got := string(injectSnippet(page, "", tracking.PlacementHead)); got != string(page) {
		t.Error("an empty snippet changed the document")
	}
	bare := string(injectSnippet([]byte("<p>no tags</p>"), "<script>1</script>", tracking.PlacementHead))
	if !strings.HasSuffix(bare, "<script>1</script>\n") {
		t.Errorf("a document without the tag = %s", bare)
	}
}

// A fresh install has nothing configured, so the document goes out as it
// always did: the base policy, and no script this service did not build.
func TestAFreshInstallServesTheDocumentUntouched(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(New(nil, logger, nil, nil).Handler())
	t.Cleanup(server.Close)
	for _, path := range []string{"/", "/login", "/admin/users"} {
		response, err := server.Client().Get(server.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK || !strings.Contains(string(body), "<html") {
			t.Fatalf("%s answered %d %.60s", path, response.StatusCode, body)
		}
		if got := response.Header.Get("Content-Security-Policy"); got != basePolicy {
			t.Errorf("%s carries policy %s", path, got)
		}
		if strings.Contains(string(body), "nonce=") || strings.Contains(string(body), "report-uri") {
			t.Errorf("%s carries a snippet: %s", path, body)
		}
	}
	// And the proxy path does not exist while nothing is configured.
	response, err := server.Client().Get(server.URL + tracking.MomentoProxyPath + "/tracker.js")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Errorf("the proxy answered %d while tracking is off", response.StatusCode)
	}
}

func TestPolicyReportsAreRecordedAndAlwaysAnswered204(t *testing.T) {
	server := New(nil, slog.New(slog.NewTextHandler(io.Discard, nil)), nil, nil)
	body := `{"csp-report":{"blocked-uri":"https://momento.corp.example/collect/v1/events","effective-directive":"connect-src","document-uri":"https://sso.example/login"}}`
	recorder := httptest.NewRecorder()
	server.receiveCSPReport(recorder, httptest.NewRequest(http.MethodPost, cspReportPath, strings.NewReader(body)))
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d", recorder.Code)
	}
	items := server.tracking.violations.List(tracking.Config{})
	if len(items) != 1 || items[0].Origin != "https://momento.corp.example" || items[0].Directive != "connect-src" || items[0].Page != "https://sso.example/login" {
		t.Fatalf("items = %+v", items)
	}
	broken := httptest.NewRecorder()
	server.receiveCSPReport(broken, httptest.NewRequest(http.MethodPost, cspReportPath, strings.NewReader("not json")))
	if broken.Code != http.StatusNoContent || len(server.tracking.violations.List(tracking.Config{})) != 1 {
		t.Fatalf("status=%d items=%#v", broken.Code, server.tracking.violations.List(tracking.Config{}))
	}
	// The endpoint is reachable without a session, because the browser
	// sends the report without one.
	handler := server.Handler()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, cspReportPath, strings.NewReader(body)))
	if response.Code != http.StatusNoContent {
		t.Errorf("an unauthenticated report answered %d", response.Code)
	}
}

// The whole path, end to end: a service administrator turns Momento on
// through the proxy, and from then on the login page carries the snippet
// with a nonce the policy names, the console does not, the collector answers
// through this origin without ever seeing the session cookie, a blocked
// origin the browser reports shows up on the screen and one click allows it,
// and turning tracking off puts everything back.
func TestIntegrationTrackingSnippetRunsUnderTheStrictPolicy(t *testing.T) {
	data := openHTTPIntegrationStore(t)
	ctx := context.Background()
	if _, err := data.Bootstrap(ctx, "admin", "bootstrap-password-123"); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := New(data, logger, nil, nil)
	server := httptest.NewServer(handler.Handler())
	t.Cleanup(server.Close)
	cookies, csrf := signInForBoundaryProbe(t, server, "admin", "bootstrap-password-123")

	// A stand-in collector that records what reached it.
	var received []*http.Request
	var receivedBodies []string
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		received = append(received, r)
		receivedBodies = append(receivedBodies, string(body))
		http.SetCookie(w, &http.Cookie{Name: "collector", Value: "x"})
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte("window.__momento=1"))
	}))
	t.Cleanup(collector.Close)

	call := func(method, path, body string) (*http.Response, []byte) {
		t.Helper()
		request, err := http.NewRequest(method, server.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-CSRF-Token", csrf)
		for _, cookie := range cookies {
			request.AddCookie(cookie)
		}
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(response.Body)
		_ = response.Body.Close()
		return response, raw
	}
	getDocument := func(path string) (*http.Response, string) {
		t.Helper()
		response, err := server.Client().Get(server.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(response.Body)
		_ = response.Body.Close()
		return response, string(raw)
	}

	// Before: the default is off and the document says so.
	response, raw := call(http.MethodGet, "/api/admin/v1/tracking", "")
	if response.StatusCode != http.StatusOK || !strings.Contains(string(raw), `"enabled":false`) || !strings.Contains(string(raw), `"provider":"none"`) {
		t.Fatalf("initial configuration: %d %s", response.StatusCode, raw)
	}

	// An oversized snippet is refused as the caller's input.
	response, raw = call(http.MethodPut, "/api/admin/v1/tracking",
		`{"enabled":true,"provider":"custom","custom_snippet":"<script>`+strings.Repeat("x", tracking.MaxSnippetBytes)+`</script>","placement":"head"}`)
	if response.StatusCode != http.StatusBadRequest || !strings.Contains(string(raw), "invalid_input") {
		t.Fatalf("an oversized snippet answered %d %s", response.StatusCode, raw)
	}

	// Turn Momento on through the proxy.
	response, raw = call(http.MethodPut, "/api/admin/v1/tracking",
		`{"enabled":true,"provider":"momento","momento_url":"`+collector.URL+`","momento_site_id":"SITE_1","momento_proxy":true,"placement":"head"}`)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("turning tracking on answered %d %s", response.StatusCode, raw)
	}
	var view struct {
		Config tracking.Config `json:"config"`
		Policy string          `json:"policy"`
	}
	if err := json.Unmarshal(raw, &view); err != nil || !view.Config.Enabled || view.Config.Provider != tracking.ProviderMomento {
		t.Fatalf("view = %s (%v)", raw, err)
	}
	if !strings.HasPrefix(scriptDirective(view.Policy), "script-src 'self' 'nonce-") {
		t.Errorf("the view's policy = %s", view.Policy)
	}

	// The login page carries the snippet with a nonce, and the header names
	// that nonce and nothing external.
	response, document := getDocument("/login")
	policy := response.Header.Get("Content-Security-Policy")
	nonceStart := strings.Index(document, `nonce="`)
	if nonceStart < 0 {
		t.Fatalf("the login page carries no nonce: %s", document)
	}
	nonce := document[nonceStart+len(`nonce="`):]
	nonce = nonce[:strings.IndexByte(nonce, '"')]
	if nonce == "" || !strings.Contains(policy, "'nonce-"+nonce+"'") {
		t.Errorf("the header does not name the page's nonce %q: %s", nonce, policy)
	}
	for _, want := range []string{`src="/momento/tracker.js"`, `data-endpoint="/momento"`, `data-site-id="SITE_1"`} {
		if !strings.Contains(document, want) {
			t.Errorf("the login page lacks %s", want)
		}
	}
	if !strings.Contains(document, "</script>\n</head>") {
		t.Errorf("the snippet is not in the head: %.400s", document)
	}
	if scriptDirective(policy) != "script-src 'self' 'nonce-"+nonce+"'" {
		t.Errorf("the policy = %s", policy)
	}
	if strings.Contains(policy, collector.URL) || !strings.Contains(policy, "report-uri "+cspReportPath) {
		t.Errorf("the policy names the collector or lacks the report-uri: %s", policy)
	}
	// Each page view gets its own nonce.
	_, again := getDocument("/login")
	if strings.Contains(again, `nonce="`+nonce+`"`) {
		t.Error("two page views shared a nonce")
	}

	// The console does not carry it unless asked.
	response, document = getDocument("/admin/users")
	if strings.Contains(document, "tracker.js") || response.Header.Get("Content-Security-Policy") != basePolicy {
		t.Errorf("the console carries the snippet without include_admin: %s / %s", response.Header.Get("Content-Security-Policy"), document)
	}
	// And non-page paths keep the base policy.
	for _, path := range []string{"/api/v1/meta", "/health/live", "/realms/master/.well-known/openid-configuration"} {
		response, _ := getDocument(path)
		if got := response.Header.Get("Content-Security-Policy"); got != basePolicy {
			t.Errorf("%s carries %s", path, got)
		}
	}

	// The proxy reaches the collector, without the session cookie, and
	// nothing the collector answers reaches the browser as a cookie.
	request, _ := http.NewRequest(http.MethodGet, server.URL+"/momento/tracker.js", nil)
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	request.Header.Set("Authorization", "Bearer should-not-be-forwarded")
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || string(raw) != "window.__momento=1" {
		t.Fatalf("the proxy answered %d %s", response.StatusCode, raw)
	}
	if len(received) != 1 || received[0].URL.Path != "/tracker.js" {
		t.Fatalf("the collector received %+v", received)
	}
	if received[0].Header.Get("Cookie") != "" || received[0].Header.Get("Authorization") != "" {
		t.Errorf("credentials were forwarded to the collector: cookie=%q authorization=%q",
			received[0].Header.Get("Cookie"), received[0].Header.Get("Authorization"))
	}
	if received[0].Header.Get("X-Forwarded-Host") == "" {
		t.Error("the collector was not told which host the page was on")
	}
	if len(response.Cookies()) != 0 {
		t.Errorf("the collector set a cookie on this origin: %v", response.Cookies())
	}
	if got := response.Header.Values("Content-Security-Policy"); len(got) != 1 || got[0] != basePolicy {
		t.Errorf("the proxied answer carries the collector's policy: %v", got)
	}
	response, raw = call(http.MethodPost, "/momento/collect/v1/events", `{"events":[]}`)
	if response.StatusCode != http.StatusOK || len(received) != 2 || received[1].Method != http.MethodPost || receivedBodies[1] != `{"events":[]}` {
		t.Errorf("an event batch answered %d %s; collector saw %d requests", response.StatusCode, raw, len(received))
	}

	// A browser reports a blocked origin; the screen lists it; one click
	// allows it; the list then says so.
	report := `{"csp-report":{"blocked-uri":"https://pixel.corp.example/p.gif","effective-directive":"img-src","document-uri":"` + server.URL + `/login"}}`
	response, _ = getDocumentPost(t, server, cspReportPath, report)
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("the report answered %d", response.StatusCode)
	}
	response, raw = call(http.MethodGet, "/api/admin/v1/tracking/violations", "")
	if response.StatusCode != http.StatusOK || !strings.Contains(string(raw), `"origin":"https://pixel.corp.example"`) || !strings.Contains(string(raw), `"allowed":false`) {
		t.Fatalf("violations = %d %s", response.StatusCode, raw)
	}
	response, raw = call(http.MethodPost, "/api/admin/v1/tracking/allowed-hosts", `{"origin":"https://pixel.corp.example"}`)
	if response.StatusCode != http.StatusOK || !strings.Contains(string(raw), `"allowed_hosts":"https://pixel.corp.example"`) {
		t.Fatalf("allowing the host answered %d %s", response.StatusCode, raw)
	}
	_, raw = call(http.MethodGet, "/api/admin/v1/tracking/violations", "")
	if !strings.Contains(string(raw), `"allowed":true`) {
		t.Errorf("the allowed origin is still reported as blocked: %s", raw)
	}
	response, _ = getDocument("/login")
	if !strings.Contains(response.Header.Get("Content-Security-Policy"), "img-src 'self' data: https://pixel.corp.example") {
		t.Errorf("the allowed origin is not in the policy: %s", response.Header.Get("Content-Security-Policy"))
	}
	response, _ = call(http.MethodDelete, "/api/admin/v1/tracking/violations", "")
	if response.StatusCode != http.StatusNoContent {
		t.Errorf("clearing answered %d", response.StatusCode)
	}
	_, raw = call(http.MethodGet, "/api/admin/v1/tracking/violations", "")
	if !strings.Contains(string(raw), `"items":[]`) {
		t.Errorf("violations after clearing = %s", raw)
	}

	// The change is in the trail, as the installation's setting rather than
	// any Realm's.
	response, raw = call(http.MethodGet, "/api/admin/v1/audit?event_type=TRACKING_UPDATE", "")
	if response.StatusCode != http.StatusOK || strings.Count(string(raw), `"event_type":"TRACKING_UPDATE"`) != 2 {
		t.Errorf("the trail = %d %s", response.StatusCode, raw)
	}

	// Somebody who is not a service administrator cannot read or change it.
	bootstrapRealm, err := data.RealmByName(ctx, "master")
	if err != nil {
		t.Fatal(err)
	}
	tenantAdmin, err := data.CreateUser(ctx, bootstrapRealm.ID, store.CreateUserInput{
		Username: "tenant-admin", Password: "tenant-password-1234", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := data.Pool.Exec(ctx, `INSERT INTO user_roles(user_id,role_id)
        SELECT $1,id FROM roles WHERE realm_id=$2 AND name='realm-admin'`,
		tenantAdmin.ID, bootstrapRealm.ID); err != nil {
		t.Fatal(err)
	}
	realmAdminCookies, realmAdminCSRF := signInForBoundaryProbe(t, server, "tenant-admin", "tenant-password-1234")
	request, _ = http.NewRequest(http.MethodGet, server.URL+"/api/admin/v1/tracking", nil)
	request.Header.Set("X-CSRF-Token", realmAdminCSRF)
	for _, cookie := range realmAdminCookies {
		request.AddCookie(cookie)
	}
	response, err = server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Errorf("a realm administrator read the tracking configuration: %d", response.StatusCode)
	}

	// Off again: the document and the policy are exactly what they were, and
	// the proxy path is gone.
	response, raw = call(http.MethodPut, "/api/admin/v1/tracking",
		`{"enabled":false,"provider":"momento","momento_url":"`+collector.URL+`","momento_site_id":"SITE_1","momento_proxy":true,"placement":"head","allowed_hosts":"https://pixel.corp.example"}`)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("turning tracking off answered %d %s", response.StatusCode, raw)
	}
	response, document = getDocument("/login")
	if response.Header.Get("Content-Security-Policy") != basePolicy || strings.Contains(document, "tracker.js") || strings.Contains(document, "nonce=") {
		t.Errorf("after turning off: %s / %s", response.Header.Get("Content-Security-Policy"), document)
	}
	response, _ = getDocument("/momento/tracker.js")
	if response.StatusCode != http.StatusNotFound {
		t.Errorf("the proxy still answers %d after turning off", response.StatusCode)
	}
}

func getDocumentPost(t *testing.T, server *httptest.Server, path, body string) (*http.Response, []byte) {
	t.Helper()
	response, err := server.Client().Post(server.URL+path, "application/csp-report", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	return response, raw
}

// scriptDirective returns the script-src directive of a policy, so a test can
// say what it allows without matching the style-src that is 'unsafe-inline'
// by design.
func scriptDirective(policy string) string {
	for _, directive := range strings.Split(policy, ";") {
		if directive = strings.TrimSpace(directive); strings.HasPrefix(directive, "script-src ") {
			return directive
		}
	}
	return ""
}
