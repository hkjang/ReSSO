package httpserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hkjang/ReSSO/internal/cryptoutil"
	"github.com/hkjang/ReSSO/internal/domain"
	"github.com/hkjang/ReSSO/internal/observability"
	ressooidc "github.com/hkjang/ReSSO/internal/oidc"
	"github.com/hkjang/ReSSO/internal/store"
)

func TestIntegrationLoginCountsFailuresAndResetsOnSuccess(t *testing.T) {
	data := openHTTPIntegrationStore(t)
	bootstrap, err := data.Bootstrap(context.Background(), "admin", "bootstrap-password-123")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := data.Pool.Exec(context.Background(),
		`UPDATE realms SET max_login_attempts=50 WHERE id=$1`, bootstrap.RealmID); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(New(data, logger, nil, nil).Handler())
	t.Cleanup(server.Close)
	client := server.Client()

	response := postIntegrationLogin(t, client, server.URL, "admin", "wrong-password")
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("invalid login status = %d", response.StatusCode)
	}
	_ = response.Body.Close()
	bucket := "login/account/" + bootstrap.RealmID.String() + "/admin"
	decision, err := data.CheckLoginRateLimit(context.Background(), bucket, 30, 5*time.Minute)
	if err != nil || decision.Attempts != 1 {
		t.Fatalf("failure bucket = %+v, err=%v", decision, err)
	}

	response = postIntegrationLogin(t, client, server.URL, "admin", "bootstrap-password-123")
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("valid login status = %d, body=%s", response.StatusCode, body)
	}
	_ = response.Body.Close()
	decision, err = data.CheckLoginRateLimit(context.Background(), bucket, 30, 5*time.Minute)
	if err != nil || !decision.Allowed || decision.Attempts != 0 {
		t.Fatalf("successful login did not reset bucket: %+v, err=%v", decision, err)
	}

	for range 30 {
		if _, err := data.RecordLoginFailure(context.Background(), bucket, 30, 5*time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	response = postIntegrationLogin(t, client, server.URL, "admin", "bootstrap-password-123")
	defer response.Body.Close()
	if response.StatusCode != http.StatusTooManyRequests {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("limited login status = %d, body=%s", response.StatusCode, body)
	}
	retryAfter, err := strconv.Atoi(response.Header.Get("Retry-After"))
	if err != nil || retryAfter < 1 || retryAfter > 300 {
		t.Fatalf("Retry-After = %q", response.Header.Get("Retry-After"))
	}
}

func TestIntegrationMCPUserTokenRequiresExactActiveSessionBinding(t *testing.T) {
	data := openHTTPIntegrationStore(t)
	ctx := context.Background()
	bootstrap, err := data.Bootstrap(ctx, "admin", "bootstrap-password-123")
	if err != nil {
		t.Fatal(err)
	}
	if err := data.EnsureActiveSigningKey(ctx, bootstrap.RealmID); err != nil {
		t.Fatal(err)
	}
	realm, err := data.RealmByID(ctx, bootstrap.RealmID)
	if err != nil {
		t.Fatal(err)
	}
	user, err := data.UserByID(ctx, bootstrap.AdminUserID)
	if err != nil {
		t.Fatal(err)
	}
	// A client identifier is intentionally set to the platform administrator's
	// UUID. Its client-credentials token must never be interpreted as that user.
	created, err := data.CreateClient(ctx, bootstrap.RealmID, store.CreateClientInput{
		ClientID:      bootstrap.AdminUserID.String(),
		Name:          "MCP impersonation regression",
		Type:          "confidential",
		GrantTypes:    []string{"client_credentials"},
		DefaultScopes: []string{"mcp:read", "admin:read"},
	})
	if err != nil {
		t.Fatal(err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(New(data, logger, nil, nil).Handler())
	t.Cleanup(server.Close)
	client := server.Client()
	clientToken := requestIntegrationClientCredentialsToken(t, client, server.URL,
		created.Client.ClientID, created.ClientSecret)
	response := postIntegrationMCP(t, client, server.URL, clientToken)
	if response.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(response.Body)
		_ = response.Body.Close()
		t.Fatalf("client-credentials MCP status = %d, body=%s", response.StatusCode, body)
	}
	_ = response.Body.Close()

	session, err := data.CreateSession(ctx, realm.ID, user.ID, time.Hour,
		"127.0.0.1", "mcp-integration-test", "password")
	if err != nil {
		t.Fatal(err)
	}
	if err := data.ValidateActiveSessionBinding(ctx, session.Session.ID, user.ID, realm.ID); err != nil {
		t.Fatalf("valid session binding was rejected: %v", err)
	}
	if err := data.ValidateActiveSessionBinding(ctx, session.Session.ID, uuid.New(), realm.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("session accepted a different user binding: %v", err)
	}
	if err := data.ValidateActiveSessionBinding(ctx, session.Session.ID, user.ID, uuid.New()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("session accepted a different Realm binding: %v", err)
	}
	expiredSession, err := data.CreateSession(ctx, realm.ID, user.ID, -time.Minute,
		"127.0.0.1", "mcp-integration-test", "password")
	if err != nil {
		t.Fatal(err)
	}
	if err := data.ValidateActiveSessionBinding(ctx, expiredSession.Session.ID, user.ID, realm.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired session binding remained active: %v", err)
	}
	service := ressooidc.Service{Store: data}
	userTokens, err := service.IssueUserTokens(ctx, realm, created.Client, user,
		session.Session.ID, []string{"mcp:read", "admin:read"}, "", false)
	if err != nil {
		t.Fatal(err)
	}
	response = postIntegrationMCP(t, client, server.URL, userTokens.AccessToken)
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		_ = response.Body.Close()
		t.Fatalf("active user-session MCP status = %d, body=%s", response.StatusCode, body)
	}
	_ = response.Body.Close()

	if err := data.RevokeSession(ctx, session.Session.ID); err != nil {
		t.Fatal(err)
	}
	response = postIntegrationMCP(t, client, server.URL, userTokens.AccessToken)
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("revoked-session MCP status = %d, body=%s", response.StatusCode, body)
	}
}

func requestIntegrationClientCredentialsToken(t *testing.T, client *http.Client, baseURL, clientID, secret string) string {
	t.Helper()
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {secret},
		"scope":         {"mcp:read admin:read"},
	}
	response, err := client.Post(baseURL+"/realms/master/protocol/openid-connect/token",
		"application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("client-credentials token status = %d, body=%s", response.StatusCode, body)
	}
	var token struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(response.Body).Decode(&token); err != nil || token.AccessToken == "" {
		t.Fatalf("decode client-credentials token: token=%q err=%v", token.AccessToken, err)
	}
	return token.AccessToken
}

func postIntegrationMCP(t *testing.T, client *http.Client, baseURL, token string) *http.Response {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, baseURL+"/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func postIntegrationLogin(t *testing.T, client *http.Client, baseURL, username, password string) *http.Response {
	t.Helper()
	body := fmt.Sprintf(`{"realm":"master","username":%q,"password":%q}`, username, password)
	request, err := http.NewRequest(http.MethodPost, baseURL+"/api/v1/auth/login", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func openHTTPIntegrationStore(t *testing.T) *store.Store {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("RESSO_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set RESSO_TEST_POSTGRES_DSN to run PostgreSQL integration tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	adminConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := pgxpool.NewWithConfig(ctx, adminConfig)
	if err != nil {
		t.Fatal(err)
	}
	if err := admin.Ping(ctx); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	schema := "resso_http_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	parsed, err := url.Parse(dsn)
	if err != nil || parsed.Scheme == "" {
		admin.Close()
		t.Fatal("RESSO_TEST_POSTGRES_DSN must be a PostgreSQL URL")
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	sealer, err := cryptoutil.NewSealer(bytes.Repeat([]byte{'i'}, 32))
	if err != nil {
		t.Fatal(err)
	}
	data, err := store.Open(ctx, parsed.String(), sealer)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(ctx, data.Pool); err != nil {
		data.Close()
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		data.Close()
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cleanupCancel()
		if _, err := admin.Exec(cleanupCtx, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop HTTP integration schema: %v", err)
		}
		admin.Close()
	})
	return data
}

func TestIntegrationBackchannelLogoutTokenIsSignedAndScoped(t *testing.T) {
	data := openHTTPIntegrationStore(t)
	bootstrap, err := data.Bootstrap(context.Background(), "admin", "bootstrap-password-123")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := data.EnsureActiveSigningKey(ctx, bootstrap.RealmID); err != nil {
		t.Fatal(err)
	}
	realm, err := data.RealmByID(ctx, bootstrap.RealmID)
	if err != nil {
		t.Fatal(err)
	}
	created, err := data.CreateClient(ctx, realm.ID, store.CreateClientInput{
		ClientID: "logout-rp", Name: "Logout RP", Type: "confidential",
		RedirectURIs:         []string{"https://rp.example.com/callback"},
		BackchannelLogoutURI: "https://rp.example.com/backchannel-logout",
	})
	if err != nil {
		t.Fatal(err)
	}
	sessionID, userID := uuid.New(), bootstrap.AdminUserID

	service := &ressooidc.Service{Store: data}
	raw, err := service.IssueLogoutToken(ctx, realm, created.Client, sessionID, userID)
	if err != nil {
		t.Fatal(err)
	}

	// Verify against the Realm's published JWKS, exactly as a relying party
	// would, then assert the claims required by Back-Channel Logout 1.0.
	keys, err := data.PublishedSigningKeys(ctx, realm.ID)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatal(err)
	}
	if typ, _ := parsed.Headers[0].ExtraHeaders[jose.HeaderType].(string); typ != "logout+jwt" {
		t.Fatalf("logout token typ header = %q, want logout+jwt", typ)
	}
	var jwk jose.JSONWebKey
	if err := json.Unmarshal(keys[0].PublicJWK, &jwk); err != nil {
		t.Fatal(err)
	}
	var standard jwt.Claims
	var extra map[string]any
	if err := parsed.Claims(jwk.Key, &standard, &extra); err != nil {
		t.Fatalf("logout token did not verify against the published JWKS: %v", err)
	}
	if standard.Issuer != realm.IssuerURL {
		t.Fatalf("iss = %q, want %q", standard.Issuer, realm.IssuerURL)
	}
	if len(standard.Audience) != 1 || standard.Audience[0] != "logout-rp" {
		t.Fatalf("aud = %v", standard.Audience)
	}
	if standard.Subject != userID.String() {
		t.Fatalf("sub = %q, want %q", standard.Subject, userID)
	}
	if standard.ID == "" || standard.IssuedAt == nil || standard.Expiry == nil {
		t.Fatalf("logout token is missing jti/iat/exp: %+v", standard)
	}
	if extra["sid"] != sessionID.String() {
		t.Fatalf("sid = %v, want %q", extra["sid"], sessionID)
	}
	events, ok := extra["events"].(map[string]any)
	if !ok {
		t.Fatalf("events claim = %v", extra["events"])
	}
	if _, ok := events["http://schemas.openid.net/event/backchannel-logout"]; !ok {
		t.Fatalf("events claim is missing the back-channel logout event: %v", events)
	}
	// A logout token must never carry a nonce.
	if _, present := extra["nonce"]; present {
		t.Fatal("logout token carries a nonce")
	}
}

func TestIntegrationMetricsRequireAdminAuthorizationAndRecordRequests(t *testing.T) {
	data := openHTTPIntegrationStore(t)
	if _, bootstrapErr := data.Bootstrap(context.Background(), "admin", "bootstrap-password-123"); bootstrapErr != nil {
		t.Fatal(bootstrapErr)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(New(data, logger, nil, nil).Handler())
	t.Cleanup(server.Close)
	client := server.Client()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client.Jar = jar

	// Operational detail must not be readable by anyone who can reach the port.
	response, err := client.Get(server.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous /metrics status = %d, want 401", response.StatusCode)
	}

	login := postIntegrationLogin(t, client, server.URL, "admin", "bootstrap-password-123")
	if login.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(login.Body)
		t.Fatalf("login status = %d, body=%s", login.StatusCode, body)
	}
	_ = login.Body.Close()

	response, err = client.Get(server.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("authenticated /metrics status = %d, body=%s", response.StatusCode, body)
	}
	rendered := string(body)
	for _, want := range []string{
		"# TYPE resso_http_requests_total counter",
		`resso_login_attempts_total{result="success"} 1`,
		"resso_http_request_duration_seconds_bucket",
		"resso_uptime_seconds",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("metrics output missing %q:\n%s", want, rendered)
		}
	}
	// Route patterns, not raw paths, keep the series count bounded.
	if strings.Contains(rendered, `route="/api/v1/auth/login"`) == false {
		t.Fatalf("login route was not recorded:\n%s", rendered)
	}
}

func TestIntegrationClientSecretBruteForceIsLimitedWithoutBlockingNeighbours(t *testing.T) {
	data := openHTTPIntegrationStore(t)
	bootstrap, err := data.Bootstrap(context.Background(), "admin", "bootstrap-password-123")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := data.EnsureActiveSigningKey(ctx, bootstrap.RealmID); err != nil {
		t.Fatal(err)
	}
	newClient := func(identifier string) store.CreatedClient {
		created, err := data.CreateClient(ctx, bootstrap.RealmID, store.CreateClientInput{
			ClientID: identifier, Name: identifier, Type: "confidential",
			RedirectURIs:  []string{"https://rp.example.com/callback"},
			GrantTypes:    []string{"client_credentials"},
			DefaultScopes: []string{"openid"},
		})
		if err != nil {
			t.Fatal(err)
		}
		return created
	}
	target := newClient("target-client")
	neighbour := newClient("neighbour-client")

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(New(data, logger, nil, nil).Handler())
	t.Cleanup(server.Close)
	client := server.Client()

	tokenRequest := func(identifier, secret string) int {
		form := url.Values{"grant_type": {"client_credentials"}, "client_id": {identifier}, "client_secret": {secret}}
		response, err := client.PostForm(server.URL+"/realms/master/protocol/openid-connect/token", form)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		return response.StatusCode
	}

	blockedAfter := 0
	for attempt := 1; attempt <= clientAuthMaxFailures+5; attempt++ {
		status := tokenRequest("target-client", "wrong-secret")
		if status == http.StatusTooManyRequests {
			blockedAfter = attempt
			break
		}
		if status != http.StatusUnauthorized {
			t.Fatalf("attempt %d returned %d, want 401", attempt, status)
		}
	}
	if blockedAfter == 0 {
		t.Fatalf("guessing was never rate limited within %d attempts", clientAuthMaxFailures+5)
	}
	if blockedAfter > clientAuthMaxFailures+1 {
		t.Fatalf("guessing was limited only after %d attempts", blockedAfter)
	}

	// Relying parties routinely share one egress address. A neighbour with a
	// correct secret must not be locked out by the client being guessed.
	if status := tokenRequest("neighbour-client", neighbour.ClientSecret); status != http.StatusOK {
		t.Fatalf("an unrelated client was blocked by another client's failures: status %d", status)
	}
	// The blocked client stays blocked even with the right secret.
	if status := tokenRequest("target-client", target.ClientSecret); status != http.StatusTooManyRequests {
		t.Fatalf("the limited client was not still blocked: status %d", status)
	}
}

func TestIntegrationQuickSearchPointsAtRoutesTheConsoleHas(t *testing.T) {
	data := openHTTPIntegrationStore(t)
	bootstrap, err := data.Bootstrap(context.Background(), "admin", "bootstrap-password-123")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := data.CreateUser(ctx, bootstrap.RealmID, store.CreateUserInput{
		Username: "searchable", DisplayName: "Searchable One", Password: "searchable-password-1", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := data.CreateClient(ctx, bootstrap.RealmID, store.CreateClientInput{
		ClientID: "searchable-client", Name: "Searchable Client", Type: "public",
		RedirectURIs: []string{"https://rp.example.com/cb"}}); err != nil {
		t.Fatal(err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(New(data, logger, nil, nil).Handler())
	t.Cleanup(server.Close)
	client := server.Client()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client.Jar = jar
	login := postIntegrationLogin(t, client, server.URL, "admin", "bootstrap-password-123")
	_ = login.Body.Close()

	response, err := client.Get(server.URL + "/api/admin/v1/quick-search?q=searchable")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	var payload struct {
		Items []struct{ Kind, Label, Path string } `json:"items"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Items) < 2 {
		t.Fatalf("quick search returned %d items", len(payload.Items))
	}
	// Every destination must be a route the console actually registers.
	// The user and client entries used to point at /admin/realms/{id}/users
	// and /admin/realms/{id}/clients, which do not exist: selecting one fell
	// through to the catch-all and landed on the personal profile instead.
	known := map[string]bool{"/admin/users": true, "/admin/clients": true, "/admin/user-federation": true, "/admin/realms": true}
	for _, item := range payload.Items {
		target, query, _ := strings.Cut(item.Path, "?")
		if strings.HasPrefix(target, "/admin/realms/") {
			continue // the Realm detail route takes an identifier
		}
		if !known[target] {
			t.Fatalf("%s %q points at %q, which the console does not route", item.Kind, item.Label, item.Path)
		}
		if !strings.Contains(query, "realm=master") {
			t.Fatalf("%s %q does not carry its Realm: %q", item.Kind, item.Label, item.Path)
		}
		if item.Kind == "user" || item.Kind == "client" {
			if !strings.Contains(query, "q=") {
				t.Fatalf("%s %q does not carry the search term: %q", item.Kind, item.Label, item.Path)
			}
		}
	}
}

// A personal API key carrying only mcp:read belongs to whoever asked for one —
// every user may mint one. The directory tools must still refuse it: the REST
// routes that return the same records sit behind requireAdmin, and reading the
// member list of a realm is what turns one compromised account into a target
// list for the rest.
func TestIntegrationMCPDirectoryToolsRefuseNonAdminKeys(t *testing.T) {
	data := openHTTPIntegrationStore(t)
	ctx := context.Background()
	bootstrap, err := data.Bootstrap(ctx, "admin", "bootstrap-password-123")
	if err != nil {
		t.Fatal(err)
	}
	intern, err := data.CreateUser(ctx, bootstrap.RealmID, store.CreateUserInput{
		Username: "intern", Password: "intern-password-123", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	internKey, err := data.CreatePersonalAPIKey(ctx, intern.ID, "agent", []string{"mcp:read"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	adminKey, err := data.CreatePersonalAPIKey(ctx, bootstrap.AdminUserID, "agent",
		[]string{"mcp:read", "admin:read"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(New(data, logger, nil, nil).Handler())
	t.Cleanup(server.Close)
	client := server.Client()

	listed := callIntegrationMCP(t, client, server.URL, internKey.Secret,
		`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`)
	for _, name := range []string{"resso_search_users", "resso_list_clients"} {
		if strings.Contains(listed, name) {
			t.Errorf("tools/list offered %s to a non-admin key: %s", name, listed)
		}
	}

	for _, call := range []string{
		`{"name":"resso_search_users","arguments":{"query":"ad"}}`,
		`{"name":"resso_list_clients","arguments":{}}`,
	} {
		body := callIntegrationMCP(t, client, server.URL, internKey.Secret,
			`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":`+call+`}`)
		if !strings.Contains(body, `"isError":true`) {
			t.Errorf("non-admin key ran %s: %s", call, body)
		}
		if strings.Contains(body, "admin") && !strings.Contains(body, `"isError":true`) {
			t.Errorf("non-admin key read directory records: %s", body)
		}
	}

	// The same tools must keep working for a key that does carry admin:read,
	// so the fix bounds the audience rather than removing the capability.
	body := callIntegrationMCP(t, client, server.URL, adminKey.Secret,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"resso_search_users","arguments":{"query":"ad"}}}`)
	if strings.Contains(body, `"isError":true`) || !strings.Contains(body, `"username":"admin"`) {
		t.Fatalf("admin key could not search users: %s", body)
	}
}

func callIntegrationMCP(t *testing.T, client *http.Client, baseURL, token, payload string) string {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, baseURL+"/mcp", strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("MCP status = %d, body=%s", response.StatusCode, body)
	}
	return string(body)
}

// The refresh exchange rotates before it issues. A rejection that happens
// after the rotation costs the relying party the only token it holds: it works
// for the length of the grace window and then reads as a replay, revoking the
// family and reporting a theft that never happened. Rejecting before the
// rotation is what keeps the caller whole.
func TestIntegrationRefreshFailureLeavesTheClientsTokenUsable(t *testing.T) {
	data := openHTTPIntegrationStore(t)
	ctx := context.Background()
	bootstrap, err := data.Bootstrap(ctx, "admin", "bootstrap-password-123")
	if err != nil {
		t.Fatal(err)
	}
	realm, err := data.RealmByName(ctx, "master")
	if err != nil {
		t.Fatal(err)
	}
	created, err := data.CreateClient(ctx, realm.ID, store.CreateClientInput{
		ClientID: "refresh-probe", Name: "Refresh Probe", Type: "public",
		RedirectURIs: []string{"https://probe.example.test/cb"},
		GrantTypes:   []string{"authorization_code", "refresh_token"}, DefaultScopes: []string{"openid"}})
	if err != nil {
		t.Fatal(err)
	}
	session, err := data.CreateSession(ctx, realm.ID, bootstrap.AdminUserID, time.Hour,
		"127.0.0.1", "refresh-integration-test", "password")
	if err != nil {
		t.Fatal(err)
	}
	userID := bootstrap.AdminUserID
	sessionID := session.Session.ID
	raw, err := data.CreateRefreshToken(ctx, store.RefreshToken{RealmID: realm.ID, ClientID: created.Client.ID,
		UserID: &userID, SessionID: &sessionID, Scope: []string{"openid"},
		ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(New(data, logger, nil, nil).Handler())
	t.Cleanup(server.Close)

	// A disabled account is the common way this exchange fails, and the
	// rejection must not cost the caller its token.
	if _, err := data.Pool.Exec(ctx, `UPDATE users SET enabled=false WHERE id=$1`, userID); err != nil {
		t.Fatal(err)
	}
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {raw}, "client_id": {"refresh-probe"}}
	response, err := server.Client().PostForm(server.URL+"/realms/master/protocol/openid-connect/token", form)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("refresh for a disabled account status = %d", response.StatusCode)
	}

	var rotatedAt *time.Time
	var children int
	if err := data.Pool.QueryRow(ctx, `SELECT rotated_at,
		(SELECT count(*) FROM refresh_tokens c WHERE c.parent_id=t.id) FROM refresh_tokens t
		WHERE t.session_id=$1 AND t.parent_id IS NULL`, sessionID).Scan(&rotatedAt, &children); err != nil {
		t.Fatal(err)
	}
	if rotatedAt != nil {
		t.Error("the client's token was left marked rotated after a failed exchange")
	}
	if children != 0 {
		t.Errorf("an undelivered successor token was left behind: %d", children)
	}
}

// Revocation answers 200 whether or not the token matched, which is what the
// specification requires but leaves the audit trail unable to say whether a
// token is actually dead. The entry has to distinguish the three outcomes.
func TestIntegrationRevocationAuditRecordsWhatWasRevoked(t *testing.T) {
	data := openHTTPIntegrationStore(t)
	ctx := context.Background()
	bootstrap, err := data.Bootstrap(ctx, "admin", "bootstrap-password-123")
	if err != nil {
		t.Fatal(err)
	}
	realm, err := data.RealmByName(ctx, "master")
	if err != nil {
		t.Fatal(err)
	}
	created, err := data.CreateClient(ctx, realm.ID, store.CreateClientInput{
		ClientID: "revoke-probe", Name: "Revoke Probe", Type: "confidential",
		RedirectURIs: []string{"https://probe.example.test/cb"},
		GrantTypes:   []string{"authorization_code", "refresh_token"}, DefaultScopes: []string{"openid"}})
	if err != nil {
		t.Fatal(err)
	}
	session, err := data.CreateSession(ctx, realm.ID, bootstrap.AdminUserID, time.Hour,
		"127.0.0.1", "revoke-integration-test", "password")
	if err != nil {
		t.Fatal(err)
	}
	userID := bootstrap.AdminUserID
	sessionID := session.Session.ID
	raw, err := data.CreateRefreshToken(ctx, store.RefreshToken{RealmID: realm.ID, ClientID: created.Client.ID,
		UserID: &userID, SessionID: &sessionID, Scope: []string{"openid"},
		ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(New(data, logger, nil, nil).Handler())
	t.Cleanup(server.Close)
	revoke := func(token string) {
		t.Helper()
		form := url.Values{"token": {token}, "client_id": {"revoke-probe"},
			"client_secret": {created.ClientSecret}}
		response, postErr := server.Client().PostForm(server.URL+"/realms/master/protocol/openid-connect/revoke", form)
		if postErr != nil {
			t.Fatal(postErr)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("revoke status = %d", response.StatusCode)
		}
	}

	revoke("not-a-token-anyone-issued")
	revoke(raw)

	page, err := data.ListAudit(ctx, store.AuditFilter{EventType: "TOKEN_REVOKED", Ascending: true, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 2 {
		t.Fatalf("audit entries = %d, want 2", len(page.Items))
	}
	detailOf := func(index int) map[string]any {
		t.Helper()
		var decoded map[string]any
		if err := json.Unmarshal(page.Items[index].Detail, &decoded); err != nil {
			t.Fatalf("decode audit detail: %v", err)
		}
		return decoded
	}
	if got := detailOf(0)["revoked"]; got != "none" {
		t.Errorf("an unmatched token recorded revoked=%v, want none", got)
	}
	matched := detailOf(1)
	if got := matched["revoked"]; got != "refresh_token" {
		t.Errorf("a revoked refresh token recorded revoked=%v", got)
	}
	if matched["family_id"] == nil {
		t.Error("the revoked family was not recorded")
	}
}

// max_age is how a relying party demands a fresh proof of identity before
// something sensitive. It was accepted and ignored, so the request came back
// with a code minted from whatever session already existed — indistinguishable,
// from the relying party's side, from a reauthentication that never happened.
func TestIntegrationMaxAgeForcesReauthentication(t *testing.T) {
	data := openHTTPIntegrationStore(t)
	ctx := context.Background()
	bootstrap, err := data.Bootstrap(ctx, "admin", "bootstrap-password-123")
	if err != nil {
		t.Fatal(err)
	}
	realm, err := data.RealmByName(ctx, "master")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := data.CreateClient(ctx, realm.ID, store.CreateClientInput{
		ClientID: "step-up", Name: "Step Up", Type: "public",
		RedirectURIs: []string{"https://step-up.example.test/cb"},
		GrantTypes:   []string{"authorization_code"}, DefaultScopes: []string{"openid"}}); err != nil {
		t.Fatal(err)
	}
	session, err := data.CreateSession(ctx, realm.ID, bootstrap.AdminUserID, time.Hour,
		"127.0.0.1", "max-age-test", "password")
	if err != nil {
		t.Fatal(err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(New(data, logger, nil, nil).Handler())
	t.Cleanup(server.Close)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	// Public clients must use PKCE, so every probe carries a valid challenge.
	verifier := strings.Repeat("step-up-verifier", 4)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	authorize := func(extra string) *url.URL {
		t.Helper()
		target := server.URL + "/realms/master/protocol/openid-connect/auth?response_type=code&client_id=step-up" +
			"&redirect_uri=" + url.QueryEscape("https://step-up.example.test/cb") + "&scope=openid&state=s" +
			"&code_challenge=" + challenge + "&code_challenge_method=S256" + extra
		request, reqErr := http.NewRequest(http.MethodGet, target, nil)
		if reqErr != nil {
			t.Fatal(reqErr)
		}
		request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session.Token})
		response, doErr := client.Do(request)
		if doErr != nil {
			t.Fatal(doErr)
		}
		_ = response.Body.Close()
		location, parseErr := url.Parse(response.Header.Get("Location"))
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		return location
	}

	// A generous max_age is satisfied by the session that already exists.
	if got := authorize("&max_age=3600"); got.Query().Get("code") == "" {
		t.Fatalf("a fresh session did not satisfy max_age=3600: %s", got)
	}

	// Age the authentication past what the relying party will accept.
	if _, err := data.Pool.Exec(ctx,
		`UPDATE sso_sessions SET created_at=now()-interval '20 minutes' WHERE id=$1`, session.Session.ID); err != nil {
		t.Fatal(err)
	}
	stale := authorize("&max_age=300")
	if stale.Query().Get("code") != "" {
		t.Errorf("max_age=300 was satisfied by a 20-minute-old authentication: %s", stale)
	}
	if stale.Path != "/login" || stale.Query().Get("request") == "" {
		t.Errorf("a stale authentication did not send the user to sign in again: %s", stale)
	}

	// With prompt=none there is nobody to ask, so the relying party has to be
	// told rather than handed a code it asked not to receive.
	silent := authorize("&max_age=300&prompt=none")
	if silent.Query().Get("error") != "login_required" {
		t.Errorf("prompt=none with a stale authentication returned %q", silent.Query().Get("error"))
	}

	// A value that is not a number is refused, not quietly dropped.
	malformed := authorize("&max_age=soon")
	if malformed.Query().Get("error") != "invalid_request" {
		t.Errorf("malformed max_age returned %q", malformed.Query().Get("error"))
	}
}

// A relying party sends request objects to protect the parameters inside them,
// and id_token_hint to name the account it believes it is renewing. Accepting
// either and acting on neither is a silent downgrade: the first honours the
// unsigned query string instead, the second can hand back a code for whoever
// happens to be signed in now.
func TestIntegrationAuthorizationRefusesUnsupportedAndMismatchedHints(t *testing.T) {
	data := openHTTPIntegrationStore(t)
	ctx := context.Background()
	bootstrap, err := data.Bootstrap(ctx, "admin", "bootstrap-password-123")
	if err != nil {
		t.Fatal(err)
	}
	realm, err := data.RealmByName(ctx, "master")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := data.CreateClient(ctx, realm.ID, store.CreateClientInput{
		ClientID: "hint-probe", Name: "Hint Probe", Type: "public",
		RedirectURIs: []string{"https://hint.example.test/cb"},
		GrantTypes:   []string{"authorization_code"}, DefaultScopes: []string{"openid"}}); err != nil {
		t.Fatal(err)
	}
	session, err := data.CreateSession(ctx, realm.ID, bootstrap.AdminUserID, time.Hour,
		"127.0.0.1", "hint-test", "password")
	if err != nil {
		t.Fatal(err)
	}
	// ID tokens are signed, and the key is created lazily on first use.
	if err := data.EnsureActiveSigningKey(ctx, realm.ID); err != nil {
		t.Fatal(err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := httptest.NewServer(New(data, logger, nil, nil).Handler())
	t.Cleanup(server.Close)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	verifier := strings.Repeat("hint-probe-verifier", 3)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	authorize := func(extra string) *url.URL {
		t.Helper()
		target := server.URL + "/realms/master/protocol/openid-connect/auth?response_type=code&client_id=hint-probe" +
			"&redirect_uri=" + url.QueryEscape("https://hint.example.test/cb") + "&scope=openid&state=s" +
			"&code_challenge=" + challenge + "&code_challenge_method=S256" + extra
		request, reqErr := http.NewRequest(http.MethodGet, target, nil)
		if reqErr != nil {
			t.Fatal(reqErr)
		}
		request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session.Token})
		response, doErr := client.Do(request)
		if doErr != nil {
			t.Fatal(doErr)
		}
		_ = response.Body.Close()
		location, parseErr := url.Parse(response.Header.Get("Location"))
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		return location
	}

	for parameter, expected := range map[string]string{
		"&request=eyJhbGciOiJub25lIn0.e30.":               "request_not_supported",
		"&request_uri=https%3A%2F%2Fattacker.example%2Fr": "request_uri_not_supported",
	} {
		if got := authorize(parameter).Query().Get("error"); got != expected {
			t.Errorf("%s returned %q, want %q", parameter, got, expected)
		}
	}

	// A hint naming somebody else must not be answered with a code for the
	// person who is actually signed in.
	hint := issueIntegrationIDToken(t, data, realm, "hint-probe", "someone-else")
	mismatch := authorize("&prompt=none&id_token_hint=" + url.QueryEscape(hint))
	if got := mismatch.Query().Get("error"); got != "login_required" {
		t.Errorf("a mismatched id_token_hint returned %q, want login_required", got)
	}
	if mismatch.Query().Get("code") != "" {
		t.Error("a mismatched id_token_hint was answered with a code")
	}

	// The hint for the account that is signed in is satisfied silently.
	admin, err := data.UserByID(ctx, bootstrap.AdminUserID)
	if err != nil {
		t.Fatal(err)
	}
	matching := issueIntegrationIDTokenFor(t, data, realm, "hint-probe", admin, session.Session.ID)
	if got := authorize("&prompt=none&id_token_hint=" + url.QueryEscape(matching)); got.Query().Get("code") == "" {
		t.Errorf("a matching id_token_hint was refused: %s", got)
	}

	// Something that is not a token this issuer signed is refused outright.
	if got := authorize("&id_token_hint=not-a-jwt").Query().Get("error"); got != "invalid_request" {
		t.Errorf("a malformed id_token_hint returned %q", got)
	}
}

// issueIntegrationIDToken mints a real ID token for a freshly created account,
// which is how a hint naming a different person is produced without forging
// anything the server would refuse for the wrong reason.
func issueIntegrationIDToken(t *testing.T, data *store.Store, realm domain.Realm, clientID, username string) string {
	t.Helper()
	ctx := context.Background()
	user, err := data.CreateUser(ctx, realm.ID, store.CreateUserInput{
		Username: username, Password: username + "-password-1234", Enabled: true})
	if err != nil {
		t.Fatalf("create hint user: %v", err)
	}
	session, err := data.CreateSession(ctx, realm.ID, user.ID, time.Hour, "127.0.0.1", "hint-test", "password")
	if err != nil {
		t.Fatalf("create hint session: %v", err)
	}
	return issueIntegrationIDTokenFor(t, data, realm, clientID, user, session.Session.ID)
}

func issueIntegrationIDTokenFor(t *testing.T, data *store.Store, realm domain.Realm,
	clientID string, user domain.User, sessionID uuid.UUID) string {
	t.Helper()
	ctx := context.Background()
	client, err := data.ClientByIdentifier(ctx, realm.ID, clientID)
	if err != nil {
		t.Fatalf("load hint client %q: %v", clientID, err)
	}
	service := ressooidc.Service{Store: data}
	tokens, err := service.IssueUserTokens(ctx, realm, client, user, sessionID, []string{"openid"}, "", false)
	if err != nil {
		t.Fatalf("issue hint tokens: %v", err)
	}
	if tokens.IDToken == "" {
		t.Fatal("no ID token was issued")
	}
	return tokens.IDToken
}

// Shutdown has to write out what is buffered. The last seconds before a
// restart are exactly the ones an operator goes looking for afterwards, and
// the mirror batches on a timer, so without a flush they are simply gone.
func TestIntegrationLogMirrorFlushesOnShutdown(t *testing.T) {
	data := openHTTPIntegrationStore(t)
	ctx := context.Background()
	metrics := observability.NewRegistry()
	handler := observability.NewDBHandler(slog.NewTextHandler(io.Discard, nil), data, "shutdown-test", metrics)
	logger := slog.New(handler)
	for index := range 5 {
		logger.Info("buffered before shutdown", "index", index)
	}

	// Close returns only once the writer has drained, so no sleep is needed.
	handler.Close(5 * time.Second)

	var written int
	if err := data.Pool.QueryRow(ctx,
		`SELECT count(*) FROM system_logs WHERE component='shutdown-test'`).Scan(&written); err != nil {
		t.Fatal(err)
	}
	if written != 5 {
		t.Errorf("records written on shutdown = %d, want 5", written)
	}
	var exported strings.Builder
	metrics.WritePrometheus(&exported)
	if !strings.Contains(exported.String(), `result="written"`) {
		t.Errorf("the written outcome was not reported: %s", exported.String())
	}
}
