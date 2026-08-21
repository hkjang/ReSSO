package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hkjang/ReSSO/internal/cryptoutil"
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
	server := httptest.NewServer(New(data, logger, nil).Handler())
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
	server := httptest.NewServer(New(data, logger, nil).Handler())
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
