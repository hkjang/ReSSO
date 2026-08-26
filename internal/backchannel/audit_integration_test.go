package backchannel

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hkjang/ReSSO/internal/cryptoutil"
	"github.com/hkjang/ReSSO/internal/store"
)

// A back-channel logout that never landed leaves a session open at a relying
// party that the user believes they closed, and the console said the session
// ended the moment the row was revoked. Until now the only trace was a log
// line, and the question it answers - was this actually ended everywhere - is
// asked long after logs have rotated. Audit events are kept for the retention
// period, which is why the federation sync records its outcome there too.
func TestIntegrationBackchannelLogoutFailureReachesTheAuditTrail(t *testing.T) {
	data, realmID := openBackchannelIntegrationStore(t)
	ctx := context.Background()

	// A relying party that answers 500 to everything: retryable, so this also
	// exercises the path that gives up after the last attempt.
	attempts := 0
	relyingParty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer relyingParty.Close()

	// Shorten the policy so the test does not sit through the real backoff.
	previousTimeout, previousBackoff := attemptTimeout, retryBackoff
	attemptTimeout = 2 * time.Second
	retryBackoff = []time.Duration{10 * time.Millisecond}
	t.Cleanup(func() { attemptTimeout, retryBackoff = previousTimeout, previousBackoff })

	revoked := store.RevokedSession{RealmID: realmID, SessionID: uuid.New(), UserID: uuid.New()}
	notifier := New(context.Background(), data, nil, slog.New(slog.DiscardHandler), nil)
	notifier.post(context.Background(), revoked, "master", "reporting", relyingParty.URL, "signed.logout.token")

	if attempts < 2 {
		t.Fatalf("the relying party was asked %d times, so the giving-up path was not reached", attempts)
	}
	page, err := data.ListAudit(ctx, store.AuditFilter{RealmID: &realmID, EventType: "BACKCHANNEL_LOGOUT", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 {
		t.Fatalf("BACKCHANNEL_LOGOUT events = %d, want 1: a delivery that never landed left no record "+
			"outside a log that rotates", len(page.Items))
	}
	event := page.Items[0]
	if event.Result != "FAILURE" || event.TargetID != "reporting" {
		t.Errorf("event = %s/%s, want FAILURE for the client that was not reached", event.Result, event.TargetID)
	}
	var detail map[string]any
	if err := json.Unmarshal(event.Detail, &detail); err != nil {
		t.Fatalf("the event carries no readable detail: %s", event.Detail)
	}
	if detail["session_id"] != revoked.SessionID.String() {
		t.Errorf("the event does not say which session is still open there: %v", detail)
	}
	if detail["outcome"] != "failed" {
		t.Errorf("the event does not say how the delivery ended: %v", detail)
	}
	if detail["user_id"] != revoked.UserID.String() {
		t.Errorf("the event does not say whose session it was: %v", detail)
	}
	// The actor is this service. Tying the record to a users row would make an
	// event kept to answer a question years later depend on one.
	if event.ActorName != "system" {
		t.Errorf("actor = %q, want system", event.ActorName)
	}
}

func openBackchannelIntegrationStore(t *testing.T) (*store.Store, uuid.UUID) {
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
	schema := "resso_backchannel_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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
	sealer, err := cryptoutil.NewSealer(bytes.Repeat([]byte{'b'}, 32))
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
	bootstrap, err := data.Bootstrap(ctx, "admin", "bootstrap-password-123")
	if err != nil {
		data.Close()
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		data.Close()
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cleanupCancel()
		if _, err := admin.Exec(cleanupCtx, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop back-channel integration schema: %v", err)
		}
		admin.Close()
	})
	return data, bootstrap.RealmID
}
