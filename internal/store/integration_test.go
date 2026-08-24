package store

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hkjang/ReSSO/internal/cryptoutil"
	"github.com/hkjang/ReSSO/internal/domain"
	"github.com/hkjang/ReSSO/internal/password"
)

const integrationDSNEnvironment = "RESSO_TEST_POSTGRES_DSN"

func TestIntegrationKeyringRotationPreservesCredentialsAndRewrapsSecrets(t *testing.T) {
	legacyMaterial := bytes.Repeat([]byte{'d'}, 32)
	oldSealer, err := cryptoutil.NewSealer(legacyMaterial)
	if err != nil {
		t.Fatal(err)
	}
	data := openIntegrationStore(t, oldSealer)
	bootstrap := bootstrapIntegrationStore(t, data)
	if err := data.EnsureActiveSigningKey(context.Background(), bootstrap.RealmID); err != nil {
		t.Fatal(err)
	}
	session, err := data.CreateSession(context.Background(), bootstrap.RealmID, bootstrap.AdminUserID,
		time.Hour, "127.0.0.1", "integration-test", "password")
	if err != nil {
		t.Fatal(err)
	}
	apiKey, err := data.CreatePersonalAPIKey(context.Background(), bootstrap.AdminUserID,
		"rotation test", []string{"api:read"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	data.Sealer = newIntegrationKeyring(t,
		[]cryptoutil.NamedKey{{ID: "data-new", Material: bytes.Repeat([]byte{'n'}, 32)}, {ID: "legacy", Material: legacyMaterial}},
		[]cryptoutil.NamedKey{{ID: "digest-new", Material: bytes.Repeat([]byte{'m'}, 32)}, {ID: "legacy", Material: legacyMaterial}})
	authenticated, err := data.SessionByToken(context.Background(), session.Token)
	if err != nil {
		t.Fatalf("old session after digest rotation: %v", err)
	}
	if !data.ValidateCSRF(authenticated, session.CSRFToken) {
		t.Fatal("old CSRF digest was not accepted")
	}
	if _, err := data.AuthenticateAPIKey(context.Background(), apiKey.Secret); err != nil {
		t.Fatalf("old API key after digest rotation: %v", err)
	}
	diagnosis, err := data.DiagnoseRecovery(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if diagnosis.EncryptedValuesVerified != 1 || diagnosis.EncryptedValuesNeedingRewrap != 1 {
		t.Fatalf("unexpected pre-rewrap diagnosis: %+v", diagnosis)
	}

	result, err := data.RewrapEncryptedSecrets(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.PrimaryKeyID != "data-new" || result.SigningKeys != 1 {
		t.Fatalf("unexpected rewrap result: %+v", result)
	}
	if _, _, err := data.ActivePrivateKey(context.Background(), bootstrap.RealmID); err != nil {
		t.Fatalf("rewrapped signing key cannot be opened: %v", err)
	}
	var cipher []byte
	if err := data.Pool.QueryRow(context.Background(),
		`SELECT private_key_cipher FROM signing_keys WHERE realm_id=$1 AND status='ACTIVE'`, bootstrap.RealmID).Scan(&cipher); err != nil {
		t.Fatal(err)
	}
	if needs, err := data.Sealer.NeedsRewrap(cipher); err != nil || needs {
		t.Fatalf("rewrapped envelope still needs rotation: needs=%v err=%v", needs, err)
	}
}

func TestIntegrationAuthorizationCodeCanBeRedeemedOnlyOnce(t *testing.T) {
	data := openIntegrationStore(t, integrationSealer(t))
	bootstrap := bootstrapIntegrationStore(t, data)
	clientID := createIntegrationClient(t, data, bootstrap.RealmID)
	session, err := data.CreateSession(context.Background(), bootstrap.RealmID, bootstrap.AdminUserID,
		time.Hour, "127.0.0.1", "integration-test", "password")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := data.CreateAuthorizationCode(context.Background(), AuthorizationCode{
		RealmID: bootstrap.RealmID, ClientID: clientID, UserID: bootstrap.AdminUserID,
		SessionID: session.Session.ID, RedirectURI: "https://client.example.test/callback", Scope: []string{"openid"},
	})
	if err != nil {
		t.Fatal(err)
	}

	const contenders = 12
	errorsFound := make(chan error, contenders)
	var wait sync.WaitGroup
	for range contenders {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, redeemErr := data.RedeemAuthorizationCode(context.Background(), raw, func(AuthorizationCode) error { return nil })
			errorsFound <- redeemErr
		}()
	}
	wait.Wait()
	close(errorsFound)
	successes := 0
	for redeemErr := range errorsFound {
		switch {
		case redeemErr == nil:
			successes++
		// Losers of the race see the code already consumed, which is the
		// same signal a replay attempt produces.
		case errors.Is(redeemErr, ErrNotFound), errors.Is(redeemErr, ErrCodeReuse):
		default:
			t.Fatalf("unexpected redemption error: %v", redeemErr)
		}
	}
	if successes != 1 {
		t.Fatalf("successful redemptions = %d, want 1", successes)
	}
}

func TestIntegrationRefreshTokenReuseRevokesFamily(t *testing.T) {
	data := openIntegrationStore(t, integrationSealer(t))
	bootstrap := bootstrapIntegrationStore(t, data)
	clientID := createIntegrationClient(t, data, bootstrap.RealmID)
	session, err := data.CreateSession(context.Background(), bootstrap.RealmID, bootstrap.AdminUserID,
		time.Hour, "127.0.0.1", "integration-test", "password")
	if err != nil {
		t.Fatal(err)
	}
	userID, sessionID := bootstrap.AdminUserID, session.Session.ID
	raw, err := data.CreateRefreshToken(context.Background(), RefreshToken{
		RealmID: bootstrap.RealmID, ClientID: clientID, UserID: &userID, SessionID: &sessionID,
		Scope: []string{"openid", "profile"}, ExpiresAt: time.Now().UTC().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, rotatedRaw, err := data.RotateRefreshToken(context.Background(), raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Presenting the rotated token again inside refreshRotationGrace is a
	// retry, not theft: it yields a fresh token and keeps the family alive.
	_, graceRaw, err := data.RotateRefreshToken(context.Background(), raw, nil)
	if err != nil {
		t.Fatalf("rotation inside the grace window was rejected: %v", err)
	}
	if graceRaw == rotatedRaw {
		t.Fatal("grace rotation returned the same token value")
	}
	if _, active, err := data.InspectRefreshToken(context.Background(), rotatedRaw); err != nil || !active {
		t.Fatalf("grace rotation revoked the earlier sibling: active=%v err=%v", active, err)
	}

	// Aging the recorded rotation past the grace window turns the same replay
	// into reuse, which revokes every token in the family.
	if _, err := data.Pool.Exec(context.Background(), `UPDATE refresh_tokens
		SET rotated_at=now()-make_interval(secs => $1) WHERE token_hash=ANY($2::bytea[])`,
		int(refreshRotationGrace.Seconds())+60, data.Sealer.Digests(raw)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := data.RotateRefreshToken(context.Background(), raw, nil); !errors.Is(err, ErrTokenReuse) {
		t.Fatalf("reuse error = %v, want ErrTokenReuse", err)
	}
	for name, token := range map[string]string{"first child": rotatedRaw, "grace child": graceRaw} {
		if _, active, err := data.InspectRefreshToken(context.Background(), token); err != nil || active {
			t.Fatalf("%s remained active after reuse: active=%v err=%v", name, active, err)
		}
	}
}

func TestIntegrationLoginFailureLimitAndReset(t *testing.T) {
	data := openIntegrationStore(t, integrationSealer(t))
	ctx := context.Background()
	const bucket = "login/account/test/user"
	decision, err := data.CheckLoginRateLimit(ctx, bucket, 3, time.Minute)
	if err != nil || !decision.Allowed || decision.Attempts != 0 {
		t.Fatalf("initial decision = %+v, err=%v", decision, err)
	}
	for attempt := 1; attempt <= 3; attempt++ {
		decision, err = data.RecordLoginFailure(ctx, bucket, 3, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if decision.Attempts != attempt || decision.Allowed != (attempt < 3) {
			t.Fatalf("attempt %d decision = %+v", attempt, decision)
		}
	}
	decision, err = data.CheckLoginRateLimit(ctx, bucket, 3, time.Minute)
	if err != nil || decision.Allowed || decision.RetryAfterSeconds < 1 || decision.RetryAfterSeconds > 60 {
		t.Fatalf("limited decision = %+v, err=%v", decision, err)
	}
	if err := data.ResetLoginRateLimit(ctx, bucket); err != nil {
		t.Fatal(err)
	}
	decision, err = data.CheckLoginRateLimit(ctx, bucket, 3, time.Minute)
	if err != nil || !decision.Allowed || decision.Attempts != 0 {
		t.Fatalf("reset decision = %+v, err=%v", decision, err)
	}
	for attempt := 1; attempt <= 3; attempt++ {
		decision, err = data.ConsumeLoginRateLimit(ctx, "login/ip/127.0.0.1", 2, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if decision.Allowed != (attempt <= 2) {
			t.Fatalf("IP attempt %d decision = %+v", attempt, decision)
		}
	}
}

func TestIntegrationLoginRateLimitSurvivesDigestKeyRotation(t *testing.T) {
	oldMaterial := bytes.Repeat([]byte{'o'}, 32)
	newMaterial := bytes.Repeat([]byte{'n'}, 32)
	encryptionKeys := []cryptoutil.NamedKey{{ID: "data", Material: bytes.Repeat([]byte{'e'}, 32)}}
	oldActive := newIntegrationKeyring(t, encryptionKeys, []cryptoutil.NamedKey{
		{ID: "old", Material: oldMaterial},
		{ID: "new", Material: newMaterial},
	})
	newActive := newIntegrationKeyring(t, encryptionKeys, []cryptoutil.NamedKey{
		{ID: "new", Material: newMaterial},
		{ID: "old", Material: oldMaterial},
	})
	data := openIntegrationStore(t, oldActive)
	ctx := context.Background()
	const bucket = "login/account/rotation/user"

	for attempt := 1; attempt <= 2; attempt++ {
		decision, err := data.RecordLoginFailure(ctx, bucket, 3, time.Minute)
		if err != nil || decision.Attempts != attempt {
			t.Fatalf("old-active attempt %d: decision=%+v err=%v", attempt, decision, err)
		}
	}
	data.Sealer = newActive
	decision, err := data.CheckLoginRateLimit(ctx, bucket, 3, time.Minute)
	if err != nil || !decision.Allowed || decision.Attempts != 2 {
		t.Fatalf("new-active check lost old counter: decision=%+v err=%v", decision, err)
	}
	decision, err = data.RecordLoginFailure(ctx, bucket, 3, time.Minute)
	if err != nil || decision.Allowed || decision.Attempts != 3 {
		t.Fatalf("new-active increment did not preserve counter: decision=%+v err=%v", decision, err)
	}

	data.Sealer = oldActive
	decision, err = data.RecordLoginFailure(ctx, bucket, 3, time.Minute)
	if err != nil || decision.Allowed || decision.Attempts != 4 {
		t.Fatalf("active-key flip split counter: decision=%+v err=%v", decision, err)
	}
	var rows int
	if err := data.Pool.QueryRow(ctx, `SELECT count(*) FROM login_rate_limits WHERE bucket_hash=ANY($1::bytea[])`,
		data.Sealer.Digests(bucket)).Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("digest representations were not consolidated: rows=%d err=%v", rows, err)
	}
	if err := data.ResetLoginRateLimit(ctx, bucket); err != nil {
		t.Fatal(err)
	}
	data.Sealer = newActive
	decision, err = data.CheckLoginRateLimit(ctx, bucket, 3, time.Minute)
	if err != nil || !decision.Allowed || decision.Attempts != 0 {
		t.Fatalf("rotation-aware reset failed: decision=%+v err=%v", decision, err)
	}

	oldInstance := &Store{Pool: data.Pool, Sealer: oldActive}
	newInstance := &Store{Pool: data.Pool, Sealer: newActive}
	const concurrentAttempts = 24
	errorsFound := make(chan error, concurrentAttempts)
	var wait sync.WaitGroup
	for attempt := range concurrentAttempts {
		wait.Add(1)
		go func(instance *Store) {
			defer wait.Done()
			_, recordErr := instance.RecordLoginFailure(ctx, bucket, 100, time.Minute)
			errorsFound <- recordErr
		}([]*Store{oldInstance, newInstance}[attempt%2])
	}
	wait.Wait()
	close(errorsFound)
	for recordErr := range errorsFound {
		if recordErr != nil {
			t.Fatal(recordErr)
		}
	}
	data.Sealer = newActive
	decision, err = data.CheckLoginRateLimit(ctx, bucket, 100, time.Minute)
	if err != nil || decision.Attempts != concurrentAttempts {
		t.Fatalf("concurrent rotating instances lost attempts: decision=%+v err=%v", decision, err)
	}
	if err := data.ResetLoginRateLimit(ctx, bucket); err != nil {
		t.Fatal(err)
	}
	if _, err := data.Pool.Exec(ctx, `INSERT INTO login_rate_limits(bucket_hash,window_started_at,attempts,updated_at)
		VALUES($1,now()-interval '50 seconds',1,now()),($2,now(),1,now())`,
		oldActive.Digest(bucket), newActive.Digest(bucket)); err != nil {
		t.Fatal(err)
	}
	decision, err = data.CheckLoginRateLimit(ctx, bucket, 3, time.Minute)
	if err != nil || decision.Attempts != 2 || decision.RetryAfterSeconds < 45 {
		t.Fatalf("split bucket expired newer attempts early: decision=%+v err=%v", decision, err)
	}
}

func TestIntegrationDiagnoseReportsIncompleteSchema(t *testing.T) {
	data := openIntegrationStore(t, integrationSealer(t))
	ctx := context.Background()
	if _, err := data.Pool.Exec(ctx, `DELETE FROM schema_migrations WHERE version='003_hardening.sql'`); err != nil {
		t.Fatal(err)
	}
	diagnosis, err := data.DiagnoseRecovery(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if diagnosis.DatabaseReady {
		t.Fatalf("incomplete schema reported ready: %+v", diagnosis)
	}
	// Count the embedded migrations rather than a literal, so adding one does
	// not require editing this assertion.
	entries, err := fs.ReadDir(migrationFiles, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	embedded := 0
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".sql") {
			embedded++
		}
	}
	if len(diagnosis.AppliedMigrations) != embedded-1 {
		t.Fatalf("applied migrations = %v, want %d entries", diagnosis.AppliedMigrations, embedded-1)
	}
	if slices.Contains(diagnosis.AppliedMigrations, "003_hardening.sql") {
		t.Fatalf("removed migration still reported as applied: %v", diagnosis.AppliedMigrations)
	}
}

func TestIntegrationOptionalEmailLifecycleAndAdminRecovery(t *testing.T) {
	data := openIntegrationStore(t, newIntegrationKeyring(t,
		[]cryptoutil.NamedKey{{ID: "data-test", Material: bytes.Repeat([]byte{'e'}, 32)}},
		[]cryptoutil.NamedKey{
			{ID: "digest-current", Material: bytes.Repeat([]byte{'g'}, 32)},
			{ID: "digest-previous", Material: bytes.Repeat([]byte{'h'}, 32)},
		}))
	bootstrap := bootstrapIntegrationStore(t, data)
	ctx := context.Background()
	first, err := data.CreateUser(ctx, bootstrap.RealmID, CreateUserInput{
		Username: "no-email-one", Password: "user-password-123", DisplayName: "No Email One", Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := data.CreateUser(ctx, bootstrap.RealmID, CreateUserInput{
		Username: "no-email-two", Password: "user-password-456", DisplayName: "No Email Two", Enabled: true,
	}); err != nil {
		t.Fatalf("second empty email in one Realm: %v", err)
	}
	verified := true
	updated, err := data.UpdateUser(ctx, first.ID, UpdateUserInput{
		Email: "first@example.test", EmailVerified: &verified, DisplayName: first.DisplayName, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.EmailVerified {
		t.Fatal("newly changed email was marked verified in the same update")
	}
	updated, err = data.UpdateUser(ctx, first.ID, UpdateUserInput{
		Email: updated.Email, EmailVerified: &verified, DisplayName: updated.DisplayName, Enabled: true,
	})
	if err != nil || !updated.EmailVerified {
		t.Fatalf("administrator could not verify unchanged email: user=%+v err=%v", updated, err)
	}
	if _, err := data.Pool.Exec(ctx, `UPDATE users SET email='First@Example.Test' WHERE id=$1`, first.ID); err != nil {
		t.Fatal(err)
	}
	updated, err = data.UpdateUser(ctx, first.ID, UpdateUserInput{
		Email: "first@example.test", DisplayName: updated.DisplayName, Enabled: true,
	})
	if err != nil || !updated.EmailVerified || updated.Email != "first@example.test" {
		t.Fatalf("case-only normalization cleared verification: user=%+v err=%v", updated, err)
	}
	if _, err := data.CreateUser(ctx, bootstrap.RealmID, CreateUserInput{
		Username: "invalid-email", Email: "not-an-email", Password: "user-password-789", Enabled: true,
	}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("invalid email error = %v, want ErrInvalidInput", err)
	}
	updated, err = data.UpdateProfile(ctx, first.ID, UpdateProfileInput{Email: "other@example.test", DisplayName: updated.DisplayName})
	if err != nil || updated.EmailVerified {
		t.Fatalf("profile email change did not clear verification: user=%+v err=%v", updated, err)
	}

	session, err := data.CreateSession(ctx, bootstrap.RealmID, bootstrap.AdminUserID,
		time.Hour, "127.0.0.1", "integration-test", "password")
	if err != nil {
		t.Fatal(err)
	}
	apiKey, err := data.CreatePersonalAPIKey(ctx, bootstrap.AdminUserID, "recovery test", []string{"api:read"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	recoveryBucket := "login/account/" + bootstrap.RealmID.String() + "/admin"
	for range 30 {
		if _, err := data.RecordLoginFailure(ctx, recoveryBucket, 30, 5*time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	digestCandidates := data.Sealer.Digests(recoveryBucket)
	if len(digestCandidates) != 2 {
		t.Fatalf("digest candidates = %d, want 2", len(digestCandidates))
	}
	if _, err := data.Pool.Exec(ctx, `INSERT INTO login_rate_limits(bucket_hash,window_started_at,attempts,updated_at)
		VALUES($1,now(),30,now())`, digestCandidates[1]); err != nil {
		t.Fatal(err)
	}
	recovery, err := data.RecoverPlatformAdmin(ctx, "admin", "replacement-password-123")
	if err != nil {
		t.Fatal(err)
	}
	if recovery.Created || recovery.SessionsRevoked != 1 || recovery.APIKeysRevoked != 1 || recovery.LoginFailureBucketsReset != 2 {
		t.Fatalf("unexpected recovery result: %+v", recovery)
	}
	if decision, err := data.CheckLoginRateLimit(ctx, recoveryBucket, 30, 5*time.Minute); err != nil || !decision.Allowed {
		t.Fatalf("recovered administrator remains rate limited: decision=%+v err=%v", decision, err)
	}
	if _, err := data.SessionByToken(ctx, session.Token); !errors.Is(err, ErrNotFound) {
		t.Fatalf("recovery session remains active: %v", err)
	}
	if _, err := data.AuthenticateAPIKey(ctx, apiKey.Secret); !errors.Is(err, ErrNotFound) {
		t.Fatalf("recovery API key remains active: %v", err)
	}
	realm, err := data.RealmByID(ctx, bootstrap.RealmID)
	if err != nil {
		t.Fatal(err)
	}
	authentication, err := data.AuthenticatePassword(ctx, realm, "admin", "replacement-password-123")
	if err != nil || !authentication.Success || !authentication.User.PlatformAdmin {
		t.Fatalf("recovered administrator cannot authenticate: result=%+v err=%v", authentication, err)
	}
}

func openIntegrationStore(t *testing.T, sealer *cryptoutil.Sealer) *Store {
	t.Helper()
	return openIntegrationStoreOptions(t, sealer, true)
}

// openIntegrationStoreWithoutMigrating leaves the schema empty so a test can
// apply an older set of migrations itself.
func openIntegrationStoreWithoutMigrating(t *testing.T, sealer *cryptoutil.Sealer) *Store {
	t.Helper()
	return openIntegrationStoreOptions(t, sealer, false)
}

func openIntegrationStoreOptions(t *testing.T, sealer *cryptoutil.Sealer, migrate bool) *Store {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv(integrationDSNEnvironment))
	if dsn == "" {
		t.Skipf("set %s to run PostgreSQL integration tests", integrationDSNEnvironment)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	adminConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	adminConfig.MaxConns = 2
	admin, err := pgxpool.NewWithConfig(ctx, adminConfig)
	if err != nil {
		t.Fatal(err)
	}
	if err := admin.Ping(ctx); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	schema := "resso_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	poolConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	if poolConfig.ConnConfig.RuntimeParams == nil {
		poolConfig.ConnConfig.RuntimeParams = make(map[string]string)
	}
	poolConfig.ConnConfig.RuntimeParams["search_path"] = schema
	poolConfig.MaxConns = 16
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		t.Fatal(err)
	}
	dummyHash, err := password.Hash("ReSSO-invalid-credential-placeholder")
	if err != nil {
		t.Fatal(err)
	}
	data := &Store{Pool: pool, Sealer: sealer, dummyPasswordHash: dummyHash}
	if migrate {
		if err := Migrate(ctx, pool); err != nil {
			pool.Close()
			admin.Close()
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		pool.Close()
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cleanupCancel()
		if _, err := admin.Exec(cleanupCtx, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop integration schema: %v", err)
		}
		admin.Close()
	})
	return data
}

func integrationSealer(t *testing.T) *cryptoutil.Sealer {
	t.Helper()
	return newIntegrationKeyring(t,
		[]cryptoutil.NamedKey{{ID: "data-test", Material: bytes.Repeat([]byte{'e'}, 32)}},
		[]cryptoutil.NamedKey{{ID: "digest-test", Material: bytes.Repeat([]byte{'g'}, 32)}})
}

func newIntegrationKeyring(t *testing.T, encryptionKeys, digestKeys []cryptoutil.NamedKey) *cryptoutil.Sealer {
	t.Helper()
	sealer, err := cryptoutil.NewKeyring(encryptionKeys, digestKeys)
	if err != nil {
		t.Fatal(err)
	}
	return sealer
}

func bootstrapIntegrationStore(t *testing.T, data *Store) BootstrapResult {
	t.Helper()
	result, err := data.Bootstrap(context.Background(), "admin", "bootstrap-password-123")
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func createIntegrationClient(t *testing.T, data *Store, realmID uuid.UUID) uuid.UUID {
	t.Helper()
	created, err := data.CreateClient(context.Background(), realmID, CreateClientInput{
		ClientID: "integration-client", Name: "Integration Client", Type: "public",
		RedirectURIs: []string{"https://client.example.test/callback"}, RequirePKCE: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return created.Client.ID
}

func TestIntegrationClientSecretUsesKeyedDigestAndUpgradesLegacyHashes(t *testing.T) {
	data := openIntegrationStore(t, integrationSealer(t))
	bootstrap := bootstrapIntegrationStore(t, data)
	ctx := context.Background()

	created, err := data.CreateClient(ctx, bootstrap.RealmID, CreateClientInput{
		ClientID: "secret-client", Name: "Secret Client", Type: "confidential",
		RedirectURIs: []string{"https://app.example.com/callback"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var stored string
	if err := data.Pool.QueryRow(ctx, "SELECT secret_hash FROM clients WHERE id=$1", created.Client.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(stored, clientSecretDigestPrefix) {
		t.Fatalf("new client secret was not stored as a keyed digest: %q", stored)
	}
	if ok, err := data.VerifyClientSecret(ctx, created.Client.ID, created.ClientSecret); err != nil || !ok {
		t.Fatalf("keyed digest verification failed: ok=%v err=%v", ok, err)
	}
	if ok, err := data.VerifyClientSecret(ctx, created.Client.ID, created.ClientSecret+"x"); err != nil || ok {
		t.Fatalf("a wrong secret was accepted: ok=%v err=%v", ok, err)
	}

	// A v0.2 Argon2 hash must keep working and be upgraded in place.
	legacySecret := "legacy-client-secret-value"
	legacyHash, err := password.Hash(legacySecret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := data.Pool.Exec(ctx, "UPDATE clients SET secret_hash=$2 WHERE id=$1", created.Client.ID, legacyHash); err != nil {
		t.Fatal(err)
	}
	if ok, err := data.VerifyClientSecret(ctx, created.Client.ID, legacySecret); err != nil || !ok {
		t.Fatalf("legacy Argon2 client secret was rejected: ok=%v err=%v", ok, err)
	}
	if err := data.Pool.QueryRow(ctx, "SELECT secret_hash FROM clients WHERE id=$1", created.Client.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(stored, clientSecretDigestPrefix) {
		t.Fatalf("legacy hash was not upgraded after a successful verification: %q", stored)
	}
	if ok, err := data.VerifyClientSecret(ctx, created.Client.ID, legacySecret); err != nil || !ok {
		t.Fatalf("upgraded digest rejected the same secret: ok=%v err=%v", ok, err)
	}

	rotated, err := data.RotateClientSecret(ctx, created.Client.ID)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := data.VerifyClientSecret(ctx, created.Client.ID, legacySecret); ok {
		t.Fatal("rotation did not invalidate the previous secret")
	}
	if ok, err := data.VerifyClientSecret(ctx, created.Client.ID, rotated); err != nil || !ok {
		t.Fatalf("rotated secret was rejected: ok=%v err=%v", ok, err)
	}
}

func TestIntegrationConcurrentFailedLoginsCountAtomicallyAndLock(t *testing.T) {
	data := openIntegrationStore(t, integrationSealer(t))
	bootstrap := bootstrapIntegrationStore(t, data)
	ctx := context.Background()
	realm, err := data.RealmByID(ctx, bootstrap.RealmID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := data.Pool.Exec(ctx, `UPDATE realms SET max_login_attempts=5,lockout_seconds=900 WHERE id=$1`, realm.ID); err != nil {
		t.Fatal(err)
	}
	realm, err = data.RealmByID(ctx, realm.ID)
	if err != nil {
		t.Fatal(err)
	}
	user, err := data.CreateUser(ctx, realm.ID, CreateUserInput{
		Username: "lock-race", Password: "correct-horse-battery", Enabled: true, DisplayName: "Lock Race",
	})
	if err != nil {
		t.Fatal(err)
	}

	const attempts = 4
	var wait sync.WaitGroup
	results := make([]AuthenticationResult, attempts)
	errs := make([]error, attempts)
	for index := range attempts {
		wait.Add(1)
		go func() {
			defer wait.Done()
			results[index], errs[index] = data.Authenticate(ctx, realm, "lock-race", "wrong-password")
		}()
	}
	wait.Wait()
	for index, err := range errs {
		if err != nil {
			t.Fatalf("attempt %d returned an error: %v", index, err)
		}
		if results[index].Success {
			t.Fatalf("attempt %d succeeded with a wrong password", index)
		}
	}
	var failed int
	if err := data.Pool.QueryRow(ctx, "SELECT failed_attempts FROM users WHERE id=$1", user.ID).Scan(&failed); err != nil {
		t.Fatal(err)
	}
	if failed != attempts {
		t.Fatalf("concurrent failures lost increments: got %d, want %d", failed, attempts)
	}

	// The fifth failure reaches max_login_attempts and must lock the account,
	// after which even the correct password is refused.
	result, err := data.Authenticate(ctx, realm, "lock-race", "wrong-password")
	if err != nil {
		t.Fatal(err)
	}
	if result.FailureReason != "ACCOUNT_LOCKED" {
		t.Fatalf("expected ACCOUNT_LOCKED, got %q", result.FailureReason)
	}
	result, err = data.Authenticate(ctx, realm, "lock-race", "correct-horse-battery")
	if err != nil {
		t.Fatal(err)
	}
	if result.Success || result.FailureReason != "ACCOUNT_LOCKED" {
		t.Fatalf("a locked account accepted the correct password: %+v", result)
	}

	if _, err := data.Pool.Exec(ctx, `UPDATE users SET locked_until=NULL WHERE id=$1`, user.ID); err != nil {
		t.Fatal(err)
	}
	result, err = data.Authenticate(ctx, realm, "lock-race", "correct-horse-battery")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Success {
		t.Fatalf("unlocked account rejected the correct password: %+v", result)
	}
	if err := data.Pool.QueryRow(ctx, "SELECT failed_attempts FROM users WHERE id=$1", user.ID).Scan(&failed); err != nil {
		t.Fatal(err)
	}
	if failed != 0 {
		t.Fatalf("successful login did not reset the failure counter: %d", failed)
	}
}

func TestIntegrationBackchannelLogoutTargetsAndRevocationHook(t *testing.T) {
	data := openIntegrationStore(t, integrationSealer(t))
	bootstrap := bootstrapIntegrationStore(t, data)
	ctx := context.Background()

	notified, err := data.CreateClient(ctx, bootstrap.RealmID, CreateClientInput{
		ClientID: "rp-with-logout", Name: "RP With Logout", Type: "confidential",
		RedirectURIs:         []string{"https://rp.example.com/callback"},
		BackchannelLogoutURI: "https://rp.example.com/backchannel-logout",
	})
	if err != nil {
		t.Fatal(err)
	}
	silent, err := data.CreateClient(ctx, bootstrap.RealmID, CreateClientInput{
		ClientID: "rp-without-logout", Name: "RP Without Logout", Type: "confidential",
		RedirectURIs: []string{"https://other.example.com/callback"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := data.CreateClient(ctx, bootstrap.RealmID, CreateClientInput{
		ClientID: "rp-bad-logout", Name: "RP Bad Logout", Type: "confidential",
		RedirectURIs:         []string{"https://bad.example.com/callback"},
		BackchannelLogoutURI: "http://bad.example.com/backchannel-logout",
	}); err == nil {
		t.Fatal("a plaintext back-channel logout URI was accepted")
	}

	session, err := data.CreateSession(ctx, bootstrap.RealmID, bootstrap.AdminUserID,
		time.Hour, "127.0.0.1", "integration-test", "password")
	if err != nil {
		t.Fatal(err)
	}
	userID, sessionID := bootstrap.AdminUserID, session.Session.ID
	for _, clientID := range []uuid.UUID{notified.Client.ID, silent.Client.ID} {
		if _, err := data.CreateRefreshToken(ctx, RefreshToken{RealmID: bootstrap.RealmID, ClientID: clientID,
			UserID: &userID, SessionID: &sessionID, Scope: []string{"openid"},
			ExpiresAt: time.Now().UTC().Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}

	targets, err := data.BackchannelLogoutTargets(ctx, bootstrap.RealmID, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || targets[0].ClientID != "rp-with-logout" {
		t.Fatalf("unexpected back-channel logout targets: %+v", targets)
	}

	// A session the client never took part in must not be notified.
	otherSession, err := data.CreateSession(ctx, bootstrap.RealmID, bootstrap.AdminUserID,
		time.Hour, "127.0.0.1", "integration-test", "password")
	if err != nil {
		t.Fatal(err)
	}
	targets, err = data.BackchannelLogoutTargets(ctx, bootstrap.RealmID, otherSession.Session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 0 {
		t.Fatalf("an uninvolved session produced targets: %+v", targets)
	}

	var mutex sync.Mutex
	var revoked []RevokedSession
	data.OnSessionRevoked = func(session RevokedSession) {
		mutex.Lock()
		defer mutex.Unlock()
		revoked = append(revoked, session)
	}
	if err := data.RevokeSession(ctx, sessionID); err != nil {
		t.Fatal(err)
	}
	mutex.Lock()
	got := append([]RevokedSession(nil), revoked...)
	mutex.Unlock()
	if len(got) != 1 || got[0].SessionID != sessionID || got[0].UserID != userID || got[0].RealmID != bootstrap.RealmID {
		t.Fatalf("revocation hook received %+v", got)
	}

	revoked = nil
	if err := data.RevokeAllUserSessions(ctx, userID, nil); err != nil {
		t.Fatal(err)
	}
	mutex.Lock()
	got = append([]RevokedSession(nil), revoked...)
	mutex.Unlock()
	// Only the still-active session is reported; the one revoked above is not
	// announced twice.
	if len(got) != 1 || got[0].SessionID != otherSession.Session.ID {
		t.Fatalf("bulk revocation hook received %+v", got)
	}
}

func TestIntegrationEnsureSearchIndexesIsIdempotentAndOptional(t *testing.T) {
	data := openIntegrationStore(t, integrationSealer(t))
	ctx := context.Background()
	var extensionSchema *string
	if err := data.Pool.QueryRow(ctx, `SELECT n.nspname FROM pg_extension e
		JOIN pg_namespace n ON n.oid=e.extnamespace WHERE e.extname='pg_trgm'`).Scan(&extensionSchema); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal(err)
	}

	indexed, err := data.EnsureSearchIndexes(ctx)
	if err != nil {
		t.Fatalf("EnsureSearchIndexes failed: %v", err)
	}
	if indexed != (extensionSchema != nil) {
		t.Fatalf("indexed=%v but pg_trgm schema=%v", indexed, extensionSchema)
	}
	// Running twice must be a no-op rather than an error.
	if again, err := data.EnsureSearchIndexes(ctx); err != nil || again != indexed {
		t.Fatalf("second run: indexed=%v err=%v", again, err)
	}
	if !indexed {
		t.Skip("pg_trgm is not installed in this database")
	}
	var created int
	if err := data.Pool.QueryRow(ctx, `SELECT count(*) FROM pg_indexes
		WHERE indexname IN ('idx_users_username_trgm','idx_users_email_trgm','idx_users_display_name_trgm')
		AND schemaname=current_schema()`).Scan(&created); err != nil {
		t.Fatal(err)
	}
	if created != 3 {
		t.Fatalf("created %d trigram indexes, want 3", created)
	}
	// The search itself must still return the right rows with the index in place.
	realm, err := data.CreateRealm(ctx, CreateRealmInput{Name: "search-realm", DisplayName: "Search",
		IssuerURL: "https://sso.example.com/realms/search-realm"})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"alice.smith", "bob.jones", "carol.smithers"} {
		if _, err := data.CreateUser(ctx, realm.ID, CreateUserInput{
			Username: name, Password: "search-password-1234", Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	users, err := data.ListUsers(ctx, realm.ID, "smith", UserSort{}, 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 2 {
		t.Fatalf("search for %q returned %d users", "smith", len(users))
	}
	total, err := data.CountUsers(ctx, realm.ID, "smith")
	if err != nil || total != 2 {
		t.Fatalf("CountUsers = %d, err=%v", total, err)
	}
}

func TestIntegrationUnlockUserClearsLockoutWithoutChangingThePassword(t *testing.T) {
	data := openIntegrationStore(t, integrationSealer(t))
	bootstrap := bootstrapIntegrationStore(t, data)
	ctx := context.Background()
	realm, err := data.RealmByID(ctx, bootstrap.RealmID)
	if err != nil {
		t.Fatal(err)
	}
	// The policy must now be readable rather than living only in the database.
	if realm.PasswordMinLength < 8 || realm.MaxLoginAttempts < 3 || realm.LockoutSeconds < 30 {
		t.Fatalf("realm policy was not loaded: %+v", realm)
	}

	user, err := data.CreateUser(ctx, realm.ID, CreateUserInput{
		Username: "lockout-user", Password: "correct-horse-battery", Enabled: true, DisplayName: "Lockout User",
	})
	if err != nil {
		t.Fatal(err)
	}
	for range realm.MaxLoginAttempts {
		if _, err := data.Authenticate(ctx, realm, "lockout-user", "wrong-password"); err != nil {
			t.Fatal(err)
		}
	}
	result, err := data.Authenticate(ctx, realm, "lockout-user", "correct-horse-battery")
	if err != nil {
		t.Fatal(err)
	}
	if result.FailureReason != "ACCOUNT_LOCKED" {
		t.Fatalf("account was not locked: %+v", result)
	}

	wasLocked, err := data.UnlockUser(ctx, realm.ID, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !wasLocked {
		t.Fatal("UnlockUser did not report the account as locked")
	}
	// The original password must still work: unlocking is not a credential reset.
	result, err = data.Authenticate(ctx, realm, "lockout-user", "correct-horse-battery")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Success {
		t.Fatalf("unlocked account rejected its unchanged password: %+v", result)
	}
	// Unlocking an account that was never locked is a no-op, not an error.
	if wasLocked, err := data.UnlockUser(ctx, realm.ID, user.ID); err != nil || wasLocked {
		t.Fatalf("second unlock: wasLocked=%v err=%v", wasLocked, err)
	}
	// A user from another Realm must not be reachable.
	other, err := data.CreateRealm(ctx, CreateRealmInput{Name: "other-realm", DisplayName: "Other",
		IssuerURL: "https://sso.example.com/realms/other-realm"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := data.UnlockUser(ctx, other.ID, user.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-realm unlock error = %v, want ErrNotFound", err)
	}
}

func TestIntegrationUpdateRealmPersistsAndValidatesThePolicy(t *testing.T) {
	data := openIntegrationStore(t, integrationSealer(t))
	bootstrap := bootstrapIntegrationStore(t, data)
	ctx := context.Background()
	realm, err := data.RealmByID(ctx, bootstrap.RealmID)
	if err != nil {
		t.Fatal(err)
	}
	base := UpdateRealmInput{
		DisplayName: realm.DisplayName, IssuerURL: realm.IssuerURL, Enabled: true,
		AccessTokenTTLSeconds: realm.AccessTokenTTLSeconds, RefreshTokenTTLSeconds: realm.RefreshTokenTTLSeconds,
		SessionTTLSeconds: realm.SessionTTLSeconds, PasswordMinLength: 16,
		MaxLoginAttempts: 10, LockoutSeconds: 600,
	}
	updated, err := data.UpdateRealm(ctx, realm.ID, base)
	if err != nil {
		t.Fatal(err)
	}
	if updated.PasswordMinLength != 16 || updated.MaxLoginAttempts != 10 || updated.LockoutSeconds != 600 {
		t.Fatalf("policy was not persisted: %+v", updated)
	}
	// The new minimum must actually be enforced on user creation.
	if _, err := data.CreateUser(ctx, realm.ID, CreateUserInput{
		Username: "short-password", Password: "0123456789", Enabled: true}); err == nil {
		t.Fatal("a password shorter than the Realm minimum was accepted")
	}

	// Out-of-range values are reported as readable input errors, not as
	// database constraint violations.
	for _, invalid := range []UpdateRealmInput{
		func() UpdateRealmInput { out := base; out.PasswordMinLength = 4; return out }(),
		func() UpdateRealmInput { out := base; out.MaxLoginAttempts = 1; return out }(),
		func() UpdateRealmInput { out := base; out.LockoutSeconds = 10; return out }(),
	} {
		if _, err := data.UpdateRealm(ctx, realm.ID, invalid); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("policy validation error = %v, want ErrInvalidInput", err)
		}
	}
}

func TestIntegrationApprovalListResolvesRequesterAndTargetRole(t *testing.T) {
	data := openIntegrationStore(t, integrationSealer(t))
	bootstrap := bootstrapIntegrationStore(t, data)
	ctx := context.Background()
	if _, err := data.Pool.Exec(ctx, `UPDATE realms SET approval_enabled=true WHERE id=$1`, bootstrap.RealmID); err != nil {
		t.Fatal(err)
	}
	manager, err := data.CreateUser(ctx, bootstrap.RealmID, CreateUserInput{
		Username: "team-lead", DisplayName: "Team Lead", Password: "manager-password-1234", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	requester, err := data.CreateUser(ctx, bootstrap.RealmID, CreateUserInput{
		Username: "requester", DisplayName: "Req Uester", Password: "requester-password-1234",
		Enabled: true, ManagerID: &manager.ID})
	if err != nil {
		t.Fatal(err)
	}
	role, err := data.CreateRole(ctx, bootstrap.RealmID, "warehouse-operator", "창고 운영")
	if err != nil {
		t.Fatal(err)
	}
	requester, err = data.UserByID(ctx, requester.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := data.CreateRoleApprovalRequest(ctx, requester, role.ID, "야간 출고 담당"); err != nil {
		t.Fatal(err)
	}

	views, err := data.ListApprovalRequests(ctx, &bootstrap.RealmID, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(views) != 1 {
		t.Fatalf("expected one request, got %d", len(views))
	}
	view := views[0]
	// A reviewer must be able to see who is asking and what approving grants,
	// not just a truncated identifier and the word ROLE_ASSIGNMENT.
	if view.RequesterUsername != "requester" || view.RequesterDisplayName != "Req Uester" {
		t.Fatalf("requester was not resolved: %+v", view)
	}
	if view.TargetRoleName != "warehouse-operator" {
		t.Fatalf("target role was not resolved: %q", view.TargetRoleName)
	}
	if view.ReviewerUsername != "team-lead" {
		t.Fatalf("reviewer was not resolved: %q", view.ReviewerUsername)
	}
	if view.RealmName == "" {
		t.Fatalf("realm was not resolved: %+v", view)
	}

	// A payload whose role_id is not a UUID must not fail the whole listing.
	if _, err := data.Pool.Exec(ctx, `INSERT INTO approval_requests(id,realm_id,requester_id,kind,payload,reason,status)
		VALUES($1,$2,$3,'ROLE_ASSIGNMENT','{"role_id":"not-a-uuid"}','malformed','PENDING')`,
		uuid.New(), bootstrap.RealmID, requester.ID); err != nil {
		t.Fatal(err)
	}
	views, err = data.ListApprovalRequests(ctx, &bootstrap.RealmID, nil, nil)
	if err != nil {
		t.Fatalf("a malformed payload broke the listing: %v", err)
	}
	if len(views) != 2 {
		t.Fatalf("expected two requests, got %d", len(views))
	}
}

func TestIntegrationAuditFilterNarrowsAndCountsMatches(t *testing.T) {
	data := openIntegrationStore(t, integrationSealer(t))
	bootstrap := bootstrapIntegrationStore(t, data)
	ctx := context.Background()
	events := []AuditEvent{
		{RealmID: &bootstrap.RealmID, ActorName: "alice", EventType: "LOGIN_SUCCESS", Result: "SUCCESS", TraceID: "trace-a"},
		{RealmID: &bootstrap.RealmID, ActorName: "alice", EventType: "LOGIN_FAILURE", Result: "FAILURE", TraceID: "trace-b"},
		{RealmID: &bootstrap.RealmID, ActorName: "bob", EventType: "LOGIN_FAILURE", Result: "FAILURE", TraceID: "trace-c"},
		{RealmID: &bootstrap.RealmID, ActorName: "bob", EventType: "TOKEN_ISSUED", Result: "SUCCESS", TraceID: "trace-d"},
	}
	for _, event := range events {
		if err := data.WriteAudit(ctx, event); err != nil {
			t.Fatal(err)
		}
	}

	all, err := data.ListAudit(ctx, AuditFilter{RealmID: &bootstrap.RealmID})
	if err != nil {
		t.Fatal(err)
	}
	if all.Total != len(events) || len(all.Items) != len(events) {
		t.Fatalf("unfiltered listing: total=%d items=%d", all.Total, len(all.Items))
	}

	for name, tc := range map[string]struct {
		filter AuditFilter
		want   int
	}{
		"by event type": {AuditFilter{RealmID: &bootstrap.RealmID, EventType: "LOGIN_FAILURE"}, 2},
		"by result":     {AuditFilter{RealmID: &bootstrap.RealmID, Result: "SUCCESS"}, 2},
		"by actor":      {AuditFilter{RealmID: &bootstrap.RealmID, Actor: "ali"}, 2},
		"by trace":      {AuditFilter{RealmID: &bootstrap.RealmID, TraceID: "trace-c"}, 1},
		"combined":      {AuditFilter{RealmID: &bootstrap.RealmID, EventType: "LOGIN_FAILURE", Actor: "bob"}, 1},
		"no match":      {AuditFilter{RealmID: &bootstrap.RealmID, EventType: "NOT_AN_EVENT"}, 0},
	} {
		page, err := data.ListAudit(ctx, tc.filter)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if page.Total != tc.want || len(page.Items) != tc.want {
			t.Fatalf("%s: total=%d items=%d, want %d", name, page.Total, len(page.Items), tc.want)
		}
	}

	// Paging must report the full match count, not the page size, so the
	// console can show that older events exist.
	page, err := data.ListAudit(ctx, AuditFilter{RealmID: &bootstrap.RealmID, Limit: 2, Offset: 2})
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != len(events) || len(page.Items) != 2 {
		t.Fatalf("paged listing: total=%d items=%d", page.Total, len(page.Items))
	}

	types, err := data.AuditEventTypes(ctx, &bootstrap.RealmID)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(types, "LOGIN_FAILURE") || !slices.Contains(types, "TOKEN_ISSUED") {
		t.Fatalf("event types = %v", types)
	}
}

func TestIntegrationRoleListReportsUsageAndBuiltins(t *testing.T) {
	data := openIntegrationStore(t, integrationSealer(t))
	bootstrap := bootstrapIntegrationStore(t, data)
	ctx := context.Background()
	role, err := data.CreateRole(ctx, bootstrap.RealmID, "warehouse", "창고")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"holder-one", "holder-two"} {
		user, err := data.CreateUser(ctx, bootstrap.RealmID, CreateUserInput{
			Username: name, Password: "holder-password-1234", Enabled: true})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := data.Pool.Exec(ctx, `INSERT INTO user_roles(user_id,role_id) VALUES($1,$2)`, user.ID, role.ID); err != nil {
			t.Fatal(err)
		}
	}

	roles, err := data.ListRoles(ctx, bootstrap.RealmID)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]Role{}
	for _, item := range roles {
		byName[item.Name] = item
	}
	// Deleting a role should not be a blind confirmation.
	if byName["warehouse"].AssignedUsers != 2 || byName["warehouse"].Builtin {
		t.Fatalf("warehouse role = %+v", byName["warehouse"])
	}
	for _, builtin := range []string{"user", "realm-admin"} {
		if !byName[builtin].Builtin {
			t.Fatalf("%s should be reported as built in: %+v", builtin, byName[builtin])
		}
	}
	if err := data.DeleteRole(ctx, bootstrap.RealmID, byName["user"].ID); !errors.Is(err, ErrConflict) {
		t.Fatalf("deleting a built-in role: %v", err)
	}
	if err := data.DeleteRole(ctx, bootstrap.RealmID, role.ID); err != nil {
		t.Fatalf("deleting an assigned role: %v", err)
	}
}

func TestIntegrationLDAPSyncClaimIsExclusiveAndReleasesWhenStale(t *testing.T) {
	data := openIntegrationStore(t, integrationSealer(t))
	bootstrap := bootstrapIntegrationStore(t, data)
	ctx := context.Background()
	created, err := data.CreateLDAPFederation(ctx, bootstrap.RealmID, LDAPFederationInput{
		Name: "corp", Vendor: "OTHER", ConnectionURL: "ldaps://ldap.invalid:636",
		UsersDN: "ou=people,dc=example,dc=com", UsernameLDAPAttribute: "uid", RDNLDAPAttribute: "uid",
		UUIDLDAPAttribute: "entryUUID", UserObjectClasses: []string{"inetOrgPerson"},
		SearchScope: "SUBTREE", BatchSize: 100, EditMode: "READ_ONLY", MissingUserAction: "KEEP",
		ImportEnabled: true, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	if running, err := data.LDAPSyncRunning(ctx, created.ID); err != nil || running {
		t.Fatalf("a fresh provider reported running: %v %v", running, err)
	}
	// The first claim wins; a second must be refused so two full walks of the
	// directory cannot interleave writes to the same users.
	claimed, err := data.ClaimLDAPSyncForTest(ctx, created.ID)
	if err != nil || !claimed {
		t.Fatalf("first claim: claimed=%v err=%v", claimed, err)
	}
	if running, err := data.LDAPSyncRunning(ctx, created.ID); err != nil || !running {
		t.Fatalf("claimed provider did not report running: %v %v", running, err)
	}
	again, err := data.ClaimLDAPSyncForTest(ctx, created.ID)
	if err != nil || again {
		t.Fatalf("second claim was granted: claimed=%v err=%v", again, err)
	}
	// Starting a sync while one is claimed reports the dedicated error.
	if _, err := data.SyncLDAPFederation(ctx, created.ID); !errors.Is(err, ErrSyncInProgress) {
		t.Fatalf("SyncLDAPFederation error = %v, want ErrSyncInProgress", err)
	}

	// A claim whose owner disappeared must not wedge the provider forever.
	if _, err := data.Pool.Exec(ctx, `UPDATE user_federations SET updated_at=now()-interval '2 hours' WHERE id=$1`, created.ID); err != nil {
		t.Fatal(err)
	}
	if running, err := data.LDAPSyncRunning(ctx, created.ID); err != nil || running {
		t.Fatalf("a stale claim still reported running: %v %v", running, err)
	}
	stale, err := data.ClaimLDAPSyncForTest(ctx, created.ID)
	if err != nil || !stale {
		t.Fatalf("stale claim was not released: claimed=%v err=%v", stale, err)
	}

	if _, err := data.LDAPSyncRunning(ctx, uuid.New()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown provider error = %v, want ErrNotFound", err)
	}
}

func TestIntegrationUserSortIsWhitelistedAndStable(t *testing.T) {
	data := openIntegrationStore(t, integrationSealer(t))
	bootstrap := bootstrapIntegrationStore(t, data)
	ctx := context.Background()
	realm, err := data.CreateRealm(ctx, CreateRealmInput{Name: "sortable", DisplayName: "Sortable",
		IssuerURL: "https://sso.example.com/realms/sortable"})
	if err != nil {
		t.Fatal(err)
	}
	_ = bootstrap
	for _, seed := range []struct{ username, display string }{
		{"carol", "Anna"}, {"alice", "Zoe"}, {"bob", "Mid"},
	} {
		if _, err := data.CreateUser(ctx, realm.ID, CreateUserInput{
			Username: seed.username, DisplayName: seed.display, Password: "sortable-password-1234", Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}
	names := func(sort UserSort) []string {
		users, err := data.ListUsers(ctx, realm.ID, "", sort, 100, 0)
		if err != nil {
			t.Fatal(err)
		}
		result := make([]string, 0, len(users))
		for _, user := range users {
			result = append(result, user.Username)
		}
		return result
	}

	if got := names(UserSort{}); !slices.Equal(got, []string{"alice", "bob", "carol"}) {
		t.Fatalf("default order = %v", got)
	}
	if got := names(UserSort{Column: "username", Descending: true}); !slices.Equal(got, []string{"carol", "bob", "alice"}) {
		t.Fatalf("descending username = %v", got)
	}
	if got := names(UserSort{Column: "display_name"}); !slices.Equal(got, []string{"carol", "bob", "alice"}) {
		t.Fatalf("display name order = %v", got)
	}
	// An unknown or hostile column must fall back rather than reach the
	// statement: the value is interpolated, not bound.
	for _, column := range []string{"", "unknown", "username; DROP TABLE users", "(SELECT 1)"} {
		got := names(UserSort{Column: column})
		if !slices.Equal(got, []string{"alice", "bob", "carol"}) {
			t.Fatalf("sort by %q = %v, want the default order", column, got)
		}
	}
	var remaining int
	if err := data.Pool.QueryRow(ctx, "SELECT count(*) FROM users WHERE realm_id=$1", realm.ID).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 3 {
		t.Fatalf("users table was altered: %d rows", remaining)
	}
}

func TestIntegrationAuditOrderDirection(t *testing.T) {
	data := openIntegrationStore(t, integrationSealer(t))
	bootstrap := bootstrapIntegrationStore(t, data)
	ctx := context.Background()
	for _, name := range []string{"first", "second", "third"} {
		if err := data.WriteAudit(ctx, AuditEvent{RealmID: &bootstrap.RealmID, ActorName: name,
			EventType: "ORDER_TEST", Result: "SUCCESS"}); err != nil {
			t.Fatal(err)
		}
	}
	newest, err := data.ListAudit(ctx, AuditFilter{RealmID: &bootstrap.RealmID, EventType: "ORDER_TEST"})
	if err != nil {
		t.Fatal(err)
	}
	if newest.Items[0].ActorName != "third" {
		t.Fatalf("default order started with %q", newest.Items[0].ActorName)
	}
	// Reconstructing an incident needs the oldest first.
	oldest, err := data.ListAudit(ctx, AuditFilter{RealmID: &bootstrap.RealmID, EventType: "ORDER_TEST", Ascending: true})
	if err != nil {
		t.Fatal(err)
	}
	if oldest.Items[0].ActorName != "first" {
		t.Fatalf("ascending order started with %q", oldest.Items[0].ActorName)
	}
}

func TestIntegrationLDAPSyncOutcomeReachesTheAuditTrail(t *testing.T) {
	data := openIntegrationStore(t, integrationSealer(t))
	bootstrap := bootstrapIntegrationStore(t, data)
	ctx := context.Background()
	created, err := data.CreateLDAPFederation(ctx, bootstrap.RealmID, LDAPFederationInput{
		Name: "corp", Vendor: "OTHER", ConnectionURL: "ldaps://ldap.invalid:636",
		UsersDN: "ou=people,dc=example,dc=com", UsernameLDAPAttribute: "uid", RDNLDAPAttribute: "uid",
		UUIDLDAPAttribute: "entryUUID", UserObjectClasses: []string{"inetOrgPerson"},
		SearchScope: "SUBTREE", BatchSize: 100, EditMode: "READ_ONLY", MissingUserAction: "KEEP",
		ImportEnabled: true, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	// The directory is unreachable, so the run fails; the point is that the
	// outcome is recorded where it is retained for a year, not only in the
	// server log. A run under the DISABLE policy deactivates accounts.
	if _, err := data.SyncLDAPFederation(ctx, created.ID); err == nil {
		t.Fatal("expected the unreachable directory to fail the sync")
	}
	page, err := data.ListAudit(ctx, AuditFilter{RealmID: &bootstrap.RealmID, EventType: "LDAP_FEDERATION_SYNC"})
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 1 {
		t.Fatalf("audit events for the sync outcome = %d, want 1", page.Total)
	}
	event := page.Items[0]
	if event.Result != "FAILURE" || event.TargetID != created.ID.String() {
		t.Fatalf("unexpected audit event: %+v", event)
	}
	for _, key := range []string{"provider", "read", "added", "updated", "failed", "disabled", "error"} {
		if !strings.Contains(string(event.Detail), `"`+key+`"`) {
			t.Fatalf("audit detail is missing %q: %s", key, event.Detail)
		}
	}
}

func TestIntegrationIdleTimeoutEndsUnusedSessionsEverywhere(t *testing.T) {
	data := openIntegrationStore(t, integrationSealer(t))
	bootstrap := bootstrapIntegrationStore(t, data)
	ctx := context.Background()
	if err := data.EnsureActiveSigningKey(ctx, bootstrap.RealmID); err != nil {
		t.Fatal(err)
	}
	realm, err := data.RealmByID(ctx, bootstrap.RealmID)
	if err != nil {
		t.Fatal(err)
	}
	// Zero is the default and must preserve the previous behaviour.
	if realm.IdleTimeoutSeconds != 0 {
		t.Fatalf("default idle timeout = %d, want 0", realm.IdleTimeoutSeconds)
	}
	clientID := createIntegrationClient(t, data, bootstrap.RealmID)

	newSession := func() (NewSession, string) {
		session, err := data.CreateSession(ctx, bootstrap.RealmID, bootstrap.AdminUserID,
			time.Hour, "127.0.0.1", "integration-test", "password")
		if err != nil {
			t.Fatal(err)
		}
		userID, sid := bootstrap.AdminUserID, session.Session.ID
		refresh, err := data.CreateRefreshToken(ctx, RefreshToken{RealmID: bootstrap.RealmID, ClientID: clientID,
			UserID: &userID, SessionID: &sid, Scope: []string{"openid"}, ExpiresAt: time.Now().UTC().Add(time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
		return session, refresh
	}
	idle := func(session NewSession, seconds int) {
		if _, err := data.Pool.Exec(ctx, `UPDATE sso_sessions SET last_access=now()-make_interval(secs => $2) WHERE id=$1`,
			session.Session.ID, seconds); err != nil {
			t.Fatal(err)
		}
	}

	// With the check off, an old last_access changes nothing.
	session, refresh := newSession()
	idle(session, 7200)
	if _, err := data.SessionByToken(ctx, session.Token); err != nil {
		t.Fatalf("idle session rejected while the timeout is disabled: %v", err)
	}

	base := UpdateRealmInput{DisplayName: realm.DisplayName, IssuerURL: realm.IssuerURL, Enabled: true,
		AccessTokenTTLSeconds: realm.AccessTokenTTLSeconds, RefreshTokenTTLSeconds: realm.RefreshTokenTTLSeconds,
		SessionTTLSeconds: realm.SessionTTLSeconds, PasswordMinLength: realm.PasswordMinLength,
		MaxLoginAttempts: realm.MaxLoginAttempts, LockoutSeconds: realm.LockoutSeconds, IdleTimeoutSeconds: 900}
	if _, err := data.UpdateRealm(ctx, realm.ID, base); err != nil {
		t.Fatal(err)
	}
	// A successful validation counts as activity and refreshes last_access, so
	// the session is put back into an idle state after the check above.
	idle(session, 7200)

	// Every path that accepts a session must apply the same rule; enforcing it
	// in some but not others would leave a stale session issuing tokens.
	if _, err := data.SessionByToken(ctx, session.Token); !errors.Is(err, ErrNotFound) {
		t.Fatalf("SessionByToken accepted an idle session: %v", err)
	}
	if _, err := data.SessionAuthTime(ctx, session.Session.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("SessionAuthTime accepted an idle session: %v", err)
	}
	if err := data.ValidateActiveSessionBinding(ctx, session.Session.ID, bootstrap.AdminUserID, realm.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ValidateActiveSessionBinding accepted an idle session: %v", err)
	}
	if _, _, err := data.RotateRefreshToken(ctx, refresh, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("RotateRefreshToken accepted an idle session: %v", err)
	}

	// A session still in use is unaffected.
	active, activeRefresh := newSession()
	idle(active, 60)
	if _, err := data.SessionByToken(ctx, active.Token); err != nil {
		t.Fatalf("an active session was rejected: %v", err)
	}
	if _, _, err := data.RotateRefreshToken(ctx, activeRefresh, nil); err != nil {
		t.Fatalf("refresh on an active session was rejected: %v", err)
	}

	for _, invalid := range []int{100, 2592001, realm.SessionTTLSeconds + 1} {
		out := base
		out.IdleTimeoutSeconds = invalid
		if _, err := data.UpdateRealm(ctx, realm.ID, out); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("idle timeout %d was accepted: %v", invalid, err)
		}
	}
}

// TestIntegrationUpgradeFromAnEarlierSchemaKeepsData applies the migrations an
// older release shipped, writes records directly into that schema, then applies
// the rest. Every migration has only ever been exercised against an empty
// database, which is the case that cannot fail; upgrading a populated one is
// the case that can. The seed data is written with plain SQL because the
// current store selects columns the older schema does not have — the server
// never reads a database it has not migrated, since Migrate runs before it
// starts serving.
func TestIntegrationUpgradeFromAnEarlierSchemaKeepsData(t *testing.T) {
	data := openIntegrationStoreWithoutMigrating(t, integrationSealer(t))
	ctx := context.Background()

	entries, err := fs.ReadDir(migrationFiles, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".sql") {
			names = append(names, entry.Name())
		}
	}
	slices.Sort(names)
	if len(names) < 3 {
		t.Skip("need at least three migrations to model an upgrade")
	}
	older := names[:len(names)-2]

	if _, err := data.Pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		t.Fatal(err)
	}
	for _, name := range older {
		body, err := migrationFiles.ReadFile("migrations/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := data.Pool.Exec(ctx, string(body)); err != nil {
			t.Fatalf("apply %s: %v", name, err)
		}
		if _, err := data.Pool.Exec(ctx, `INSERT INTO schema_migrations(version) VALUES($1)`, name); err != nil {
			t.Fatal(err)
		}
	}

	realmID, userID := uuid.New(), uuid.New()
	hash, err := password.Hash("legacy-password-12345")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := data.Pool.Exec(ctx, `INSERT INTO realms(id,name,display_name,issuer_url)
		VALUES($1,'legacy','Legacy','https://sso.example.com/realms/legacy')`, realmID); err != nil {
		t.Fatal(err)
	}
	if _, err := data.Pool.Exec(ctx, `INSERT INTO users(id,realm_id,username,display_name,password_hash,enabled)
		VALUES($1,$2,'legacy-user','Legacy User',$3,true)`, userID, realmID, hash); err != nil {
		t.Fatal(err)
	}
	token, err := cryptoutil.RandomToken(32)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := data.Pool.Exec(ctx, `INSERT INTO sso_sessions(id,realm_id,user_id,token_hash,csrf_hash,expires_at)
		VALUES($1,$2,$3,$4,$5,now()+interval '1 hour')`,
		uuid.New(), realmID, userID, data.Sealer.Digest(token), data.Sealer.Digest("csrf")); err != nil {
		t.Fatal(err)
	}

	if err := Migrate(ctx, data.Pool); err != nil {
		t.Fatalf("upgrade migration failed on a populated database: %v", err)
	}

	// Records written before the upgrade still work through the current code.
	if _, err := data.SessionByToken(ctx, token); err != nil {
		t.Fatalf("a session created before the upgrade stopped working: %v", err)
	}
	upgraded, err := data.RealmByID(ctx, realmID)
	if err != nil {
		t.Fatalf("a Realm created before the upgrade cannot be read: %v", err)
	}
	// Columns the newer releases added must carry defaults that preserve the
	// previous behaviour rather than switching something on during an upgrade.
	if upgraded.IdleTimeoutSeconds != 0 {
		t.Fatalf("idle timeout defaulted to %d; an upgrade must not start expiring sessions", upgraded.IdleTimeoutSeconds)
	}
	if upgraded.PasswordMinLength < 8 || upgraded.MaxLoginAttempts < 3 || upgraded.LockoutSeconds < 30 {
		t.Fatalf("policy defaults are outside their documented range: %+v", upgraded)
	}
	result, err := data.Authenticate(ctx, upgraded, "legacy-user", "legacy-password-12345")
	if err != nil || !result.Success {
		t.Fatalf("an account created before the upgrade cannot sign in: %+v err=%v", result, err)
	}
	// Applying again must be a no-op rather than an error.
	if err := Migrate(ctx, data.Pool); err != nil {
		t.Fatalf("re-running migrations failed: %v", err)
	}
}

// TestIntegrationConcurrentRefreshRotationIsSafe exercises the case the grace
// window exists for: two tabs refreshing the same token at the same moment.
// The earlier coverage presented the token twice in sequence, which does not
// contend for the row lock the rotation relies on.
func TestIntegrationConcurrentRefreshRotationIsSafe(t *testing.T) {
	data := openIntegrationStore(t, integrationSealer(t))
	bootstrap := bootstrapIntegrationStore(t, data)
	ctx := context.Background()
	clientID := createIntegrationClient(t, data, bootstrap.RealmID)
	session, err := data.CreateSession(ctx, bootstrap.RealmID, bootstrap.AdminUserID,
		time.Hour, "127.0.0.1", "integration-test", "password")
	if err != nil {
		t.Fatal(err)
	}
	userID, sessionID := bootstrap.AdminUserID, session.Session.ID
	raw, err := data.CreateRefreshToken(ctx, RefreshToken{RealmID: bootstrap.RealmID, ClientID: clientID,
		UserID: &userID, SessionID: &sessionID, Scope: []string{"openid"},
		ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}

	const attempts = 6
	start := make(chan struct{})
	var wait sync.WaitGroup
	issued := make([]string, attempts)
	errs := make([]error, attempts)
	for index := range attempts {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, token, err := data.RotateRefreshToken(ctx, raw, nil)
			issued[index], errs[index] = token, err
		}()
	}
	close(start)
	wait.Wait()

	var succeeded int
	unique := map[string]bool{}
	for index, err := range errs {
		if err != nil {
			// Inside the grace window nothing should be treated as reuse.
			if errors.Is(err, ErrTokenReuse) {
				t.Fatalf("attempt %d was treated as theft inside the grace window", index)
			}
			t.Fatalf("attempt %d failed: %v", index, err)
		}
		succeeded++
		if issued[index] == "" || unique[issued[index]] {
			t.Fatalf("attempt %d returned a duplicate or empty token", index)
		}
		unique[issued[index]] = true
	}
	if succeeded != attempts {
		t.Fatalf("%d of %d concurrent refreshes succeeded", succeeded, attempts)
	}

	// Every token belongs to one family, and every one still works, so no tab
	// is logged out by another tab's refresh.
	var families int
	if err := data.Pool.QueryRow(ctx, `SELECT count(DISTINCT family_id) FROM refresh_tokens`).Scan(&families); err != nil {
		t.Fatal(err)
	}
	if families != 1 {
		t.Fatalf("concurrent rotation produced %d families", families)
	}
	for index, token := range issued {
		if _, active, err := data.InspectRefreshToken(ctx, token); err != nil || !active {
			t.Fatalf("token %d is not usable: active=%v err=%v", index, active, err)
		}
	}

	// Aging the recorded rotation past the window restores theft detection.
	if _, err := data.Pool.Exec(ctx, `UPDATE refresh_tokens SET rotated_at=now()-make_interval(secs => $1)
		WHERE rotated_at IS NOT NULL`, int(refreshRotationGrace.Seconds())+60); err != nil {
		t.Fatal(err)
	}
	if _, _, err := data.RotateRefreshToken(ctx, raw, nil); !errors.Is(err, ErrTokenReuse) {
		t.Fatalf("reuse after the grace window: %v", err)
	}
}

// TestIntegrationConcurrentLDAPSyncClaimAdmitsOne races the claim the way two
// administrators or an overlapping scheduled sweep would.
func TestIntegrationConcurrentLDAPSyncClaimAdmitsOne(t *testing.T) {
	data := openIntegrationStore(t, integrationSealer(t))
	bootstrap := bootstrapIntegrationStore(t, data)
	ctx := context.Background()
	created, err := data.CreateLDAPFederation(ctx, bootstrap.RealmID, LDAPFederationInput{
		Name: "corp", Vendor: "OTHER", ConnectionURL: "ldaps://ldap.invalid:636",
		UsersDN: "ou=people,dc=example,dc=com", UsernameLDAPAttribute: "uid", RDNLDAPAttribute: "uid",
		UUIDLDAPAttribute: "entryUUID", UserObjectClasses: []string{"inetOrgPerson"},
		SearchScope: "SUBTREE", BatchSize: 100, EditMode: "READ_ONLY", MissingUserAction: "KEEP",
		ImportEnabled: true, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	const racers = 8
	start := make(chan struct{})
	var wait sync.WaitGroup
	claimed := make([]bool, racers)
	errs := make([]error, racers)
	for index := range racers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			claimed[index], errs[index] = data.ClaimLDAPSyncForTest(ctx, created.ID)
		}()
	}
	close(start)
	wait.Wait()

	winners := 0
	for index, err := range errs {
		if err != nil {
			t.Fatalf("racer %d failed: %v", index, err)
		}
		if claimed[index] {
			winners++
		}
	}
	// Two full walks of a directory would interleave writes to the same users.
	if winners != 1 {
		t.Fatalf("%d racers claimed the synchronization, want exactly 1", winners)
	}
}

// A replayed authorization code means the code leaked: one of the two
// redemptions was not the relying party. The server cannot tell which, so the
// tokens the first redemption produced have to go, exactly as a replayed
// refresh token takes down its family.
func TestIntegrationAuthorizationCodeReuseRevokesIssuedRefreshTokens(t *testing.T) {
	data := openIntegrationStore(t, integrationSealer(t))
	bootstrap := bootstrapIntegrationStore(t, data)
	ctx := context.Background()
	clientID := createIntegrationClient(t, data, bootstrap.RealmID)
	session, err := data.CreateSession(ctx, bootstrap.RealmID, bootstrap.AdminUserID,
		time.Hour, "127.0.0.1", "integration-test", "password")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := data.CreateAuthorizationCode(ctx, AuthorizationCode{
		RealmID: bootstrap.RealmID, ClientID: clientID, UserID: bootstrap.AdminUserID,
		SessionID: session.Session.ID, RedirectURI: "https://client.example.test/callback", Scope: []string{"openid"},
	})
	if err != nil {
		t.Fatal(err)
	}
	code, err := data.RedeemAuthorizationCode(ctx, raw, func(AuthorizationCode) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	userID := bootstrap.AdminUserID
	issued, err := data.CreateRefreshToken(ctx, RefreshToken{RealmID: code.RealmID, ClientID: code.ClientID,
		UserID: &userID, SessionID: &code.SessionID, Scope: []string{"openid"},
		ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := data.RedeemAuthorizationCode(ctx, raw, func(AuthorizationCode) error { return nil }); !errors.Is(err, ErrCodeReuse) {
		t.Fatalf("replayed code error = %v, want ErrCodeReuse", err)
	}

	inspected, active, err := data.InspectRefreshToken(ctx, issued)
	if err != nil {
		t.Fatal(err)
	}
	if active {
		t.Errorf("refresh token issued from a replayed code is still active: %+v", inspected)
	}
	var revoked bool
	if err := data.Pool.QueryRow(ctx,
		`SELECT revoked_at IS NOT NULL FROM refresh_tokens WHERE session_id=$1 AND client_id=$2`,
		session.Session.ID, clientID).Scan(&revoked); err != nil {
		t.Fatal(err)
	}
	if !revoked {
		t.Error("refresh token from the replayed code was left usable")
	}

	// An unknown code is still just an unknown code: reuse detection must not
	// turn a stray request into a revocation signal.
	if _, err := data.RedeemAuthorizationCode(ctx, "not-a-real-code", func(AuthorizationCode) error { return nil }); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown code error = %v, want ErrNotFound", err)
	}
}

// The approval workflow exists so that nobody grants themselves a role. Its
// only enforcement is that the reviewer is the requester's manager, and
// manager_id was accepted without checking who it points at — so pointing it
// at the requester, or at somebody in another realm entirely, dissolved the
// control it was there to provide.
func TestIntegrationApprovalReviewerCannotBeSelfOrForeign(t *testing.T) {
	data := openIntegrationStore(t, integrationSealer(t))
	bootstrap := bootstrapIntegrationStore(t, data)
	ctx := context.Background()
	if _, err := data.Pool.Exec(ctx, `UPDATE realms SET approval_enabled=true WHERE id=$1`, bootstrap.RealmID); err != nil {
		t.Fatal(err)
	}
	role, err := data.CreateRole(ctx, bootstrap.RealmID, "payments-admin", "")
	if err != nil {
		t.Fatal(err)
	}
	alice, err := data.CreateUser(ctx, bootstrap.RealmID, CreateUserInput{
		Username: "alice", Password: "alice-password-123", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}

	// Naming yourself as your own approver must be refused outright.
	if _, err := data.UpdateUser(ctx, alice.ID, UpdateUserInput{
		Enabled: true, ManagerID: &alice.ID}); err == nil {
		t.Error("a user was accepted as their own manager")
	}

	other, err := data.CreateRealm(ctx, CreateRealmInput{
		Name: "partner", DisplayName: "Partner", IssuerURL: "https://partner.example.test/realms/partner"})
	if err != nil {
		t.Fatal(err)
	}
	outsider, err := data.CreateUser(ctx, other.ID, CreateUserInput{
		Username: "outsider", Password: "outsider-password-123", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := data.UpdateUser(ctx, alice.ID, UpdateUserInput{
		Enabled: true, ManagerID: &outsider.ID}); err == nil {
		t.Error("a manager from another realm was accepted")
	}

	// Even if such a pairing already exists in an upgraded database, deciding
	// the request must not work: authorization is checked at the decision.
	if _, err := data.Pool.Exec(ctx, `UPDATE users SET manager_id=$2 WHERE id=$1`, alice.ID, alice.ID); err != nil {
		t.Fatal(err)
	}
	alice, err = data.UserByID(ctx, alice.ID)
	if err != nil {
		t.Fatal(err)
	}
	request, err := data.CreateRoleApprovalRequest(ctx, alice, role.ID, "need it")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := data.DecideApprovalRequest(ctx, request.ID, alice.ID, false, false, uuid.Nil, true, ""); err == nil {
		t.Error("a requester approved their own role request")
	}
	var granted bool
	if err := data.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM user_roles WHERE user_id=$1 AND role_id=$2)`,
		alice.ID, role.ID).Scan(&granted); err != nil {
		t.Fatal(err)
	}
	if granted {
		t.Error("self-approval granted the role")
	}

	// The workflow itself must still work: a real manager, in the same realm,
	// approves and the role lands.
	lead, err := data.CreateUser(ctx, bootstrap.RealmID, CreateUserInput{
		Username: "lead", Password: "lead-password-1234", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := data.Pool.Exec(ctx, `UPDATE users SET manager_id=$2 WHERE id=$1`, alice.ID, lead.ID); err != nil {
		t.Fatal(err)
	}
	alice, err = data.UserByID(ctx, alice.ID)
	if err != nil {
		t.Fatal(err)
	}
	// A fresh request, raised after the manager was assigned so that it names
	// them as reviewer. It asks for a different role because the first request
	// is still waiting and a second for the same one is refused as a duplicate.
	secondRole, err := data.CreateRole(ctx, alice.RealmID, "auditor-second", "")
	if err != nil {
		t.Fatal(err)
	}
	legitimate, err := data.CreateRoleApprovalRequest(ctx, alice, secondRole.ID, "still need it")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := data.DecideApprovalRequest(ctx, legitimate.ID, lead.ID, false, false, uuid.Nil, true, "ok"); err != nil {
		t.Fatalf("a manager could not approve their report's request: %v", err)
	}
	if err := data.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM user_roles WHERE user_id=$1 AND role_id=$2)`,
		alice.ID, secondRole.ID).Scan(&granted); err != nil {
		t.Fatal(err)
	}
	if !granted {
		t.Error("an approved request did not grant the role")
	}
}

// A refresh that fails after the rotation has committed must not cost the
// client its token family. The exchange is two steps — rotate, then issue —
// and if the second fails the caller never receives the new token while the
// old one is already marked rotated. Once the grace window passes, presenting
// the only token it still holds looks exactly like theft.
func TestIntegrationFailedRefreshExchangeDoesNotStrandTheClient(t *testing.T) {
	data := openIntegrationStore(t, integrationSealer(t))
	bootstrap := bootstrapIntegrationStore(t, data)
	ctx := context.Background()
	clientID := createIntegrationClient(t, data, bootstrap.RealmID)
	userID := bootstrap.AdminUserID
	raw, err := data.CreateRefreshToken(ctx, RefreshToken{RealmID: bootstrap.RealmID, ClientID: clientID,
		UserID: &userID, Scope: []string{"openid"}, ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	original, _, err := data.InspectRefreshToken(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}

	rotated, _, err := data.RotateRefreshToken(ctx, raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Stand in for the issue step failing: the caller never saw rotated.
	if err := data.RollbackRefreshRotation(ctx, original.ID, rotated.ID); err != nil {
		t.Fatal(err)
	}
	var orphans int
	if err := data.Pool.QueryRow(ctx, `SELECT count(*) FROM refresh_tokens WHERE id=$1`, rotated.ID).Scan(&orphans); err != nil {
		t.Fatal(err)
	}
	if orphans != 0 {
		t.Error("the undelivered token was left behind")
	}

	// The grace window must not be what saves the retry, so age the rotation
	// past it before trying again.
	if _, err := data.Pool.Exec(ctx, `UPDATE refresh_tokens SET rotated_at=now()-interval '10 minutes'
		WHERE id=$1 AND rotated_at IS NOT NULL`, original.ID); err != nil {
		t.Fatal(err)
	}
	retry, _, err := data.RotateRefreshToken(ctx, raw, nil)
	if err != nil {
		t.Fatalf("the client's only refresh token was rejected after a failed exchange: %v", err)
	}
	if retry.FamilyID != original.FamilyID {
		t.Errorf("retry started a new family: %v want %v", retry.FamilyID, original.FamilyID)
	}
}

// A directory that returns nothing looks the same whether every account really
// left or the search was simply pointed at the wrong place. Under the DISABLE
// policy the old behaviour read it the first way and deactivated every
// federated account in the Realm, ending all of their sessions — so a mistyped
// users DN locked the organisation out on the next scheduled sweep.
func TestIntegrationEmptyLDAPReadDoesNotDisableEveryone(t *testing.T) {
	data := openIntegrationStore(t, integrationSealer(t))
	bootstrap := bootstrapIntegrationStore(t, data)
	ctx := context.Background()
	provider, err := data.CreateLDAPFederation(ctx, bootstrap.RealmID, LDAPFederationInput{
		Name: "corp", Vendor: "OTHER", ConnectionURL: "ldaps://ldap.invalid:636",
		UsersDN: "ou=people,dc=example,dc=com", UsernameLDAPAttribute: "uid", RDNLDAPAttribute: "uid",
		UUIDLDAPAttribute: "entryUUID", UserObjectClasses: []string{"inetOrgPerson"},
		SearchScope: "SUBTREE", BatchSize: 100, EditMode: "READ_ONLY", MissingUserAction: "DISABLE",
		ImportEnabled: true, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"kim", "lee", "park"} {
		user, createErr := data.CreateUser(ctx, bootstrap.RealmID, CreateUserInput{
			Username: name, Password: name + "-password-1234", Enabled: true})
		if createErr != nil {
			t.Fatal(createErr)
		}
		if _, err := data.Pool.Exec(ctx, `UPDATE users SET federation_id=$2,external_id=$3,
			federation_synced_at=now()-interval '1 day' WHERE id=$1`, user.ID, provider.ID, name); err != nil {
			t.Fatal(err)
		}
	}

	startedAt := time.Now().UTC()
	disabled, err := data.disableUnseenFederatedUsers(ctx, provider.ID, startedAt, 0)
	if !errors.Is(err, ErrSyncReadNothing) {
		t.Fatalf("empty read error = %v, want ErrSyncReadNothing", err)
	}
	if disabled != 0 {
		t.Errorf("an empty read disabled %d accounts", disabled)
	}
	var stillEnabled int
	if err := data.Pool.QueryRow(ctx,
		"SELECT count(*) FROM users WHERE federation_id=$1 AND enabled=true", provider.ID).Scan(&stillEnabled); err != nil {
		t.Fatal(err)
	}
	if stillEnabled != 3 {
		t.Errorf("enabled federated accounts = %d, want 3", stillEnabled)
	}

	// The policy must still do its job when the directory actually answered:
	// two accounts were seen this run, the third was not.
	if _, err := data.Pool.Exec(ctx, `UPDATE users SET federation_synced_at=now()
		WHERE federation_id=$1 AND username IN ('kim','lee')`, provider.ID); err != nil {
		t.Fatal(err)
	}
	disabled, err = data.disableUnseenFederatedUsers(ctx, provider.ID, startedAt, 2)
	if err != nil {
		t.Fatal(err)
	}
	if disabled != 1 {
		t.Errorf("disabled %d accounts, want 1", disabled)
	}
	var parkEnabled bool
	if err := data.Pool.QueryRow(ctx,
		"SELECT enabled FROM users WHERE federation_id=$1 AND username='park'", provider.ID).Scan(&parkEnabled); err != nil {
		t.Fatal(err)
	}
	if parkEnabled {
		t.Error("an account the directory no longer lists stayed enabled")
	}
}

// A rotated refresh token inherits its predecessor's expiry, so the whole
// family dies when the first token would have. That is a deliberate ceiling —
// a sliding expiry would let a client that keeps refreshing hold a credential
// forever — but nothing recorded it, and a future change to what rotation
// copies would flip it silently in the direction that removes the ceiling.
func TestIntegrationRefreshRotationDoesNotExtendTheFamilyLifetime(t *testing.T) {
	data := openIntegrationStore(t, integrationSealer(t))
	bootstrap := bootstrapIntegrationStore(t, data)
	ctx := context.Background()
	clientID := createIntegrationClient(t, data, bootstrap.RealmID)
	userID := bootstrap.AdminUserID
	expiry := time.Now().UTC().Add(30 * time.Minute)
	raw, err := data.CreateRefreshToken(ctx, RefreshToken{RealmID: bootstrap.RealmID, ClientID: clientID,
		UserID: &userID, Scope: []string{"openid"}, ExpiresAt: expiry})
	if err != nil {
		t.Fatal(err)
	}
	// Two rotations, so a per-rotation extension would be unmistakable.
	rotated, rawNext, err := data.RotateRefreshToken(ctx, raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	rotated, _, err = data.RotateRefreshToken(ctx, rawNext, nil)
	if err != nil {
		t.Fatal(err)
	}
	// PostgreSQL stores microseconds, so compare instants rather than values.
	if drift := rotated.ExpiresAt.Sub(expiry); drift > time.Second || drift < -time.Second {
		t.Errorf("rotation moved the expiry by %s; the family lifetime must be fixed at issuance", drift)
	}
}

// A locked account used to be refused without the password ever being hashed,
// so it answered in a fraction of the time an ordinary rejection takes. The
// login error is deliberately identical for every failure, and that timing
// gap handed back exactly what the wording withholds: this account exists and
// is locked. Verifying regardless also tells the caller whether the password
// was right, which is what makes it safe to name the real obstacle.
func TestIntegrationLockedAccountStillVerifiesThePassword(t *testing.T) {
	data := openIntegrationStore(t, integrationSealer(t))
	bootstrap := bootstrapIntegrationStore(t, data)
	ctx := context.Background()
	if _, err := data.Pool.Exec(ctx,
		`UPDATE realms SET max_login_attempts=3, lockout_seconds=600 WHERE id=$1`, bootstrap.RealmID); err != nil {
		t.Fatal(err)
	}
	realm, err := data.RealmByID(ctx, bootstrap.RealmID)
	if err != nil {
		t.Fatal(err)
	}
	const secret = "victim-password-1234"
	victim, err := data.CreateUser(ctx, bootstrap.RealmID, CreateUserInput{
		Username: "victim", Password: secret, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if _, err := data.AuthenticatePassword(ctx, realm, "victim", "wrong-password-here"); err != nil {
			t.Fatal(err)
		}
	}
	locked, err := data.UserByID(ctx, victim.ID)
	if err != nil {
		t.Fatal(err)
	}
	if locked.LockedUntil == nil {
		t.Fatal("the account was not locked by repeated failures")
	}

	wrong, err := data.AuthenticatePassword(ctx, realm, "victim", "still-wrong-here")
	if err != nil {
		t.Fatal(err)
	}
	if wrong.FailureReason != "ACCOUNT_LOCKED" || wrong.CredentialsValid {
		t.Errorf("locked with a wrong password = %+v", wrong)
	}
	right, err := data.AuthenticatePassword(ctx, realm, "victim", secret)
	if err != nil {
		t.Fatal(err)
	}
	if right.Success {
		t.Error("a locked account was allowed in")
	}
	if right.FailureReason != "ACCOUNT_LOCKED" || !right.CredentialsValid {
		t.Errorf("locked with the right password = %+v", right)
	}

	// Attempts against a locked account must not push the lockout further out,
	// or anyone could keep a colleague signed out indefinitely.
	after, err := data.UserByID(ctx, victim.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.LockedUntil == nil || !after.LockedUntil.Equal(*locked.LockedUntil) {
		t.Errorf("the lockout moved: %v then %v", locked.LockedUntil, after.LockedUntil)
	}
}

// Which relying parties took part in a session is not recorded anywhere; it is
// inferred from the refresh tokens and authorization codes still on file. A
// client that does not use refresh tokens leaves only the code, and the code is
// swept a day after it expires — so for any session outliving that, back-channel
// logout quietly stops reaching it. The Realm session lifetime goes to 30 days.
func TestIntegrationBackchannelTargetsSurvivePruning(t *testing.T) {
	data := openIntegrationStore(t, integrationSealer(t))
	bootstrap := bootstrapIntegrationStore(t, data)
	ctx := context.Background()
	created, err := data.CreateClient(ctx, bootstrap.RealmID, CreateClientInput{
		ClientID: "no-refresh", Name: "No Refresh", Type: "confidential",
		RedirectURIs: []string{"https://no-refresh.example.test/cb"},
		GrantTypes:   []string{"authorization_code"}, DefaultScopes: []string{"openid"},
		BackchannelLogoutURI: "https://no-refresh.example.test/backchannel-logout"})
	if err != nil {
		t.Fatal(err)
	}
	session, err := data.CreateSession(ctx, bootstrap.RealmID, bootstrap.AdminUserID,
		20*24*time.Hour, "127.0.0.1", "prune-test", "password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := data.CreateAuthorizationCode(ctx, AuthorizationCode{
		RealmID: bootstrap.RealmID, ClientID: created.Client.ID, UserID: bootstrap.AdminUserID,
		SessionID: session.Session.ID, RedirectURI: "https://no-refresh.example.test/cb",
		Scope: []string{"openid"}}); err != nil {
		t.Fatal(err)
	}
	targets, err := data.BackchannelLogoutTargets(ctx, bootstrap.RealmID, session.Session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 {
		t.Fatalf("targets before pruning = %d, want 1", len(targets))
	}

	// Age the code past the sweep and run the real maintenance pass.
	if _, err := data.Pool.Exec(ctx,
		`UPDATE authorization_codes SET expires_at=now()-interval '3 days' WHERE session_id=$1`,
		session.Session.ID); err != nil {
		t.Fatal(err)
	}
	if err := data.PruneOperationalData(ctx); err != nil {
		t.Fatal(err)
	}
	targets, err = data.BackchannelLogoutTargets(ctx, bootstrap.RealmID, session.Session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 {
		t.Errorf("a live session lost its logout target to pruning: %d targets", len(targets))
	}

	// Retention is one row per client, not every code the session ever used,
	// so a client that keeps returning to the authorization endpoint cannot
	// make the table grow without bound.
	for range 4 {
		if _, err := data.CreateAuthorizationCode(ctx, AuthorizationCode{
			RealmID: bootstrap.RealmID, ClientID: created.Client.ID, UserID: bootstrap.AdminUserID,
			SessionID: session.Session.ID, RedirectURI: "https://no-refresh.example.test/cb",
			Scope: []string{"openid"}}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := data.Pool.Exec(ctx,
		`UPDATE authorization_codes SET expires_at=expires_at-interval '3 days' WHERE session_id=$1`,
		session.Session.ID); err != nil {
		t.Fatal(err)
	}
	if err := data.PruneOperationalData(ctx); err != nil {
		t.Fatal(err)
	}
	var kept int
	if err := data.Pool.QueryRow(ctx,
		`SELECT count(*) FROM authorization_codes WHERE session_id=$1`, session.Session.ID).Scan(&kept); err != nil {
		t.Fatal(err)
	}
	if kept != 1 {
		t.Errorf("kept %d codes for one client, want 1", kept)
	}

	// Once the session is over there is nobody left to notify, so the record
	// goes with it rather than lingering.
	if err := data.RevokeSession(ctx, session.Session.ID); err != nil {
		t.Fatal(err)
	}
	if err := data.PruneOperationalData(ctx); err != nil {
		t.Fatal(err)
	}
	if err := data.Pool.QueryRow(ctx,
		`SELECT count(*) FROM authorization_codes WHERE session_id=$1`, session.Session.ID).Scan(&kept); err != nil {
		t.Fatal(err)
	}
	if kept != 0 {
		t.Errorf("an ended session left %d codes behind", kept)
	}
}

// Undoing a rotation must not disturb a concurrent refresh that succeeded.
// Two tabs refreshing at once both come back with tokens, and if the first
// exchange then fails and rolls back, the second one's tokens are already
// somebody's — rolling those back would sign a working client out.
func TestIntegrationRollbackLeavesAConcurrentRefreshAlone(t *testing.T) {
	data := openIntegrationStore(t, integrationSealer(t))
	bootstrap := bootstrapIntegrationStore(t, data)
	ctx := context.Background()
	clientID := createIntegrationClient(t, data, bootstrap.RealmID)
	userID := bootstrap.AdminUserID
	raw, err := data.CreateRefreshToken(ctx, RefreshToken{RealmID: bootstrap.RealmID, ClientID: clientID,
		UserID: &userID, Scope: []string{"openid"}, ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	original, _, err := data.InspectRefreshToken(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}

	// Both tabs present the same token inside the grace window.
	first, _, err := data.RotateRefreshToken(ctx, raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	second, secondRaw, err := data.RotateRefreshToken(ctx, raw, nil)
	if err != nil {
		t.Fatalf("a second refresh inside the grace window was refused: %v", err)
	}

	// The first tab's exchange fails and is undone.
	if err := data.RollbackRefreshRotation(ctx, original.ID, first.ID); err != nil {
		t.Fatal(err)
	}
	if _, active, err := data.InspectRefreshToken(ctx, secondRaw); err != nil || !active {
		t.Errorf("the concurrent refresh lost its token: active=%v err=%v", active, err)
	}
	var survived int
	if err := data.Pool.QueryRow(ctx,
		`SELECT count(*) FROM refresh_tokens WHERE id=$1 AND revoked_at IS NULL`, second.ID).Scan(&survived); err != nil {
		t.Fatal(err)
	}
	if survived != 1 {
		t.Error("the successful exchange's token was removed by another exchange's rollback")
	}
	// The predecessor keeps its rotation, because a successor built on it is
	// still in use; clearing it would let the old token be replayed.
	var rotatedAt *time.Time
	if err := data.Pool.QueryRow(ctx,
		`SELECT rotated_at FROM refresh_tokens WHERE id=$1`, original.ID).Scan(&rotatedAt); err != nil {
		t.Fatal(err)
	}
	if rotatedAt == nil {
		t.Error("the predecessor was revived while a live successor exists")
	}
}

// Idle expiry is meant to end sessions nobody is using. Only the browser
// console recorded use, so a session driven entirely through OIDC — a relying
// party refreshing tokens for someone who is working in it all afternoon —
// looked idle from the moment they signed in, and was cut off mid-work.
func TestIntegrationOIDCUseKeepsASessionFromGoingIdle(t *testing.T) {
	data := openIntegrationStore(t, integrationSealer(t))
	bootstrap := bootstrapIntegrationStore(t, data)
	ctx := context.Background()
	if _, err := data.Pool.Exec(ctx,
		`UPDATE realms SET idle_timeout_seconds=600 WHERE id=$1`, bootstrap.RealmID); err != nil {
		t.Fatal(err)
	}
	clientID := createIntegrationClient(t, data, bootstrap.RealmID)
	session, err := data.CreateSession(ctx, bootstrap.RealmID, bootstrap.AdminUserID,
		8*time.Hour, "127.0.0.1", "idle-test", "password")
	if err != nil {
		t.Fatal(err)
	}
	userID := bootstrap.AdminUserID
	sessionID := session.Session.ID
	raw, err := data.CreateRefreshToken(ctx, RefreshToken{RealmID: bootstrap.RealmID, ClientID: clientID,
		UserID: &userID, SessionID: &sessionID, Scope: []string{"openid"},
		ExpiresAt: time.Now().UTC().Add(8 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}

	lastAccess := func() time.Time {
		t.Helper()
		var value time.Time
		if err := data.Pool.QueryRow(ctx,
			`SELECT last_access FROM sso_sessions WHERE id=$1`, sessionID).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	// Five minutes of working through the relying party, inside the timeout.
	if _, err := data.Pool.Exec(ctx,
		`UPDATE sso_sessions SET last_access=now()-interval '5 minutes' WHERE id=$1`, sessionID); err != nil {
		t.Fatal(err)
	}
	before := lastAccess()
	if _, _, err := data.RotateRefreshToken(ctx, raw, nil); err != nil {
		t.Fatalf("refresh inside the idle window failed: %v", err)
	}
	if after := lastAccess(); !after.After(before) {
		t.Errorf("a token refresh did not count as using the session: %s", after)
	}

	// Genuinely idle past the timeout still expires, which is the point.
	if _, err := data.Pool.Exec(ctx,
		`UPDATE sso_sessions SET last_access=now()-interval '20 minutes' WHERE id=$1`, sessionID); err != nil {
		t.Fatal(err)
	}
	if err := data.ValidateActiveSessionBinding(ctx, sessionID, userID, bootstrap.RealmID); !errors.Is(err, ErrNotFound) {
		t.Errorf("an idle session stayed usable: %v", err)
	}
}

// The authorization endpoint writes a row for every sign-in that needs a login
// screen, and reaching it takes only a client identifier and a redirect URI —
// both visible in any relying party's sign-in link. Anyone can therefore drive
// one insert per request, so an expired row must not linger: it is invisible
// to every reader from the moment it expires.
func TestIntegrationExpiredPendingAuthorizationsAreSweptPromptly(t *testing.T) {
	data := openIntegrationStore(t, integrationSealer(t))
	bootstrap := bootstrapIntegrationStore(t, data)
	ctx := context.Background()
	clientID := createIntegrationClient(t, data, bootstrap.RealmID)
	pending := func(expiresAt time.Time) string {
		t.Helper()
		token, err := data.CreateAuthorizationRequest(ctx, AuthorizationRequest{
			RealmID: bootstrap.RealmID, ClientID: clientID, RedirectURI: "https://client.example.test/callback",
			ResponseType: "code", Scope: []string{"openid"}, ExpiresAt: expiresAt})
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	stale := pending(time.Now().UTC().Add(-time.Minute))
	live := pending(time.Now().UTC().Add(5 * time.Minute))

	if _, err := data.AuthorizationRequestByToken(ctx, stale); !errors.Is(err, ErrNotFound) {
		t.Fatalf("an expired request was still readable: %v", err)
	}
	if err := data.PruneOperationalData(ctx); err != nil {
		t.Fatal(err)
	}
	var remaining int
	if err := data.Pool.QueryRow(ctx, `SELECT count(*) FROM authorization_requests`).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 1 {
		t.Errorf("rows left after the sweep = %d, want 1", remaining)
	}
	if _, err := data.AuthorizationRequestByToken(ctx, live); err != nil {
		t.Errorf("the sweep took a request that was still valid: %v", err)
	}
}

// "Is a sync running" had two answers. The guard that refuses a second run
// bounded the RUNNING status by how long ago it reported in; the listed
// provider carried the raw column. A run whose process died — a container
// stopped during a directory walk that may take half an hour — leaves that
// column saying RUNNING for ever, so the console disabled the sync button and
// polled every few seconds with no way back, while the server would have
// accepted a new run all along.
func TestIntegrationStaleSyncIsNotReportedAsRunning(t *testing.T) {
	data := openIntegrationStore(t, integrationSealer(t))
	bootstrap := bootstrapIntegrationStore(t, data)
	ctx := context.Background()
	provider, err := data.CreateLDAPFederation(ctx, bootstrap.RealmID, LDAPFederationInput{
		Name: "corp", Vendor: "OTHER", ConnectionURL: "ldaps://ldap.invalid:636",
		UsersDN: "ou=people,dc=example,dc=com", UsernameLDAPAttribute: "uid", RDNLDAPAttribute: "uid",
		UUIDLDAPAttribute: "entryUUID", UserObjectClasses: []string{"inetOrgPerson"},
		SearchScope: "SUBTREE", BatchSize: 100, EditMode: "READ_ONLY", MissingUserAction: "KEEP",
		ImportEnabled: true, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	claimed, err := data.ClaimLDAPSyncForTest(ctx, provider.ID)
	if err != nil || !claimed {
		t.Fatalf("claim = %v, err = %v", claimed, err)
	}
	listed := func() domain.LDAPFederation {
		t.Helper()
		items, listErr := data.ListLDAPFederations(ctx, bootstrap.RealmID)
		if listErr != nil || len(items) != 1 {
			t.Fatalf("list = %d items, err = %v", len(items), listErr)
		}
		return items[0]
	}
	running, err := data.LDAPSyncRunning(ctx, provider.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !running || !listed().SyncRunning {
		t.Fatalf("a claimed sync was not reported as running: guard=%v listed=%v", running, listed().SyncRunning)
	}

	// The process dies without ever reporting back.
	if _, err := data.Pool.Exec(ctx,
		`UPDATE user_federations SET updated_at=now()-interval '2 hours' WHERE id=$1`, provider.ID); err != nil {
		t.Fatal(err)
	}
	running, err = data.LDAPSyncRunning(ctx, provider.ID)
	if err != nil {
		t.Fatal(err)
	}
	stale := listed()
	if running {
		t.Error("the guard still considered an abandoned run to be running")
	}
	if stale.SyncRunning {
		t.Error("the listed provider still reported a run in progress, which locks the console out")
	}
	if stale.LastSyncStatus != "RUNNING" {
		t.Errorf("the raw status was expected to remain RUNNING, got %q", stale.LastSyncStatus)
	}
}

// A Realm that expires unused sessions refuses them long before expires_at
// arrives, and that is not something a reader of the listed columns can work
// out. The console derived "active" from revoked_at and expires_at alone, so
// it showed sessions as usable that the server had already stopped accepting —
// an administrator looking for who is signed in, and a user checking their own
// devices, both being told about sessions that no longer exist.
func TestIntegrationListedSessionReportsWhetherItStillWorks(t *testing.T) {
	data := openIntegrationStore(t, integrationSealer(t))
	bootstrap := bootstrapIntegrationStore(t, data)
	ctx := context.Background()
	if _, err := data.Pool.Exec(ctx,
		`UPDATE realms SET idle_timeout_seconds=600 WHERE id=$1`, bootstrap.RealmID); err != nil {
		t.Fatal(err)
	}
	session, err := data.CreateSession(ctx, bootstrap.RealmID, bootstrap.AdminUserID,
		8*time.Hour, "127.0.0.1", "listing-test", "password")
	if err != nil {
		t.Fatal(err)
	}
	listed := func() domain.Session {
		t.Helper()
		items, listErr := data.ListSessions(ctx, &bootstrap.RealmID, nil, 10)
		if listErr != nil {
			t.Fatal(listErr)
		}
		for _, item := range items {
			if item.ID == session.Session.ID {
				return item
			}
		}
		t.Fatal("the session was not listed")
		return domain.Session{}
	}
	if !listed().Active {
		t.Fatal("a fresh session was listed as unusable")
	}

	// Unused past the idle timeout: refused by the server, while expires_at is
	// still hours away.
	if _, err := data.Pool.Exec(ctx,
		`UPDATE sso_sessions SET last_access=now()-interval '30 minutes' WHERE id=$1`, session.Session.ID); err != nil {
		t.Fatal(err)
	}
	idle := listed()
	if idle.Active {
		t.Error("an idle-expired session was listed as active")
	}
	if !idle.ExpiresAt.After(time.Now()) {
		t.Fatal("the test needs expires_at to still be in the future to mean anything")
	}
	if idle.RevokedAt != nil {
		t.Error("the session was revoked, which is not the case being tested")
	}
}

// Whether a lockout is in force and whether an API key is still accepted both
// gate an action in the console: the unlock button only appears for a locked
// account, and rotate and revoke are offered only for a live key. Deciding
// either against the browser's clock meant a machine running fast hid the only
// way to release an account nobody could sign in to, and offered no way to
// withdraw a key that still worked.
func TestIntegrationLockAndKeyStateComeFromTheServer(t *testing.T) {
	data := openIntegrationStore(t, integrationSealer(t))
	bootstrap := bootstrapIntegrationStore(t, data)
	ctx := context.Background()
	user, err := data.CreateUser(ctx, bootstrap.RealmID, CreateUserInput{
		Username: "locked-probe", Password: "locked-probe-password-1234", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if fetched, err := data.UserByID(ctx, user.ID); err != nil || fetched.Locked {
		t.Fatalf("a new account reported locked=%v err=%v", fetched.Locked, err)
	}
	if _, err := data.Pool.Exec(ctx,
		`UPDATE users SET locked_until=now()+interval '10 minutes' WHERE id=$1`, user.ID); err != nil {
		t.Fatal(err)
	}
	locked, err := data.UserByID(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !locked.Locked {
		t.Error("a locked account did not report it, which hides the unlock action")
	}
	// A lockout that has run its course is not in force, even though the
	// timestamp is still on the row.
	if _, err := data.Pool.Exec(ctx,
		`UPDATE users SET locked_until=now()-interval '1 minute' WHERE id=$1`, user.ID); err != nil {
		t.Fatal(err)
	}
	if released, err := data.UserByID(ctx, user.ID); err != nil || released.Locked {
		t.Errorf("an elapsed lockout still reported as locked: %v", err)
	}

	created, err := data.CreatePersonalAPIKey(ctx, user.ID, "probe", []string{"api:read"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !created.Key.Active {
		t.Error("a key was reported inactive at the moment it was issued")
	}
	keys, err := data.ListPersonalAPIKeys(ctx, user.ID)
	if err != nil || len(keys) != 1 {
		t.Fatalf("listed %d keys, err=%v", len(keys), err)
	}
	if !keys[0].Active {
		t.Error("a live key was listed as inactive, which hides rotate and revoke")
	}
	if err := data.RevokePersonalAPIKey(ctx, user.ID, created.Key.ID); err != nil {
		t.Fatal(err)
	}
	keys, err = data.ListPersonalAPIKeys(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if keys[0].Active {
		t.Error("a revoked key was still listed as active")
	}
}

// The DISABLE policy deactivates the accounts a sync did not see and ends
// their sessions. It is the most consequential thing this service does on its
// own, and until a real directory could be pointed at it there was no way to
// run it end to end — the guard against an empty read was tested by calling
// the sweep directly, not by synchronising anything.
//
// Set RESSO_TEST_LDAP_URL alongside the database DSN to run this.
func TestIntegrationFederationSyncImportsThenDisablesOnlyWhatLeft(t *testing.T) {
	directory := strings.TrimSpace(os.Getenv("RESSO_TEST_LDAP_URL"))
	if directory == "" {
		t.Skip("set RESSO_TEST_LDAP_URL to run federation synchronisation tests")
	}
	data := openIntegrationStore(t, integrationSealer(t))
	bootstrap := bootstrapIntegrationStore(t, data)
	ctx := context.Background()
	branch := "ou=sync-leave,dc=example,dc=test"
	createDirectoryBranch(t, branch, "stays", "leaves")
	credential := "adminpassword"
	provider, err := data.CreateLDAPFederation(ctx, bootstrap.RealmID, LDAPFederationInput{
		Name: "corp", Vendor: "OTHER", ConnectionURL: directory,
		BindDN: "cn=admin,dc=example,dc=test", BindCredential: &credential,
		UsersDN: branch, UsernameLDAPAttribute: "uid", RDNLDAPAttribute: "uid",
		UUIDLDAPAttribute: "entryUUID", UserObjectClasses: []string{"inetOrgPerson"},
		SearchScope: "SUBTREE", BatchSize: 100, EditMode: "READ_ONLY", MissingUserAction: "DISABLE",
		EmailLDAPAttribute: "mail", DisplayNameLDAPAttribute: "cn",
		ImportEnabled: true, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	summary, err := data.SyncLDAPFederation(ctx, provider.ID)
	if err != nil {
		t.Fatalf("synchronising a reachable directory failed: %v (%+v)", err, summary)
	}
	if summary.Read < 2 || summary.Failed != 0 {
		t.Fatalf("first sync summary = %+v", summary)
	}
	enabled := func(username string) (bool, bool) {
		t.Helper()
		var isEnabled bool
		err := data.Pool.QueryRow(ctx,
			`SELECT enabled FROM users WHERE realm_id=$1 AND username=$2 AND federation_id=$3`,
			bootstrap.RealmID, username, provider.ID).Scan(&isEnabled)
		if errors.Is(err, pgx.ErrNoRows) {
			return false, false
		}
		if err != nil {
			t.Fatal(err)
		}
		return isEnabled, true
	}
	for _, username := range []string{"stays", "leaves"} {
		if isEnabled, found := enabled(username); !found || !isEnabled {
			t.Fatalf("%s was not imported as an enabled account (found=%v)", username, found)
		}
	}
	// Attributes come across, not just the username.
	var email string
	if err := data.Pool.QueryRow(ctx,
		`SELECT email FROM users WHERE realm_id=$1 AND username='stays'`, bootstrap.RealmID).Scan(&email); err != nil {
		t.Fatal(err)
	}
	if email != "stays@example.test" {
		t.Errorf("imported email = %q", email)
	}

	// The console and the user federation page both describe this policy as
	// "비활성화 및 세션 종료", so the departing account has something to end.
	rp, err := data.CreateClient(ctx, bootstrap.RealmID, CreateClientInput{
		ClientID: "rp-of-the-departed", Name: "RP", Type: "confidential",
		RedirectURIs:         []string{"https://rp.example.com/callback"},
		BackchannelLogoutURI: "https://rp.example.com/backchannel-logout",
	})
	if err != nil {
		t.Fatal(err)
	}
	var leavingID, stayingID uuid.UUID
	if err := data.Pool.QueryRow(ctx, `SELECT id FROM users WHERE realm_id=$1 AND username='leaves'`,
		bootstrap.RealmID).Scan(&leavingID); err != nil {
		t.Fatal(err)
	}
	if err := data.Pool.QueryRow(ctx, `SELECT id FROM users WHERE realm_id=$1 AND username='stays'`,
		bootstrap.RealmID).Scan(&stayingID); err != nil {
		t.Fatal(err)
	}
	for _, id := range []uuid.UUID{leavingID, stayingID} {
		session, sessionErr := data.CreateSession(ctx, bootstrap.RealmID, id, time.Hour,
			"127.0.0.1", "integration-test", "password")
		if sessionErr != nil {
			t.Fatal(sessionErr)
		}
		userID, sessionID := id, session.Session.ID
		if _, err := data.CreateRefreshToken(ctx, RefreshToken{RealmID: bootstrap.RealmID,
			ClientID: rp.Client.ID, UserID: &userID, SessionID: &sessionID,
			Scope: []string{"openid"}, ExpiresAt: time.Now().UTC().Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	var told []RevokedSession
	data.OnSessionRevoked = func(revoked RevokedSession) { told = append(told, revoked) }

	// Somebody leaves the directory. Only that account may be deactivated.
	if err := removeDirectoryEntry(t, "uid=leaves,"+branch); err != nil {
		t.Fatal(err)
	}
	summary, err = data.SyncLDAPFederation(ctx, provider.ID)
	if err != nil {
		t.Fatalf("second sync failed: %v (%+v)", err, summary)
	}
	if summary.Disabled != 1 {
		t.Errorf("accounts disabled = %d, want 1", summary.Disabled)
	}
	if isEnabled, _ := enabled("leaves"); isEnabled {
		t.Error("an account the directory no longer lists stayed enabled")
	}
	if isEnabled, _ := enabled("stays"); !isEnabled {
		t.Error("an account still in the directory was deactivated")
	}
	// The sweep revoked the session rows and stopped there: the refresh tokens
	// went on working and no relying party was told, so the departed employee
	// stayed signed in at every application that keeps its own session.
	live := func(id uuid.UUID) (int, int) {
		t.Helper()
		var sessions, refresh int
		if err := data.Pool.QueryRow(ctx,
			"SELECT count(*) FROM sso_sessions WHERE user_id=$1 AND revoked_at IS NULL", id).Scan(&sessions); err != nil {
			t.Fatal(err)
		}
		if err := data.Pool.QueryRow(ctx,
			"SELECT count(*) FROM refresh_tokens WHERE user_id=$1 AND revoked_at IS NULL", id).Scan(&refresh); err != nil {
			t.Fatal(err)
		}
		return sessions, refresh
	}
	if sessions, refresh := live(leavingID); sessions != 0 || refresh != 0 {
		t.Errorf("the departed account kept %d sessions and %d refresh tokens", sessions, refresh)
	}
	if sessions, refresh := live(stayingID); sessions != 1 || refresh != 1 {
		t.Errorf("an account still in the directory was signed out: %d sessions, %d refresh tokens", sessions, refresh)
	}
	if len(told) != 1 || told[0].UserID != leavingID {
		t.Errorf("relying parties were told about %+v, want only the departed account", told)
	}
}

// A directory that answers with nothing looks the same whether everybody left
// or the search was pointed somewhere wrong, and under the DISABLE policy the
// second reading would deactivate every federated account in the Realm. The
// guard against that was previously exercised by calling the sweep directly;
// this runs a whole synchronisation against a real, empty branch.
func TestIntegrationFederationSyncRefusesToActOnAnEmptyDirectory(t *testing.T) {
	directory := strings.TrimSpace(os.Getenv("RESSO_TEST_LDAP_URL"))
	if directory == "" {
		t.Skip("set RESSO_TEST_LDAP_URL to run federation synchronisation tests")
	}
	data := openIntegrationStore(t, integrationSealer(t))
	bootstrap := bootstrapIntegrationStore(t, data)
	ctx := context.Background()
	credential := "adminpassword"
	populated := "ou=sync-empty,dc=example,dc=test"
	createDirectoryBranch(t, populated, "present-one", "present-two")
	provider, err := data.CreateLDAPFederation(ctx, bootstrap.RealmID, LDAPFederationInput{
		Name: "corp", Vendor: "OTHER", ConnectionURL: directory,
		BindDN: "cn=admin,dc=example,dc=test", BindCredential: &credential,
		UsersDN: populated, UsernameLDAPAttribute: "uid", RDNLDAPAttribute: "uid",
		UUIDLDAPAttribute: "entryUUID", UserObjectClasses: []string{"inetOrgPerson"},
		SearchScope: "SUBTREE", BatchSize: 100, EditMode: "READ_ONLY", MissingUserAction: "DISABLE",
		EmailLDAPAttribute: "mail", DisplayNameLDAPAttribute: "cn",
		ImportEnabled: true, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := data.SyncLDAPFederation(ctx, provider.ID); err != nil {
		t.Fatal(err)
	}
	var imported int
	if err := data.Pool.QueryRow(ctx,
		`SELECT count(*) FROM users WHERE federation_id=$1 AND enabled=true`, provider.ID).Scan(&imported); err != nil {
		t.Fatal(err)
	}
	if imported < 2 {
		t.Fatalf("imported %d accounts, expected the directory's users", imported)
	}

	// The search now points at a branch that exists and holds nobody, which is
	// what a mistyped base or a lost read permission looks like.
	emptyBranch := "ou=nobody,dc=example,dc=test"
	createEmptyDirectoryBranch(t, emptyBranch)
	t.Cleanup(func() { _ = removeDirectoryEntry(t, emptyBranch) })
	if _, err := data.Pool.Exec(ctx,
		`UPDATE user_federations SET users_dn=$2 WHERE id=$1`, provider.ID, emptyBranch); err != nil {
		t.Fatal(err)
	}

	summary, err := data.SyncLDAPFederation(ctx, provider.ID)
	if !errors.Is(err, ErrSyncReadNothing) {
		t.Fatalf("an empty directory returned %v, want ErrSyncReadNothing", err)
	}
	if summary.Disabled != 0 {
		t.Errorf("an empty read disabled %d accounts", summary.Disabled)
	}
	var stillEnabled int
	if err := data.Pool.QueryRow(ctx,
		`SELECT count(*) FROM users WHERE federation_id=$1 AND enabled=true`, provider.ID).Scan(&stillEnabled); err != nil {
		t.Fatal(err)
	}
	if stillEnabled != imported {
		t.Errorf("enabled accounts went from %d to %d on an empty read", imported, stillEnabled)
	}
	// The operator has to be able to see why, so the run is recorded as failed.
	var status, message string
	if err := data.Pool.QueryRow(ctx,
		`SELECT last_sync_status,last_sync_error FROM user_federations WHERE id=$1`, provider.ID).Scan(&status, &message); err != nil {
		t.Fatal(err)
	}
	if status != "FAILURE" || message == "" {
		t.Errorf("the run was recorded as %q with message %q", status, message)
	}
}

func createEmptyDirectoryBranch(t *testing.T, dn string) {
	t.Helper()
	connection := directoryConnection(t)
	defer func() { _ = connection.Close() }()
	request := ldap.NewAddRequest(dn, nil)
	request.Attribute("objectClass", []string{"organizationalUnit"})
	request.Attribute("ou", []string{"nobody"})
	if err := connection.Add(request); err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultEntryAlreadyExists) {
		t.Fatal(err)
	}
}

// Each synchronisation test owns the directory entries it works with.
//
// The federation package's tests use the shared accounts at ou=people, and
// these tests delete an account to see the DISABLE policy act on it. Go runs
// package test binaries in parallel, so sharing an entry that one package
// removes and another reads is a race waiting for a slower machine — it did
// not reproduce here, which is exactly the kind of assurance not worth having.
func createDirectoryBranch(t *testing.T, branch string, usernames ...string) {
	t.Helper()
	connection := directoryConnection(t)
	defer func() { _ = connection.Close() }()
	unit := ldap.NewAddRequest(branch, nil)
	unit.Attribute("objectClass", []string{"organizationalUnit"})
	unit.Attribute("ou", []string{strings.SplitN(strings.TrimPrefix(branch, "ou="), ",", 2)[0]})
	if err := connection.Add(unit); err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultEntryAlreadyExists) {
		t.Fatal(err)
	}
	for _, username := range usernames {
		entry := ldap.NewAddRequest("uid="+username+","+branch, nil)
		entry.Attribute("objectClass", []string{"inetOrgPerson"})
		entry.Attribute("uid", []string{username})
		entry.Attribute("cn", []string{username + " Person"})
		entry.Attribute("sn", []string{"Person"})
		entry.Attribute("mail", []string{username + "@example.test"})
		entry.Attribute("userPassword", []string{username + "-pass-1234"})
		if err := connection.Add(entry); err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultEntryAlreadyExists) {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { removeDirectoryBranch(t, branch) })
}

func removeDirectoryBranch(t *testing.T, branch string) {
	t.Helper()
	connection := directoryConnection(t)
	defer func() { _ = connection.Close() }()
	found, err := connection.Search(ldap.NewSearchRequest(branch, ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases, 0, 10, false, "(objectClass=*)", []string{"1.1"}, nil))
	if err != nil {
		return
	}
	// Children first: a directory refuses to delete a branch that still holds
	// entries.
	for index := len(found.Entries) - 1; index >= 0; index-- {
		_ = connection.Del(ldap.NewDelRequest(found.Entries[index].DN, nil))
	}
}

// The directory is modified through the same library the service uses, so the
// test needs no command-line tools on whatever machine it runs on.
func directoryConnection(t *testing.T) *ldap.Conn {
	t.Helper()
	connection, err := ldap.DialURL(strings.TrimSpace(os.Getenv("RESSO_TEST_LDAP_URL")))
	if err != nil {
		t.Fatal(err)
	}
	if err := connection.Bind("cn=admin,dc=example,dc=test", "adminpassword"); err != nil {
		_ = connection.Close()
		t.Fatal(err)
	}
	return connection
}

func removeDirectoryEntry(t *testing.T, dn string) error {
	t.Helper()
	connection := directoryConnection(t)
	defer func() { _ = connection.Close() }()
	return connection.Del(ldap.NewDelRequest(dn, nil))
}

// What an administrator may do to a federated account depends on the edit
// mode, and getting that wrong writes into a directory the service does not
// own — or refuses a change the operator was told they could make. None of it
// had been run: the READ_ONLY refusal, the WRITABLE write-through, or signing
// in as a directory account at all.
func TestIntegrationFederatedAccountsFollowTheEditMode(t *testing.T) {
	directory := strings.TrimSpace(os.Getenv("RESSO_TEST_LDAP_URL"))
	if directory == "" {
		t.Skip("set RESSO_TEST_LDAP_URL to run federation synchronisation tests")
	}
	data := openIntegrationStore(t, integrationSealer(t))
	bootstrap := bootstrapIntegrationStore(t, data)
	ctx := context.Background()
	branch := "ou=sync-edit,dc=example,dc=test"
	createDirectoryBranch(t, branch, "editable")
	credential := "adminpassword"
	provider, err := data.CreateLDAPFederation(ctx, bootstrap.RealmID, LDAPFederationInput{
		Name: "corp", Vendor: "OTHER", ConnectionURL: directory,
		BindDN: "cn=admin,dc=example,dc=test", BindCredential: &credential,
		UsersDN: branch, UsernameLDAPAttribute: "uid", RDNLDAPAttribute: "uid",
		UUIDLDAPAttribute: "entryUUID", UserObjectClasses: []string{"inetOrgPerson"},
		SearchScope: "SUBTREE", BatchSize: 100, EditMode: "READ_ONLY", MissingUserAction: "KEEP",
		EmailLDAPAttribute: "mail", DisplayNameLDAPAttribute: "cn",
		ImportEnabled: true, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := data.SyncLDAPFederation(ctx, provider.ID); err != nil {
		t.Fatal(err)
	}
	realm, err := data.RealmByID(ctx, bootstrap.RealmID)
	if err != nil {
		t.Fatal(err)
	}
	imported, err := data.userByRealmUsername(ctx, bootstrap.RealmID, "editable")
	if err != nil {
		t.Fatal(err)
	}
	if imported.FederationID == nil || imported.ExternalDN == nil {
		t.Fatalf("the imported account was not linked to the directory: %+v", imported)
	}

	// Authenticate is the entry point the sign-in handler uses; it routes a
	// linked account to the directory instead of to a local hash.
	result, err := data.Authenticate(ctx, realm, "editable", "editable-pass-1234")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Success {
		t.Fatalf("a directory account could not sign in: %+v", result)
	}
	if wrong, err := data.Authenticate(ctx, realm, "editable", "not-the-password"); err != nil || wrong.Success {
		t.Errorf("a wrong directory password was accepted: %+v err=%v", wrong, err)
	}

	// READ_ONLY means the directory is the record: an edit here is refused
	// rather than quietly diverging from it.
	if _, err := data.UpdateUser(ctx, imported.ID, UpdateUserInput{
		Enabled: true, Email: "elsewhere@example.test", DisplayName: "Elsewhere"}); !errors.Is(err, ErrFederationReadOnly) {
		t.Errorf("editing a READ_ONLY account returned %v, want ErrFederationReadOnly", err)
	}
	if err := data.ChangePassword(ctx, imported.ID, "editable-pass-1234", "another-pass-1234", false); !errors.Is(err, ErrFederationPasswordExternal) {
		t.Errorf("changing a READ_ONLY password returned %v, want ErrFederationPasswordExternal", err)
	}

	// WRITABLE means the change is carried into the directory, which is the
	// only way to tell it apart from a local edit that happens to stick.
	if _, err := data.Pool.Exec(ctx,
		`UPDATE user_federations SET edit_mode='WRITABLE' WHERE id=$1`, provider.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := data.UpdateUser(ctx, imported.ID, UpdateUserInput{
		Enabled: true, Email: "moved@example.test", DisplayName: "Moved Person"}); err != nil {
		t.Fatalf("editing a WRITABLE account failed: %v", err)
	}
	connection := directoryConnection(t)
	defer func() { _ = connection.Close() }()
	found, err := connection.Search(ldap.NewSearchRequest(*imported.ExternalDN, ldap.ScopeBaseObject,
		ldap.NeverDerefAliases, 1, 5, false, "(objectClass=*)", []string{"mail", "cn"}, nil))
	if err != nil || len(found.Entries) != 1 {
		t.Fatalf("reading the entry back failed: %v", err)
	}
	if got := found.Entries[0].GetAttributeValue("mail"); got != "moved@example.test" {
		t.Errorf("the directory still holds mail=%q", got)
	}
	if got := found.Entries[0].GetAttributeValue("cn"); got != "Moved Person" {
		t.Errorf("the directory still holds cn=%q", got)
	}

	// And a password change reaches the directory too, which is what the
	// person will actually sign in with next.
	if err := data.ChangePassword(ctx, imported.ID, "editable-pass-1234", "changed-pass-5678", false); err != nil {
		t.Fatalf("changing a WRITABLE password failed: %v", err)
	}
	if after, err := data.Authenticate(ctx, realm, "editable", "changed-pass-5678"); err != nil || !after.Success {
		t.Errorf("the new directory password was refused: %+v err=%v", after, err)
	}
}

// A directory group deciding a Realm role is permissions coming from a system
// this service does not control, and the half that matters is the removal:
// somebody leaving a group has to lose the role at the next synchronisation.
// Retaining it is how a person keeps access after being moved off a team.
func TestIntegrationDirectoryGroupsGrantAndWithdrawRoles(t *testing.T) {
	directory := strings.TrimSpace(os.Getenv("RESSO_TEST_LDAP_URL"))
	if directory == "" {
		t.Skip("set RESSO_TEST_LDAP_URL to run federation synchronisation tests")
	}
	data := openIntegrationStore(t, integrationSealer(t))
	bootstrap := bootstrapIntegrationStore(t, data)
	ctx := context.Background()
	branch := "ou=sync-groups,dc=example,dc=test"
	createDirectoryBranch(t, branch, "member")
	memberDN := "uid=member," + branch
	groupBranch := "ou=sync-teams,dc=example,dc=test"
	groupDN := "cn=payments," + groupBranch
	createDirectoryGroup(t, groupBranch, groupDN, memberDN)

	role, err := data.CreateRole(ctx, bootstrap.RealmID, "payments-operator", "")
	if err != nil {
		t.Fatal(err)
	}
	credential := "adminpassword"
	provider, err := data.CreateLDAPFederation(ctx, bootstrap.RealmID, LDAPFederationInput{
		Name: "corp", Vendor: "OTHER", ConnectionURL: directory,
		BindDN: "cn=admin,dc=example,dc=test", BindCredential: &credential,
		UsersDN: branch, UsernameLDAPAttribute: "uid", RDNLDAPAttribute: "uid",
		UUIDLDAPAttribute: "entryUUID", UserObjectClasses: []string{"inetOrgPerson"},
		SearchScope: "SUBTREE", BatchSize: 100, EditMode: "READ_ONLY", MissingUserAction: "KEEP",
		EmailLDAPAttribute: "mail", DisplayNameLDAPAttribute: "cn", MemberOfLDAPAttribute: "memberOf",
		GroupRoleMappings: map[string]string{"payments": "payments-operator"},
		ImportEnabled:     true, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := data.SyncLDAPFederation(ctx, provider.ID); err != nil {
		t.Fatal(err)
	}
	holdsRole := func() bool {
		t.Helper()
		var held bool
		if err := data.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM user_roles ur
			JOIN users u ON u.id=ur.user_id
			WHERE u.realm_id=$1 AND u.username='member' AND ur.role_id=$2)`,
			bootstrap.RealmID, role.ID).Scan(&held); err != nil {
			t.Fatal(err)
		}
		return held
	}
	if !holdsRole() {
		t.Fatal("membership of the mapped group did not grant the role")
	}

	// Off the team. The role has to go with the membership.
	removeDirectoryGroupMember(t, groupDN, memberDN)
	if _, err := data.SyncLDAPFederation(ctx, provider.ID); err != nil {
		t.Fatal(err)
	}
	if holdsRole() {
		t.Error("leaving the group left the role in place, so access outlived the membership")
	}
}

func createDirectoryGroup(t *testing.T, branch, groupDN, memberDN string) {
	t.Helper()
	connection := directoryConnection(t)
	defer func() { _ = connection.Close() }()
	unit := ldap.NewAddRequest(branch, nil)
	unit.Attribute("objectClass", []string{"organizationalUnit"})
	unit.Attribute("ou", []string{strings.SplitN(strings.TrimPrefix(branch, "ou="), ",", 2)[0]})
	if err := connection.Add(unit); err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultEntryAlreadyExists) {
		t.Fatal(err)
	}
	group := ldap.NewAddRequest(groupDN, nil)
	group.Attribute("objectClass", []string{"groupOfNames"})
	group.Attribute("cn", []string{strings.SplitN(strings.TrimPrefix(groupDN, "cn="), ",", 2)[0]})
	group.Attribute("member", []string{memberDN})
	if err := connection.Add(group); err != nil {
		if !ldap.IsErrorWithCode(err, ldap.LDAPResultEntryAlreadyExists) {
			t.Fatal(err)
		}
		// Tolerating the group already being there is not the same as
		// tolerating whatever it happens to contain. A group left behind by an
		// earlier run holds that run's member, so the member this test just
		// created never gets memberOf and the test measures somebody else's
		// setup — which fails as "membership did not grant the role", pointing
		// at the code rather than at the directory.
		modify := ldap.NewModifyRequest(groupDN, nil)
		modify.Replace("member", []string{memberDN})
		if err := connection.Modify(modify); err != nil {
			t.Fatalf("setting the membership of an existing group failed: %v", err)
		}
	}
	t.Cleanup(func() { removeDirectoryBranch(t, branch) })
}

// removeDirectoryGroupMember empties the group rather than deleting the entry,
// because groupOfNames requires at least one member and the directory would
// refuse to remove the last one.
func removeDirectoryGroupMember(t *testing.T, groupDN, memberDN string) {
	t.Helper()
	connection := directoryConnection(t)
	defer func() { _ = connection.Close() }()
	if err := connection.Del(ldap.NewDelRequest(groupDN, nil)); err != nil {
		t.Fatalf("removing the group failed: %v", err)
	}
	_ = memberDN
}

// A directory that cannot be reached must not be mistaken for a wrong
// password. Counting those attempts would mean an outage locks people out of
// their own accounts, and the lockout would outlast the outage — everybody
// affected would still be barred once the directory came back.
func TestIntegrationDirectoryOutageDoesNotCountAsAFailedPassword(t *testing.T) {
	directory := strings.TrimSpace(os.Getenv("RESSO_TEST_LDAP_URL"))
	if directory == "" {
		t.Skip("set RESSO_TEST_LDAP_URL to run federation synchronisation tests")
	}
	data := openIntegrationStore(t, integrationSealer(t))
	bootstrap := bootstrapIntegrationStore(t, data)
	ctx := context.Background()
	if _, err := data.Pool.Exec(ctx,
		`UPDATE realms SET max_login_attempts=3, lockout_seconds=600 WHERE id=$1`, bootstrap.RealmID); err != nil {
		t.Fatal(err)
	}
	realm, err := data.RealmByID(ctx, bootstrap.RealmID)
	if err != nil {
		t.Fatal(err)
	}
	branch := "ou=sync-outage,dc=example,dc=test"
	createDirectoryBranch(t, branch, "onleave")
	credential := "adminpassword"
	provider, err := data.CreateLDAPFederation(ctx, bootstrap.RealmID, LDAPFederationInput{
		Name: "corp", Vendor: "OTHER", ConnectionURL: directory,
		BindDN: "cn=admin,dc=example,dc=test", BindCredential: &credential,
		UsersDN: branch, UsernameLDAPAttribute: "uid", RDNLDAPAttribute: "uid",
		UUIDLDAPAttribute: "entryUUID", UserObjectClasses: []string{"inetOrgPerson"},
		SearchScope: "SUBTREE", BatchSize: 100, EditMode: "READ_ONLY", MissingUserAction: "KEEP",
		EmailLDAPAttribute: "mail", DisplayNameLDAPAttribute: "cn",
		ImportEnabled: true, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := data.SyncLDAPFederation(ctx, provider.ID); err != nil {
		t.Fatal(err)
	}
	if result, err := data.Authenticate(ctx, realm, "onleave", "onleave-pass-1234"); err != nil || !result.Success {
		t.Fatalf("the account could not sign in before the outage: %+v err=%v", result, err)
	}

	// The directory goes away.
	if _, err := data.Pool.Exec(ctx,
		`UPDATE user_federations SET connection_url='ldap://127.0.0.1:1' WHERE id=$1`, provider.ID); err != nil {
		t.Fatal(err)
	}
	for range 5 {
		result, err := data.Authenticate(ctx, realm, "onleave", "onleave-pass-1234")
		if err == nil {
			t.Fatalf("an unreachable directory was answered with %+v rather than an error", result)
		}
	}
	var attempts int
	var locked *time.Time
	if err := data.Pool.QueryRow(ctx,
		`SELECT failed_attempts,locked_until FROM users WHERE realm_id=$1 AND username='onleave'`,
		bootstrap.RealmID).Scan(&attempts, &locked); err != nil {
		t.Fatal(err)
	}
	if attempts != 0 {
		t.Errorf("an outage counted %d failed attempts", attempts)
	}
	if locked != nil {
		t.Error("an outage locked the account, which would outlast the outage itself")
	}

	// And once the directory is back, the same password works.
	if _, err := data.Pool.Exec(ctx,
		`UPDATE user_federations SET connection_url=$2 WHERE id=$1`, provider.ID, directory); err != nil {
		t.Fatal(err)
	}
	if result, err := data.Authenticate(ctx, realm, "onleave", "onleave-pass-1234"); err != nil || !result.Success {
		t.Errorf("the account could not sign in after the outage: %+v err=%v", result, err)
	}
}

// Disabling an account is the emergency stop, and until now it stopped
// nothing. The cookie stopped resolving because every session lookup filters
// on users.enabled, which reads as signed out — but the session row stayed
// live, the refresh tokens stayed live, and no relying party was told. So the
// person remained signed in at every application that had its own session, and
// re-enabling the account later — after an investigation, at the end of a
// suspension — handed back every session that had been open at the moment it
// was disabled, including whichever one was the reason for disabling it.
func TestIntegrationDisablingAnAccountSignsItOutForGood(t *testing.T) {
	data := openIntegrationStore(t, integrationSealer(t))
	bootstrap := bootstrapIntegrationStore(t, data)
	ctx := context.Background()
	var told []RevokedSession
	data.OnSessionRevoked = func(revoked RevokedSession) { told = append(told, revoked) }

	client, err := data.CreateClient(ctx, bootstrap.RealmID, CreateClientInput{
		ClientID: "rp-of-the-disabled", Name: "RP", Type: "confidential",
		RedirectURIs:         []string{"https://rp.example.com/callback"},
		BackchannelLogoutURI: "https://rp.example.com/backchannel-logout",
	})
	if err != nil {
		t.Fatal(err)
	}
	user, err := data.CreateUser(ctx, bootstrap.RealmID, CreateUserInput{
		Username: "suspended", Password: "suspended-password-1234", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	session, err := data.CreateSession(ctx, bootstrap.RealmID, user.ID, time.Hour,
		"127.0.0.1", "integration-test", "password")
	if err != nil {
		t.Fatal(err)
	}
	userID, sessionID := user.ID, session.Session.ID
	if _, err := data.CreateRefreshToken(ctx, RefreshToken{RealmID: bootstrap.RealmID,
		ClientID: client.Client.ID, UserID: &userID, SessionID: &sessionID,
		Scope: []string{"openid"}, ExpiresAt: time.Now().UTC().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, err := data.SessionByToken(ctx, session.Token); err != nil {
		t.Fatalf("the session did not work to begin with: %v", err)
	}

	if _, err := data.UpdateUser(ctx, userID, UpdateUserInput{
		DisplayName: user.DisplayName, Email: user.Email, Enabled: false}); err != nil {
		t.Fatal(err)
	}

	var liveSessions, liveRefresh int
	if err := data.Pool.QueryRow(ctx,
		"SELECT count(*) FROM sso_sessions WHERE user_id=$1 AND revoked_at IS NULL", userID).Scan(&liveSessions); err != nil {
		t.Fatal(err)
	}
	if liveSessions != 0 {
		t.Errorf("sessions left unrevoked after disabling = %d", liveSessions)
	}
	if err := data.Pool.QueryRow(ctx,
		"SELECT count(*) FROM refresh_tokens WHERE user_id=$1 AND revoked_at IS NULL", userID).Scan(&liveRefresh); err != nil {
		t.Fatal(err)
	}
	if liveRefresh != 0 {
		t.Errorf("refresh tokens left usable after disabling = %d", liveRefresh)
	}
	if len(told) != 1 || told[0].SessionID != sessionID || told[0].UserID != userID {
		t.Errorf("relying parties were told about %+v, want the one revoked session", told)
	}

	// The part an administrator cannot see: re-enabling must not undo it.
	if _, err := data.UpdateUser(ctx, userID, UpdateUserInput{
		DisplayName: user.DisplayName, Email: user.Email, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := data.SessionByToken(ctx, session.Token); !errors.Is(err, ErrNotFound) {
		t.Errorf("re-enabling the account brought its old session back: err=%v", err)
	}

	// Disabling an account that is already disabled has nothing to end, and
	// must not resend a logout for a session that ended long ago.
	told = nil
	if _, err := data.UpdateUser(ctx, userID, UpdateUserInput{
		DisplayName: user.DisplayName, Email: user.Email, Enabled: false}); err != nil {
		t.Fatal(err)
	}
	if _, err := data.UpdateUser(ctx, userID, UpdateUserInput{
		DisplayName: user.DisplayName, Email: user.Email, Enabled: false}); err != nil {
		t.Fatal(err)
	}
	if len(told) != 0 {
		t.Errorf("disabling twice notified relying parties again: %+v", told)
	}
}

// The retention sweep used to return at the first failing statement, so one
// statement decided the fate of every statement after it. That repeats every
// hour at the same position, so the tables behind the failure are never
// collected at all — they grow, and growing makes the failure more likely
// still. The realistic trigger is the two-minute deadline the caller sets
// running out on the largest table, which is a year of audit events, and that
// one used to sit third in a list of nine.
func TestIntegrationRetentionSweepDoesNotStopAtOneFailure(t *testing.T) {
	data := openIntegrationStore(t, integrationSealer(t))
	bootstrap := bootstrapIntegrationStore(t, data)
	ctx := context.Background()
	client, err := data.CreateClient(ctx, bootstrap.RealmID, CreateClientInput{
		ClientID: "retention-probe", Name: "Retention Probe", Type: "public",
		RedirectURIs: []string{"https://probe.example.test/cb"}})
	if err != nil {
		t.Fatal(err)
	}
	// One expired row for three of the statements that follow the audit sweep.
	// The first fills from unauthenticated traffic, which is what makes it the
	// worst one to leave uncollected.
	seed := func(marker string) {
		t.Helper()
		if _, err := data.Pool.Exec(ctx, `INSERT INTO authorization_requests(id,token_hash,realm_id,client_id,
			redirect_uri,response_type,scope,state,nonce,code_challenge,code_challenge_method,expires_at)
			VALUES($1,$2,$3,$4,'https://probe.example.test/cb','code',ARRAY['openid'],'','','','S256',
			now()-interval '1 hour')`, uuid.New(), data.Sealer.Digest(marker),
			bootstrap.RealmID, client.Client.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := data.Pool.Exec(ctx, `INSERT INTO revoked_access_tokens(jti,expires_at)
			VALUES($1,now()-interval '1 hour')`, uuid.New()); err != nil {
			t.Fatal(err)
		}
		if _, err := data.Pool.Exec(ctx, `INSERT INTO login_rate_limits(bucket_hash,attempts,
			window_started_at,updated_at) VALUES($1,1,now()-interval '30 days',now()-interval '30 days')`,
			data.Sealer.Digest(marker)); err != nil {
			t.Fatal(err)
		}
	}
	uncollected := func() int {
		t.Helper()
		var total int
		if err := data.Pool.QueryRow(ctx, `SELECT
			(SELECT count(*) FROM authorization_requests)
			+ (SELECT count(*) FROM revoked_access_tokens)
			+ (SELECT count(*) FROM login_rate_limits)`).Scan(&total); err != nil {
			t.Fatal(err)
		}
		return total
	}

	seed("healthy")
	if err := data.PruneOperationalData(ctx); err != nil {
		t.Fatalf("a healthy sweep reported %v", err)
	}
	if left := uncollected(); left != 0 {
		t.Fatalf("a healthy sweep left %d expired rows", left)
	}

	// Break one statement in the middle of the list. Renaming the table is a
	// stand-in for whatever makes a statement fail on a real installation —
	// a lock, a statement timeout, a deadline — and the point is only that
	// the ones after it still run.
	seed("broken")
	if _, err := data.Pool.Exec(ctx, "ALTER TABLE audit_events RENAME TO audit_events_moved"); err != nil {
		t.Fatal(err)
	}
	restore := func() {
		if _, err := data.Pool.Exec(context.Background(),
			"ALTER TABLE audit_events_moved RENAME TO audit_events"); err != nil {
			t.Error(err)
		}
	}
	sweepErr := data.PruneOperationalData(ctx)
	restore()
	if sweepErr == nil {
		t.Fatal("a sweep with a broken statement reported success")
	}
	// An operator reading one line has to be able to tell which statement it
	// was; "cleanup failed" and nothing else was the whole report before.
	if !strings.Contains(sweepErr.Error(), "audit events past retention") {
		t.Errorf("the failure does not name the statement: %v", sweepErr)
	}
	if left := uncollected(); left != 0 {
		t.Errorf("one broken statement left %d expired rows uncollected", left)
	}

	// A spent deadline is the one failure that does carry to the rest, and
	// saying so beats repeating the same error for every statement left.
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	deadlineErr := data.PruneOperationalData(cancelled)
	if deadlineErr == nil || !strings.Contains(deadlineErr.Error(), "were not attempted") {
		t.Errorf("a spent deadline reported %v, want the statements left undone", deadlineErr)
	}
}

// A synchronization records how it ended in two places: the provider row the
// console reads, and the audit trail. Both writes were issued and discarded,
// so a run whose bookkeeping failed returned success while the console still
// showed the previous run's numbers and the trail held no entry for this one —
// including for a sweep that had just deactivated an account and signed it out
// everywhere. The upgrade notes send an operator to that trail to find out
// whether the DISABLE policy acted on them, so it cannot lose an entry
// quietly.
func TestIntegrationSyncReportsWhenItsOwnOutcomeIsNotRecorded(t *testing.T) {
	directory := strings.TrimSpace(os.Getenv("RESSO_TEST_LDAP_URL"))
	if directory == "" {
		t.Skip("set RESSO_TEST_LDAP_URL to run federation synchronisation tests")
	}
	data := openIntegrationStore(t, integrationSealer(t))
	bootstrap := bootstrapIntegrationStore(t, data)
	ctx := context.Background()
	branch := "ou=sync-bookkeeping,dc=example,dc=test"
	createDirectoryBranch(t, branch, "stays", "leaves")
	credential := "adminpassword"
	provider, err := data.CreateLDAPFederation(ctx, bootstrap.RealmID, LDAPFederationInput{
		Name: "corp", Vendor: "OTHER", ConnectionURL: directory,
		BindDN: "cn=admin,dc=example,dc=test", BindCredential: &credential,
		UsersDN: branch, UsernameLDAPAttribute: "uid", RDNLDAPAttribute: "uid",
		UUIDLDAPAttribute: "entryUUID", UserObjectClasses: []string{"inetOrgPerson"},
		SearchScope: "SUBTREE", BatchSize: 100, EditMode: "READ_ONLY", MissingUserAction: "DISABLE",
		EmailLDAPAttribute: "mail", DisplayNameLDAPAttribute: "cn",
		ImportEnabled: true, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	recorded := func() (string, int) {
		t.Helper()
		var status string
		if err := data.Pool.QueryRow(ctx, `SELECT last_sync_status FROM user_federations WHERE id=$1`,
			provider.ID).Scan(&status); err != nil {
			t.Fatal(err)
		}
		var events int
		if err := data.Pool.QueryRow(ctx,
			`SELECT count(*) FROM audit_events WHERE event_type='LDAP_FEDERATION_SYNC'`).Scan(&events); err != nil {
			t.Fatal(err)
		}
		return status, events
	}

	summary, err := data.SyncLDAPFederation(ctx, provider.ID)
	if err != nil || summary.RecordError != "" {
		t.Fatalf("a healthy sync reported err=%v record_error=%q", err, summary.RecordError)
	}
	if status, events := recorded(); status != "SUCCESS" || events != 1 {
		t.Fatalf("a healthy sync recorded status=%s events=%d", status, events)
	}

	// Block both bookkeeping writes and nothing else, so the run itself — the
	// directory read, the upserts, the DISABLE sweep — proceeds normally.
	for _, statement := range []string{
		`CREATE FUNCTION block_bookkeeping() RETURNS trigger AS $$
			BEGIN RAISE EXCEPTION 'bookkeeping blocked for the test'; END $$ LANGUAGE plpgsql`,
		`CREATE TRIGGER block_outcome BEFORE UPDATE ON user_federations
			FOR EACH ROW WHEN (NEW.last_sync_status <> 'RUNNING') EXECUTE FUNCTION block_bookkeeping()`,
		`CREATE TRIGGER block_audit BEFORE INSERT ON audit_events
			FOR EACH ROW WHEN (NEW.event_type='LDAP_FEDERATION_SYNC') EXECUTE FUNCTION block_bookkeeping()`,
	} {
		if _, err := data.Pool.Exec(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = data.Pool.Exec(context.Background(), "DROP TRIGGER IF EXISTS block_outcome ON user_federations")
		_, _ = data.Pool.Exec(context.Background(), "DROP TRIGGER IF EXISTS block_audit ON audit_events")
	})

	if err := removeDirectoryEntry(t, "uid=leaves,"+branch); err != nil {
		t.Fatal(err)
	}
	summary, err = data.SyncLDAPFederation(ctx, provider.ID)
	if err != nil {
		t.Fatalf("blocking the bookkeeping should not fail the run itself: %v", err)
	}
	// The run really did act on somebody, which is what makes the missing
	// record worth reporting rather than tidying away.
	if summary.Disabled != 1 {
		t.Fatalf("the run disabled %d accounts, want 1", summary.Disabled)
	}
	if summary.RecordError == "" {
		t.Fatal("the run reported nothing about its outcome not being recorded")
	}
	for _, expected := range []string{"provider", "audit"} {
		if !strings.Contains(summary.RecordError, expected) {
			t.Errorf("the report does not name the %s write: %q", expected, summary.RecordError)
		}
	}
	// And the two places an operator would look really are unchanged, which is
	// the reason the summary has to carry it.
	if status, events := recorded(); status != "RUNNING" || events != 1 {
		t.Errorf("the blocked writes did not stay blocked: status=%s events=%d", status, events)
	}
}

// The refresh rotation grace decides whether a token presented twice is a
// legitimate retry or a replay, and the timestamp it is measured from is
// written by the database. Measuring it against this process's clock made the
// answer depend on the difference between two clocks: run more than the grace
// ahead of PostgreSQL and every retry inside the window reads as a replay —
// the family is revoked, the person is signed out of that relying party, and
// REFRESH_TOKEN_REUSE records an incident that never happened. ReSSO runs
// offline, where there is often nothing keeping the two in step.
//
// A single clock cannot demonstrate the difference, so what is pinned here is
// that both decisions come from the database: the boundary is moved by writing
// rotated_at and expires_at with the database's own now(), which is the one
// reading a process-clock implementation cannot be trusted to agree with.
func TestIntegrationRefreshRotationAsksTheDatabaseForTheTime(t *testing.T) {
	data := openIntegrationStore(t, integrationSealer(t))
	bootstrap := bootstrapIntegrationStore(t, data)
	ctx := context.Background()
	client, err := data.CreateClient(ctx, bootstrap.RealmID, CreateClientInput{
		ClientID: "clock-probe", Name: "Clock Probe", Type: "confidential",
		RedirectURIs: []string{"https://probe.example.test/cb"}})
	if err != nil {
		t.Fatal(err)
	}
	session, err := data.CreateSession(ctx, bootstrap.RealmID, bootstrap.AdminUserID, time.Hour,
		"127.0.0.1", "clock-test", "password")
	if err != nil {
		t.Fatal(err)
	}
	userID, sessionID := bootstrap.AdminUserID, session.Session.ID
	issue := func() string {
		t.Helper()
		raw, issueErr := data.CreateRefreshToken(ctx, RefreshToken{RealmID: bootstrap.RealmID,
			ClientID: client.Client.ID, UserID: &userID, SessionID: &sessionID,
			Scope: []string{"openid"}, ExpiresAt: time.Now().UTC().Add(time.Hour)})
		if issueErr != nil {
			t.Fatal(issueErr)
		}
		return raw
	}
	// Both timestamps are moved with the database's own now(), so the value the
	// decision is measured against and the reading it is compared to come from
	// the same clock — which is the whole point.
	setRotatedAgo := func(raw string, seconds int) {
		t.Helper()
		if _, err := data.Pool.Exec(ctx, `UPDATE refresh_tokens
			SET rotated_at=now()-make_interval(secs => $2) WHERE token_hash=ANY($1::bytea[])`,
			data.Sealer.Digests(raw), seconds); err != nil {
			t.Fatal(err)
		}
	}

	// Rotated a moment ago: a retry inside the grace window is served, and the
	// family survives.
	inGrace := issue()
	setRotatedAgo(inGrace, 2)
	if _, _, err := data.RotateRefreshToken(ctx, inGrace, nil); err != nil {
		t.Fatalf("a retry two seconds after the rotation was refused: %v", err)
	}

	// Rotated well outside it: the same presentation is a replay.
	stale := issue()
	setRotatedAgo(stale, int(RefreshRotationGrace.Seconds())+10)
	if _, _, err := data.RotateRefreshToken(ctx, stale, nil); !errors.Is(err, ErrTokenReuse) {
		t.Fatalf("a token rotated outside the grace window returned %v, want ErrTokenReuse", err)
	}

	// Expiry is the database's reading too.
	expired := issue()
	if _, err := data.Pool.Exec(ctx, `UPDATE refresh_tokens SET expires_at=now()-interval '1 second'
		WHERE token_hash=ANY($1::bytea[])`, data.Sealer.Digests(expired)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := data.RotateRefreshToken(ctx, expired, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("an expired token returned %v, want ErrNotFound", err)
	}

	// And the difference between the two clocks is reported rather than left to
	// be discovered as a handful of unrelated oddities.
	skew, roundTrip, err := data.ClockSkew(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if roundTrip <= 0 {
		t.Errorf("the reading reported no round trip, so its uncertainty is unstated")
	}
	if skew > time.Minute || skew < -time.Minute {
		t.Errorf("this machine reports %v of difference from its own PostgreSQL, "+
			"which means the measurement is wrong rather than the clocks", skew)
	}
}

// Which value is at fault is what the constraint decides, so the message has
// to be chosen from the constraint that fired. The users table alone carries
// three, and answering an email collision with "that username is taken" sends
// somebody to change a field that was never the problem — which is what the
// first pass at this did, by mapping any unique violation on a create to the
// one field the call site happened to know about.
func TestIntegrationTakenValuesNameTheFieldThatCollided(t *testing.T) {
	data := openIntegrationStore(t, integrationSealer(t))
	bootstrap := bootstrapIntegrationStore(t, data)
	ctx := context.Background()
	realm := bootstrap.RealmID

	// Every constraint the table above claims to know must exist, or its entry
	// quietly stops applying and the vague fallback takes over instead.
	for name := range takenValueMessages {
		var exists bool
		if err := data.Pool.QueryRow(ctx, `SELECT EXISTS(
			SELECT 1 FROM pg_constraint WHERE conname=$1
			UNION ALL
			SELECT 1 FROM pg_indexes WHERE indexname=$1 AND schemaname=current_schema())`,
			name).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if !exists {
			t.Errorf("takenValueMessages names %q, which this schema does not have", name)
		}
	}

	if _, err := data.CreateUser(ctx, realm, CreateUserInput{Username: "alice",
		Email: "shared@example.test", Password: "probe-password-1234", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	carol, err := data.CreateUser(ctx, realm, CreateUserInput{Username: "carol",
		Email: "carol@example.test", Password: "probe-password-1234", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	other, err := data.CreateRealm(ctx, CreateRealmInput{Name: "second", DisplayName: "Second",
		IssuerURL: "https://second.example.test/realms/second"})
	if err != nil {
		t.Fatal(err)
	}
	master, err := data.RealmByID(ctx, realm)
	if err != nil {
		t.Fatal(err)
	}
	realmPolicy := func(issuer string) UpdateRealmInput {
		return UpdateRealmInput{DisplayName: "Second", IssuerURL: issuer, Enabled: true,
			AccessTokenTTLSeconds: 300, RefreshTokenTTLSeconds: 1800, SessionTTLSeconds: 28800,
			PasswordMinLength: 12, MaxLoginAttempts: 5, LockoutSeconds: 900}
	}

	for _, collision := range []struct {
		what   string
		do     func() error
		expect string
	}{
		{"a taken username", func() error {
			_, err := data.CreateUser(ctx, realm, CreateUserInput{Username: "alice",
				Password: "probe-password-1234", Enabled: true})
			return err
		}, "사용자 이름"},
		{"a username differing only in case", func() error {
			_, err := data.CreateUser(ctx, realm, CreateUserInput{Username: "ALICE",
				Password: "probe-password-1234", Enabled: true})
			return err
		}, "사용자 이름"},
		{"a taken email on create", func() error {
			_, err := data.CreateUser(ctx, realm, CreateUserInput{Username: "bob",
				Email: "shared@example.test", Password: "probe-password-1234", Enabled: true})
			return err
		}, "이메일"},
		{"a taken email on update", func() error {
			_, err := data.UpdateUser(ctx, carol.ID, UpdateUserInput{DisplayName: "Carol",
				Email: "shared@example.test", Enabled: true})
			return err
		}, "이메일"},
		{"a taken issuer URL on update", func() error {
			_, err := data.UpdateRealm(ctx, other.ID, realmPolicy(master.IssuerURL))
			return err
		}, "Issuer URL"},
	} {
		err := collision.do()
		if !errors.Is(err, ErrConflict) {
			t.Errorf("%s returned %v, want a conflict", collision.what, err)
			continue
		}
		if !strings.Contains(err.Error(), collision.expect) {
			t.Errorf("%s was reported as %q, which does not name %s",
				collision.what, err.Error(), collision.expect)
		}
	}

	// The value that was free still goes in, so this bounds the refusal.
	if _, err := data.UpdateRealm(ctx, other.ID, realmPolicy("https://third.example.test/realms/second")); err != nil {
		t.Errorf("a free issuer URL was refused: %v", err)
	}
}

// The Realm policy bounds are written down three times: the CHECK constraints
// on the table, the validator that mirrors them so an operator gets a sentence
// instead of a constraint violation, and the operations guide that prints them
// for whoever is choosing a value. Two of the three had already drifted — the
// guide gave the idle timeout a maximum of 24 hours where the constraint
// allows 30 days — so all three are compared here.
func TestIntegrationRealmPolicyBoundsAgreeEverywhere(t *testing.T) {
	data := openIntegrationStore(t, integrationSealer(t))
	ctx := context.Background()

	// The database is the authority: the validator exists to say the same
	// thing sooner and in words, so a validator that allows what the
	// constraint rejects produces exactly the violation it was added to avoid.
	definitions := map[string]string{}
	rows, err := data.Pool.Query(ctx, `SELECT conname, pg_get_constraintdef(oid)
		FROM pg_constraint WHERE conrelid = 'realms'::regclass AND contype = 'c'`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var name, definition string
		if err := rows.Scan(&name, &definition); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		definitions[name] = definition
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}

	for _, bound := range realmPolicyBounds {
		definition, found := definitions["realms_"+bound.Label+"_check"]
		if !found {
			t.Errorf("the table has no CHECK for %s, so the validator is the only thing holding it", bound.Label)
			continue
		}
		numbers := regexp.MustCompile(`\d+`).FindAllString(definition, -1)
		low, high := strconv.Itoa(bound.Low), strconv.Itoa(bound.High)
		if !slices.Contains(numbers, low) || !slices.Contains(numbers, high) {
			t.Errorf("%s: the validator allows %s–%s, the constraint says %q",
				bound.Label, low, high, definition)
		}
	}

	// And the guide has to print the same numbers. Only the range cells of its
	// policy tables are read: a row names a setting and gives its range in
	// seconds, which is the form both tables already use.
	guide, err := os.ReadFile(filepath.Join("..", "..", "docs", "operations.md"))
	if err != nil {
		t.Fatal(err)
	}
	// Each row is tied to the setting it describes, because asking only
	// whether a number is a bound somewhere is not enough: 86400 is a real
	// bound — of the lockout — so an idle timeout documented as 300–86400
	// would pass a looser check while being wrong, which is the mistake this
	// exists to catch.
	//
	// Only the rows that state their range as plain seconds are read. The
	// lockout, password length and attempt count are written in the units
	// somebody choosing a value thinks in ("30초 ~ 24시간"), and rewriting them
	// to satisfy a test would make the guide worse to read than the drift is
	// worth.
	settings := map[string]string{
		"Access Token":  "access_token_ttl_seconds",
		"Refresh Token": "refresh_token_ttl_seconds",
		"SSO Session":   "session_ttl_seconds",
		"유휴 만료":         "idle_timeout_seconds",
	}
	bounds := map[string][2]int{}
	for _, bound := range realmPolicyBounds {
		bounds[bound.Label] = [2]int{bound.Low, bound.High}
	}
	rangePattern := regexp.MustCompile(`(\d{2,})[–-](\d{2,})초`)
	checked := 0
	for _, line := range strings.Split(string(guide), "\n") {
		cells := strings.Split(strings.Trim(line, "| "), "|")
		if len(cells) < 2 {
			continue
		}
		label, found := settings[strings.Trim(cells[0], " `")]
		if !found {
			continue
		}
		match := rangePattern.FindStringSubmatch(line)
		if match == nil {
			t.Errorf("the guide's row for %s states no range in seconds: %q", label, line)
			continue
		}
		low, _ := strconv.Atoi(match[1])
		high, _ := strconv.Atoi(match[2])
		if bounds[label] != [2]int{low, high} {
			t.Errorf("the guide gives %s a range of %d–%d, the service enforces %d–%d",
				label, low, high, bounds[label][0], bounds[label][1])
		}
		checked++
	}
	if checked < len(settings) {
		t.Errorf("only %d of %d documented policy rows were found to check", checked, len(settings))
	}
}

// A rate limiter that cannot work must not answer that everything is fine.
// The three entry points each derived Allowed from a zero decision and reached
// three different conclusions from the same unusable settings — and a window of
// zero, which turns the limiter off outright, came back allowed from all three:
//
//	maximum 0        consume=true   check=false  record=false
//	window 0         consume=true   check=true   record=true
//
// The values come from literals in the handlers rather than from
// configuration, so reaching this is a mistake in the code. Failing the request
// is how such a mistake gets found, instead of running with the throttle in
// front of password hashing silently absent.
func TestIntegrationLoginLimiterRefusesToRunWithoutUsableSettings(t *testing.T) {
	data := openIntegrationStore(t, integrationSealer(t))
	_ = bootstrapIntegrationStore(t, data)
	ctx := context.Background()

	for _, unusable := range []struct {
		what    string
		maximum int
		window  time.Duration
	}{
		{"a maximum of zero", 0, time.Minute},
		{"a negative maximum", -1, time.Minute},
		{"no window at all", 5, 0},
		{"a negative window", 5, -time.Minute},
	} {
		bucket := "limiter-probe/" + unusable.what
		for name, call := range map[string]func() (RateLimitDecision, error){
			"ConsumeLoginRateLimit": func() (RateLimitDecision, error) {
				return data.ConsumeLoginRateLimit(ctx, bucket, unusable.maximum, unusable.window)
			},
			"CheckLoginRateLimit": func() (RateLimitDecision, error) {
				return data.CheckLoginRateLimit(ctx, bucket, unusable.maximum, unusable.window)
			},
			"RecordLoginFailure": func() (RateLimitDecision, error) {
				return data.RecordLoginFailure(ctx, bucket, unusable.maximum, unusable.window)
			},
		} {
			decision, err := call()
			if !errors.Is(err, ErrInvalidInput) {
				t.Errorf("%s with %s returned %v, want it refused", name, unusable.what, err)
			}
			if decision.Allowed {
				t.Errorf("%s with %s allowed the attempt anyway", name, unusable.what)
			}
		}
	}

	// Usable settings still count, so this bounds the refusal rather than
	// disabling the limiter from the other direction.
	bucket := "limiter-probe/usable"
	for attempt := 1; attempt <= 2; attempt++ {
		decision, err := data.RecordLoginFailure(ctx, bucket, 3, time.Minute)
		if err != nil || !decision.Allowed || decision.Attempts != attempt {
			t.Fatalf("failure %d recorded %+v, err=%v", attempt, decision, err)
		}
	}
	decision, err := data.RecordLoginFailure(ctx, bucket, 3, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Allowed || decision.RetryAfterSeconds < 1 {
		t.Errorf("reaching the maximum reported %+v, want it limited with a wait", decision)
	}
}

// A public Client has no secret, so PKCE is the only thing tying an
// authorization code to whoever asked for it: without it a code lifted from
// the redirect — browser history, a rival app registered for the same custom
// scheme, a referrer — is redeemable by anyone who has it. Creation forced it
// on and updating did not, so an ordinary edit could take it away, while the
// compatibility document says it is enforced for public Clients.
func TestIntegrationPublicClientKeepsPKCEThroughAnUpdate(t *testing.T) {
	data := openIntegrationStore(t, integrationSealer(t))
	bootstrap := bootstrapIntegrationStore(t, data)
	ctx := context.Background()

	public, err := data.CreateClient(ctx, bootstrap.RealmID, CreateClientInput{
		ClientID: "spa", Name: "SPA", Type: "public",
		RedirectURIs: []string{"https://spa.example.test/cb"},
		GrantTypes:   []string{"authorization_code"}, DefaultScopes: []string{"openid"},
		RequirePKCE: false})
	if err != nil {
		t.Fatal(err)
	}
	if !public.Client.RequirePKCE {
		t.Fatal("a public Client was created without PKCE")
	}
	updated, err := data.UpdateClient(ctx, public.Client.ID, UpdateClientInput{
		Name: "SPA", RedirectURIs: public.Client.RedirectURIs,
		GrantTypes: public.Client.GrantTypes, DefaultScopes: public.Client.DefaultScopes,
		RequirePKCE: false, Enabled: true,
		AccessTokenTTLSeconds:  public.Client.AccessTokenTTLSeconds,
		RefreshTokenTTLSeconds: public.Client.RefreshTokenTTLSeconds})
	if err != nil {
		t.Fatal(err)
	}
	if !updated.RequirePKCE {
		t.Error("an update took PKCE away from a public Client")
	}

	// A confidential Client authenticates with its secret, so it may choose.
	// Forcing it there would be a different product than the one documented.
	confidential, err := data.CreateClient(ctx, bootstrap.RealmID, CreateClientInput{
		ClientID: "service", Name: "Service", Type: "confidential",
		RedirectURIs: []string{"https://service.example.test/cb"},
		GrantTypes:   []string{"authorization_code"}, DefaultScopes: []string{"openid"},
		RequirePKCE: true})
	if err != nil {
		t.Fatal(err)
	}
	relaxed, err := data.UpdateClient(ctx, confidential.Client.ID, UpdateClientInput{
		Name: "Service", RedirectURIs: confidential.Client.RedirectURIs,
		GrantTypes: confidential.Client.GrantTypes, DefaultScopes: confidential.Client.DefaultScopes,
		RequirePKCE: false, Enabled: true,
		AccessTokenTTLSeconds:  confidential.Client.AccessTokenTTLSeconds,
		RefreshTokenTTLSeconds: confidential.Client.RefreshTokenTTLSeconds})
	if err != nil {
		t.Fatal(err)
	}
	if relaxed.RequirePKCE {
		t.Error("a confidential Client could not turn PKCE off")
	}
}

// Rolling the container back to an earlier image is step five of the
// documented upgrade procedure, and the older binary then finds every
// migration it knows about already applied and starts as if nothing were
// unusual. Whether that is safe depends on what the newer migrations did —
// the release notes say so per release — but the service could see the fact
// plainly and said nothing, leaving the operator's only protection a document
// they had to remember to read during an incident.
func TestIntegrationSchemaAheadOfThisBuildIsReported(t *testing.T) {
	data := openIntegrationStore(t, integrationSealer(t))
	_ = bootstrapIntegrationStore(t, data)
	ctx := context.Background()

	ahead, err := MigrationsAheadOfBinary(ctx, data.Pool)
	if err != nil {
		t.Fatal(err)
	}
	if len(ahead) != 0 {
		t.Fatalf("a database this build migrated reports %v ahead of it", ahead)
	}
	diagnosis, err := data.DiagnoseRecovery(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(diagnosis.MigrationsAheadOfBinary) != 0 || !diagnosis.DatabaseReady {
		t.Fatalf("a matching schema was not diagnosed as ready: %+v", diagnosis.MigrationsAheadOfBinary)
	}

	// What a rolled-back image sees: a version recorded by a build that had a
	// migration this one does not carry.
	if _, err := data.Pool.Exec(ctx,
		`INSERT INTO schema_migrations(version) VALUES('900_from_a_later_release.sql')`); err != nil {
		t.Fatal(err)
	}
	ahead, err = MigrationsAheadOfBinary(ctx, data.Pool)
	if err != nil {
		t.Fatal(err)
	}
	if len(ahead) != 1 || ahead[0] != "900_from_a_later_release.sql" {
		t.Errorf("the newer migration was not reported: %v", ahead)
	}
	diagnosis, err = data.DiagnoseRecovery(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(diagnosis.MigrationsAheadOfBinary) != 1 {
		t.Errorf("the diagnosis did not name it: %+v", diagnosis.MigrationsAheadOfBinary)
	}
	// And it is reported, not refused: the database is still usable, because a
	// rollback happens when something is already wrong and a service that will
	// not start takes away the way out.
	if !diagnosis.DatabaseReady {
		t.Error("a schema ahead of this build was diagnosed as not ready")
	}
	if err := Migrate(ctx, data.Pool); err != nil {
		t.Errorf("migrating against a schema ahead of this build failed: %v", err)
	}
}

// Bootstrap is meant to be idempotent, and it says so: it never resets an
// existing administrator's password, so a restart cannot become a password
// reset. But it re-applied platform_admin and enabled on every start, so a
// restart undid an administrator's decisions instead — an operator who
// disabled the bootstrap account after creating named administrators, which is
// ordinary practice, found it enabled again with its original password and
// nothing to say so.
//
// The same line meant that pointing BOOTSTRAP_ADMIN at an existing ordinary
// user promoted them to platform administrator on the next start.
func TestIntegrationBootstrapDoesNotUndoAnAdministratorsDecisions(t *testing.T) {
	data := openIntegrationStore(t, integrationSealer(t))
	ctx := context.Background()
	first, err := data.Bootstrap(ctx, "admin", "bootstrap-password-123")
	if err != nil {
		t.Fatal(err)
	}
	if !first.Created {
		t.Fatal("the first bootstrap did not create the administrator")
	}
	state := func() (enabled, platformAdmin bool) {
		t.Helper()
		if err := data.Pool.QueryRow(ctx, `SELECT enabled, platform_admin FROM users WHERE id=$1`,
			first.AdminUserID).Scan(&enabled, &platformAdmin); err != nil {
			t.Fatal(err)
		}
		return enabled, platformAdmin
	}
	if enabled, admin := state(); !enabled || !admin {
		t.Fatalf("the account it created is enabled=%v platform_admin=%v", enabled, admin)
	}

	if _, err := data.UpdateUser(ctx, first.AdminUserID, UpdateUserInput{
		DisplayName: "Bootstrap Administrator", Email: "", Enabled: false}); err != nil {
		t.Fatal(err)
	}
	if _, err := data.Pool.Exec(ctx, `UPDATE users SET platform_admin=false WHERE id=$1`,
		first.AdminUserID); err != nil {
		t.Fatal(err)
	}

	// The container restarts with the same environment.
	again, err := data.Bootstrap(ctx, "admin", "bootstrap-password-123")
	if err != nil {
		t.Fatal(err)
	}
	if again.Created || again.AdminUserID != first.AdminUserID {
		t.Fatalf("a restart did not find the existing account: %+v", again)
	}
	if enabled, admin := state(); enabled || admin {
		t.Errorf("a restart restored the account: enabled=%v platform_admin=%v", enabled, admin)
	}

	// Naming an ordinary user in the environment must not promote them.
	ordinary, err := data.CreateUser(ctx, first.RealmID, CreateUserInput{
		Username: "alice", Password: "alice-password-1234", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := data.Bootstrap(ctx, "alice", "unused-password-1234"); err != nil {
		t.Fatal(err)
	}
	var promoted bool
	if err := data.Pool.QueryRow(ctx, `SELECT platform_admin FROM users WHERE id=$1`,
		ordinary.ID).Scan(&promoted); err != nil {
		t.Fatal(err)
	}
	if promoted {
		t.Error("naming an existing user in BOOTSTRAP_ADMIN made them a platform administrator")
	}

	// And it still does its job on an empty database: the guarantee this
	// change must not break is that a first start produces a usable
	// administrator.
	fresh := openIntegrationStore(t, integrationSealer(t))
	created, err := fresh.Bootstrap(ctx, "admin", "bootstrap-password-123")
	if err != nil {
		t.Fatal(err)
	}
	var enabled, admin bool
	if err := fresh.Pool.QueryRow(ctx, `SELECT enabled, platform_admin FROM users WHERE id=$1`,
		created.AdminUserID).Scan(&enabled, &admin); err != nil {
		t.Fatal(err)
	}
	if !created.Created || !enabled || !admin {
		t.Errorf("a first start did not produce a usable administrator: %+v enabled=%v admin=%v",
			created, enabled, admin)
	}
}

// The trigram indexes are optional and created one statement at a time, and
// the first failure used to return, leaving the rest uncreated. The caller
// logs a single line either way, so a search by e-mail or display name went on
// scanning the whole table with nothing to say which of the three was missing —
// the same shape as the retention sweep stopping at its first failure.
func TestIntegrationSearchIndexesAreAllAttempted(t *testing.T) {
	data := openIntegrationStore(t, integrationSealer(t))
	_ = bootstrapIntegrationStore(t, data)
	ctx := context.Background()

	var extensionPresent bool
	if err := data.Pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM pg_extension WHERE extname='pg_trgm')`).Scan(&extensionPresent); err != nil {
		t.Fatal(err)
	}
	if !extensionPresent {
		t.Skip("pg_trgm is not installed in this database")
	}
	indexed, err := data.EnsureSearchIndexes(ctx)
	if err != nil || !indexed {
		t.Fatalf("creating the search indexes reported indexed=%v err=%v", indexed, err)
	}
	present := func() int {
		t.Helper()
		var count int
		if err := data.Pool.QueryRow(ctx, `SELECT count(*) FROM pg_indexes
			WHERE schemaname=current_schema() AND indexname IN
			('idx_users_username_trgm','idx_users_email_trgm','idx_users_display_name_trgm')`).Scan(&count); err != nil {
			t.Fatal(err)
		}
		return count
	}
	if present() != 3 {
		t.Fatalf("only %d of the three search indexes exist", present())
	}

	// Take them away, then make the middle statement fail. The one before it
	// must still have been created and — the point — the one after it too.
	for _, name := range []string{"idx_users_username_trgm", "idx_users_email_trgm", "idx_users_display_name_trgm"} {
		if _, err := data.Pool.Exec(ctx, "DROP INDEX "+name); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := data.Pool.Exec(ctx, "ALTER TABLE users RENAME COLUMN email TO email_renamed"); err != nil {
		t.Fatal(err)
	}
	indexed, err = data.EnsureSearchIndexes(ctx)
	if _, restoreErr := data.Pool.Exec(ctx,
		"ALTER TABLE users RENAME COLUMN email_renamed TO email"); restoreErr != nil {
		t.Fatal(restoreErr)
	}
	if err == nil {
		t.Fatal("an index that could not be created was reported as created")
	}
	if indexed {
		t.Error("indexed was reported true while one index could not be created")
	}
	if !strings.Contains(err.Error(), "email") {
		t.Errorf("the failure does not name which index it was: %v", err)
	}
	if present() != 2 {
		t.Errorf("%d of the two possible indexes exist; the run stopped at the failure", present())
	}
}

// Asking twice for the same role adds nothing and shows the reviewer the same
// row again — clicking a second time because nothing appeared to happen is the
// ordinary way it arises. And approving a request whose role was granted in the
// meantime, by an administrator or by a duplicate decided first, used to fail
// with "approval target is no longer valid": the target was fine, and the
// outcome the reviewer wanted already held.
func TestIntegrationApprovalRequestsAreNotDuplicatedOrMisreported(t *testing.T) {
	data := openIntegrationStore(t, integrationSealer(t))
	bootstrap := bootstrapIntegrationStore(t, data)
	ctx := context.Background()
	realm, err := data.RealmByID(ctx, bootstrap.RealmID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := data.UpdateRealm(ctx, realm.ID, UpdateRealmInput{
		DisplayName: realm.DisplayName, IssuerURL: realm.IssuerURL, Enabled: true, ApprovalEnabled: true,
		AccessTokenTTLSeconds: realm.AccessTokenTTLSeconds, RefreshTokenTTLSeconds: realm.RefreshTokenTTLSeconds,
		SessionTTLSeconds: realm.SessionTTLSeconds, PasswordMinLength: realm.PasswordMinLength,
		MaxLoginAttempts: realm.MaxLoginAttempts, LockoutSeconds: realm.LockoutSeconds}); err != nil {
		t.Fatal(err)
	}
	manager, err := data.CreateUser(ctx, realm.ID, CreateUserInput{
		Username: "manager", Password: "manager-password-1234", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	created, err := data.CreateUser(ctx, realm.ID, CreateUserInput{
		Username: "staff", Password: "staff-password-1234", Enabled: true, ManagerID: &manager.ID})
	if err != nil {
		t.Fatal(err)
	}
	staff, err := data.UserByID(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	role, err := data.CreateRole(ctx, realm.ID, "auditor", "")
	if err != nil {
		t.Fatal(err)
	}
	second, err := data.CreateRole(ctx, realm.ID, "reviewer", "")
	if err != nil {
		t.Fatal(err)
	}

	first, err := data.CreateRoleApprovalRequest(ctx, staff, role.ID, "please")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := data.CreateRoleApprovalRequest(ctx, staff, role.ID, "please again"); !errors.Is(err, ErrConflict) {
		t.Errorf("a second request for a role already waiting returned %v, want a conflict", err)
	}
	// A different role is a different question and must still be askable.
	other, err := data.CreateRoleApprovalRequest(ctx, staff, second.ID, "and this one")
	if err != nil {
		t.Fatalf("a request for another role was refused: %v", err)
	}

	// An administrator grants the role while the request is still waiting.
	if _, err := data.Pool.Exec(ctx, `INSERT INTO user_roles(user_id,role_id) VALUES($1,$2)
		ON CONFLICT DO NOTHING`, staff.ID, role.ID); err != nil {
		t.Fatal(err)
	}
	decided, err := data.DecideApprovalRequest(ctx, first.ID, manager.ID, false, false, realm.ID, true, "ok")
	if err != nil {
		t.Fatalf("approving a role the person already holds failed: %v", err)
	}
	if decided.Status != "APPROVED" {
		t.Errorf("the request was recorded as %s", decided.Status)
	}

	// A target that really has gone still fails, which is what that message
	// was for: the role is deleted while its request waits.
	if err := data.DeleteRole(ctx, realm.ID, second.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := data.DecideApprovalRequest(ctx, other.ID, manager.ID, false, false, realm.ID, true, "ok"); err == nil {
		t.Error("approving a request whose role was deleted succeeded")
	}
}

// The approvals list is capped, and the console filters for the ones still
// waiting after it arrives. Ordered newest-first alone, a request nobody had
// answered dropped off the page once five hundred newer ones had been decided:
// the reviewer's queue read as empty while somebody waited, and there is no
// page to turn to.
func TestIntegrationWaitingApprovalsSurviveTheListingCap(t *testing.T) {
	data := openIntegrationStore(t, integrationSealer(t))
	bootstrap := bootstrapIntegrationStore(t, data)
	ctx := context.Background()
	role, err := data.CreateRole(ctx, bootstrap.RealmID, "requested", "")
	if err != nil {
		t.Fatal(err)
	}
	payload := func() string { return bootstrap.AdminUserID.String() }
	if _, err := data.Pool.Exec(ctx, `INSERT INTO approval_requests(
		id,realm_id,requester_id,kind,payload,reason,status,created_at)
		VALUES(gen_random_uuid(),$1,$2,'ROLE_ASSIGNMENT',
		jsonb_build_object('user_id',$4::text,'role_id',$3::text),
		'still waiting','PENDING', now()-interval '400 days')`,
		bootstrap.RealmID, bootstrap.AdminUserID, role.ID, payload()); err != nil {
		t.Fatal(err)
	}
	// More decided requests than the cap, all of them newer.
	if _, err := data.Pool.Exec(ctx, `INSERT INTO approval_requests(
		id,realm_id,requester_id,kind,payload,reason,status,created_at,decided_at)
		SELECT gen_random_uuid(),$1,$2,'ROLE_ASSIGNMENT',
		jsonb_build_object('user_id',$4::text,'role_id',$3::text),
		'decided ' || i,'APPROVED', now()-(i || ' minutes')::interval, now()
		FROM generate_series(1,520) AS i`,
		bootstrap.RealmID, bootstrap.AdminUserID, role.ID, payload()); err != nil {
		t.Fatal(err)
	}

	realmID := bootstrap.RealmID
	listed, err := data.ListApprovalRequests(ctx, &realmID, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	waiting := 0
	for _, item := range listed {
		if item.Status == "PENDING" {
			waiting++
		}
	}
	var inTheDatabase int
	if err := data.Pool.QueryRow(ctx,
		`SELECT count(*) FROM approval_requests WHERE status='PENDING'`).Scan(&inTheDatabase); err != nil {
		t.Fatal(err)
	}
	if waiting != inTheDatabase {
		t.Errorf("the list carries %d waiting requests out of %d; one nobody answered is unreachable",
			waiting, inTheDatabase)
	}
	// Decided requests still come back, newest first, so the page keeps its
	// history — the cap is what bounds it, not the ordering.
	if len(listed) != 500 {
		t.Errorf("the list returned %d rows, want the cap of 500", len(listed))
	}
	if listed[0].Status != "PENDING" {
		t.Errorf("the waiting request is not at the top of the reviewer's list")
	}
}

// Ending one of your own sessions has to end that one and no other. The
// ownership check used to list up to five hundred of the caller's sessions and
// search for the identifier, which was right only because that number exceeds
// the hundred the page shows — a session somebody could see was always inside
// the window the check happened to read. It is decided by the revoking
// statement now.
func TestIntegrationRevokingOwnSessionTouchesNobodyElses(t *testing.T) {
	data := openIntegrationStore(t, integrationSealer(t))
	bootstrap := bootstrapIntegrationStore(t, data)
	ctx := context.Background()
	other, err := data.CreateUser(ctx, bootstrap.RealmID, CreateUserInput{
		Username: "someone-else", Password: "someone-password-1234", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	mine, err := data.CreateSession(ctx, bootstrap.RealmID, bootstrap.AdminUserID, time.Hour,
		"127.0.0.1", "ownership-test", "password")
	if err != nil {
		t.Fatal(err)
	}
	theirs, err := data.CreateSession(ctx, bootstrap.RealmID, other.ID, time.Hour,
		"127.0.0.1", "ownership-test", "password")
	if err != nil {
		t.Fatal(err)
	}
	live := func(id uuid.UUID) bool {
		t.Helper()
		var alive bool
		if err := data.Pool.QueryRow(ctx,
			`SELECT revoked_at IS NULL FROM sso_sessions WHERE id=$1`, id).Scan(&alive); err != nil {
			t.Fatal(err)
		}
		return alive
	}

	// Somebody else's session is reported as absent, and left alone.
	if err := data.RevokeOwnedSession(ctx, theirs.Session.ID, bootstrap.AdminUserID); !errors.Is(err, ErrNotFound) {
		t.Errorf("revoking another person's session returned %v, want not found", err)
	}
	if !live(theirs.Session.ID) {
		t.Error("another person's session was ended")
	}
	// A session that does not exist answers the same way, so the response says
	// nothing about whether it does.
	if err := data.RevokeOwnedSession(ctx, uuid.New(), bootstrap.AdminUserID); !errors.Is(err, ErrNotFound) {
		t.Errorf("revoking a session that does not exist returned %v, want not found", err)
	}
	// And your own ends, with the refresh tokens issued from it.
	userID, sessionID := bootstrap.AdminUserID, mine.Session.ID
	client, err := data.CreateClient(ctx, bootstrap.RealmID, CreateClientInput{
		ClientID: "own-session-rp", Name: "RP", Type: "confidential",
		RedirectURIs: []string{"https://rp.example.test/cb"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := data.CreateRefreshToken(ctx, RefreshToken{RealmID: bootstrap.RealmID,
		ClientID: client.Client.ID, UserID: &userID, SessionID: &sessionID,
		Scope: []string{"openid"}, ExpiresAt: time.Now().UTC().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := data.RevokeOwnedSession(ctx, sessionID, userID); err != nil {
		t.Fatalf("ending my own session failed: %v", err)
	}
	if live(sessionID) {
		t.Error("my own session survived")
	}
	var liveTokens int
	if err := data.Pool.QueryRow(ctx,
		`SELECT count(*) FROM refresh_tokens WHERE session_id=$1 AND revoked_at IS NULL`,
		sessionID).Scan(&liveTokens); err != nil {
		t.Fatal(err)
	}
	if liveTokens != 0 {
		t.Errorf("%d refresh tokens outlived the session they came from", liveTokens)
	}
}

// A count is not a diagnosis. An administrator who made a local account before
// the directory was connected produces exactly this: the sync knows the
// username is already taken, says "1 LDAP users could not be synchronized", and
// throws the sentence away. It matters more than one user, because any failure
// switches off the DISABLE sweep — so one unresolvable collision leaves the
// accounts of everybody who has left enabled indefinitely, and the message that
// would explain why names nothing.
func TestIntegrationSyncNamesTheUsersItCouldNotImport(t *testing.T) {
	directory := strings.TrimSpace(os.Getenv("RESSO_TEST_LDAP_URL"))
	if directory == "" {
		t.Skip("set RESSO_TEST_LDAP_URL to run federation synchronisation tests")
	}
	data := openIntegrationStore(t, integrationSealer(t))
	bootstrap := bootstrapIntegrationStore(t, data)
	ctx := context.Background()
	branch := "ou=sync-collision,dc=example,dc=test"
	createDirectoryBranch(t, branch, "collides", "imports")
	if _, err := data.CreateUser(ctx, bootstrap.RealmID, CreateUserInput{
		Username: "collides", Email: "collides@local.test", Password: "LocalPassword!1", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	credential := "adminpassword"
	provider, err := data.CreateLDAPFederation(ctx, bootstrap.RealmID, LDAPFederationInput{
		Name: "collide", Vendor: "OTHER", ConnectionURL: directory,
		BindDN: "cn=admin,dc=example,dc=test", BindCredential: &credential,
		UsersDN: branch, UsernameLDAPAttribute: "uid", RDNLDAPAttribute: "uid",
		UUIDLDAPAttribute: "entryUUID", UserObjectClasses: []string{"inetOrgPerson"},
		SearchScope: "SUBTREE", BatchSize: 100, EditMode: "READ_ONLY", MissingUserAction: "DISABLE",
		EmailLDAPAttribute: "mail", DisplayNameLDAPAttribute: "cn",
		ImportEnabled: true, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	summary, syncErr := data.SyncLDAPFederation(ctx, provider.ID)
	if syncErr == nil {
		t.Fatalf("a collision synchronised cleanly: %+v", summary)
	}
	if summary.Failed != 1 {
		t.Fatalf("summary.Failed = %d, want 1 (%+v)", summary.Failed, summary)
	}
	for _, where := range []struct {
		what string
		text string
	}{
		{"the error returned to the caller", syncErr.Error()},
		{"the summary", strings.Join(summary.Failures, "; ")},
	} {
		if !strings.Contains(where.text, "collides") {
			t.Errorf("%s does not name the user: %q", where.what, where.text)
		}
		if !strings.Contains(where.text, "already belongs") {
			t.Errorf("%s does not give the reason: %q", where.what, where.text)
		}
	}

	// The console reads the provider row, and the audit trail is what an
	// operator is told to consult about a DISABLE policy. Both have to carry it.
	var recorded string
	if err := data.Pool.QueryRow(ctx,
		"SELECT last_sync_error FROM user_federations WHERE id=$1", provider.ID).Scan(&recorded); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(recorded, "collides") || !strings.Contains(recorded, "already belongs") {
		t.Errorf("the provider row records %q, which an operator cannot act on", recorded)
	}
	var detail string
	if err := data.Pool.QueryRow(ctx, `SELECT detail::text FROM audit_events
        WHERE event_type='LDAP_FEDERATION_SYNC' AND target_id=$1 ORDER BY occurred_at DESC LIMIT 1`,
		provider.ID.String()).Scan(&detail); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(detail, "collides") || !strings.Contains(detail, "already belongs") {
		t.Errorf("the audit detail records %q, which an operator cannot act on", detail)
	}

	// Any failure switches off the DISABLE sweep. That is the right call — the
	// users that failed are the ones whose synced_at did not move — but leaving
	// it to be inferred means the policy can sit idle for months behind a
	// message about one username.
	if !strings.Contains(syncErr.Error(), "left enabled") {
		t.Errorf("the failure does not say the DISABLE sweep was skipped: %q", syncErr)
	}
}

// A rotation invalidates the cache of the instance that performed it and no
// other. Every other instance kept a key set without the new identifier, so it
// rejected the tokens the rotating instance had already started issuing — and
// served that same stale set as its JWKS, which is what a relying party fetches
// the moment it meets an identifier it does not know. A relying party that
// fetched in that window could go on refusing the new key for as long as its
// own cache lived, well past the window that caused it.
func TestIntegrationRotationIsVisibleToInstancesThatDidNotRotate(t *testing.T) {
	rotating := openIntegrationStore(t, integrationSealer(t))
	bootstrap := bootstrapIntegrationStore(t, rotating)
	ctx := context.Background()
	if err := rotating.EnsureActiveSigningKey(ctx, bootstrap.RealmID); err != nil {
		t.Fatal(err)
	}
	// A second process against the same database: its own cache, the same rows.
	other := &Store{Pool: rotating.Pool, Sealer: rotating.Sealer}
	if _, err := other.PublishedSigningKeys(ctx, bootstrap.RealmID); err != nil {
		t.Fatal(err)
	}

	rotated, err := rotating.RotateSigningKey(ctx, bootstrap.RealmID)
	if err != nil {
		t.Fatal(err)
	}
	// Past the floor that keeps an invented identifier from forcing a read; a
	// real deployment is past it long before a token from the new key arrives.
	time.Sleep(minimumKeyReload + 50*time.Millisecond)

	if _, err := other.SigningKeyByKID(ctx, bootstrap.RealmID, rotated.KID); err != nil {
		t.Fatalf("an instance that did not rotate cannot verify the new key: %v", err)
	}
	published, err := other.PublishedSigningKeys(ctx, bootstrap.RealmID)
	if err != nil {
		t.Fatal(err)
	}
	if _, found := findSigningKey(published, rotated.KID); !found {
		t.Errorf("the JWKS of an instance that did not rotate omits the new key")
	}
	if len(published) < 2 {
		t.Errorf("published keys = %d, want the rotated key kept alongside the new one", len(published))
	}
}

// The reload above turns a cache miss into a read, and the identifier comes off
// a token the caller supplies. Without a floor, inventing identifiers is a
// query per request against an endpoint that parses tokens.
func TestIntegrationAnInventedKeyIdentifierDoesNotForceAReadPerRequest(t *testing.T) {
	data := openIntegrationStore(t, integrationSealer(t))
	bootstrap := bootstrapIntegrationStore(t, data)
	ctx := context.Background()
	if err := data.EnsureActiveSigningKey(ctx, bootstrap.RealmID); err != nil {
		t.Fatal(err)
	}
	if _, err := data.PublishedSigningKeys(ctx, bootstrap.RealmID); err != nil {
		t.Fatal(err)
	}
	before := data.Pool.Stat().AcquireCount()
	for i := 0; i < 100; i++ {
		if _, err := data.SigningKeyByKID(ctx, bootstrap.RealmID, "rsa-invented-0000"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("SigningKeyByKID(invented) error = %v, want ErrNotFound", err)
		}
	}
	if reads := data.Pool.Stat().AcquireCount() - before; reads > 2 {
		t.Errorf("100 invented identifiers took %d connection acquisitions; the floor is not holding", reads)
	}
}

// Rotation states how long the previous key stays accepted, and writes that
// moment to retire_at. Nothing read it. The status column decided instead, and
// the only thing that writes the status is the hourly retention pass — so the
// retired key stayed in the JWKS, stayed accepted, and stayed on the console
// as PASSIVE for up to an hour past the retirement time the console was
// displaying in the same row. Rotation is what an operator reaches for when a
// key may have leaked; the window it promises should not depend on a job whose
// purpose is deleting old rows.
func TestIntegrationAKeyIsOutOfEffectTheMomentItRetires(t *testing.T) {
	data := openIntegrationStore(t, integrationSealer(t))
	bootstrap := bootstrapIntegrationStore(t, data)
	ctx := context.Background()
	if err := data.EnsureActiveSigningKey(ctx, bootstrap.RealmID); err != nil {
		t.Fatal(err)
	}
	_, retiring, err := data.ActivePrivateKey(ctx, bootstrap.RealmID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := data.RotateSigningKey(ctx, bootstrap.RealmID); err != nil {
		t.Fatal(err)
	}
	if key, err := data.SigningKeyByKID(ctx, bootstrap.RealmID, retiring.KID); err != nil {
		t.Fatalf("the rotated key is refused before its retirement: %v (%s)", err, key.KID)
	}

	// The retirement moment arrives. The retention pass has not run.
	if _, err := data.Pool.Exec(ctx, `UPDATE signing_keys SET retire_at=now()-interval '1 minute'
        WHERE realm_id=$1 AND status='PASSIVE'`, bootstrap.RealmID); err != nil {
		t.Fatal(err)
	}
	data.InvalidateSigningKeys(bootstrap.RealmID)

	published, err := data.PublishedSigningKeys(ctx, bootstrap.RealmID)
	if err != nil {
		t.Fatal(err)
	}
	if _, found := findSigningKey(published, retiring.KID); found {
		t.Errorf("the JWKS still publishes %s after its retirement", retiring.KID)
	}
	if _, err := data.SigningKeyByKID(ctx, bootstrap.RealmID, retiring.KID); !errors.Is(err, ErrNotFound) {
		t.Errorf("a token signed with the retired key still verifies: err = %v", err)
	}
	// The console reads the same list, so it cannot show a key as PASSIVE
	// beside a retirement time that has already gone by.
	listed, err := data.ListSigningKeys(ctx, bootstrap.RealmID)
	if err != nil {
		t.Fatal(err)
	}
	if _, found := findSigningKey(listed, retiring.KID); found {
		t.Errorf("the console still lists %s as live after its retirement", retiring.KID)
	}
	if len(listed) != 1 {
		t.Errorf("keys in effect = %d, want only the active one", len(listed))
	}
}

// Ending a session is two writes: the session row, which stops the browser
// cookie, and the refresh tokens, which are what keep a relying party going.
// The second one's failure was dropped and the call returned success, so the
// person looked signed out while every relying party holding a refresh token
// went on minting access tokens — and the PARTIAL the callers were given for
// exactly this could never fire, because nothing told them.
func TestIntegrationEndingASessionReportsRefreshTokensItCouldNotRevoke(t *testing.T) {
	data := openIntegrationStore(t, integrationSealer(t))
	bootstrap := bootstrapIntegrationStore(t, data)
	ctx := context.Background()
	realm, err := data.RealmByID(ctx, bootstrap.RealmID)
	if err != nil {
		t.Fatal(err)
	}
	client, err := data.CreateClient(ctx, realm.ID, CreateClientInput{
		ClientID: "still-running", Name: "RP", Type: "confidential",
		RedirectURIs: []string{"https://rp.example.test/cb"},
		GrantTypes:   []string{"authorization_code", "refresh_token"}, DefaultScopes: []string{"openid"}})
	if err != nil {
		t.Fatal(err)
	}
	userID := bootstrap.AdminUserID
	newToken := func(t *testing.T) (uuid.UUID, string) {
		t.Helper()
		session, sessionErr := data.CreateSession(ctx, realm.ID, userID, time.Hour, "127.0.0.1", "revoke", "password")
		if sessionErr != nil {
			t.Fatal(sessionErr)
		}
		sessionID := session.Session.ID
		raw, tokenErr := data.CreateRefreshToken(ctx, RefreshToken{RealmID: realm.ID, ClientID: client.Client.ID,
			UserID: &userID, SessionID: &sessionID, Scope: []string{"openid"},
			ExpiresAt: time.Now().UTC().Add(time.Hour)})
		if tokenErr != nil {
			t.Fatal(tokenErr)
		}
		return sessionID, raw
	}
	byOwner, ownerToken := newToken(t)
	bySession, sessionToken := newToken(t)
	byUser, userToken := newToken(t)

	// The refresh tokens cannot be revoked. The session rows still can, which
	// is what made the failure look like a success.
	if _, err := data.Pool.Exec(ctx,
		"ALTER TABLE refresh_tokens RENAME COLUMN revoked_at TO revoked_at_moved"); err != nil {
		t.Fatal(err)
	}
	failures := map[string]error{
		"RevokeOwnedSession":    data.RevokeOwnedSession(ctx, byOwner, userID),
		"RevokeSession":         data.RevokeSession(ctx, bySession),
		"RevokeAllUserSessions": data.RevokeAllUserSessions(ctx, userID, nil),
	}
	if _, err := data.Pool.Exec(ctx,
		"ALTER TABLE refresh_tokens RENAME COLUMN revoked_at_moved TO revoked_at"); err != nil {
		t.Fatal(err)
	}
	for name, err := range failures {
		if err == nil {
			t.Errorf("%s reported success while its refresh tokens were left live", name)
		}
	}

	// And they really were left live, which is why reporting matters.
	for name, raw := range map[string]string{
		"RevokeOwnedSession": ownerToken, "RevokeSession": sessionToken, "RevokeAllUserSessions": userToken,
	} {
		_, active, inspectErr := data.InspectRefreshToken(ctx, raw)
		if inspectErr != nil {
			t.Fatal(inspectErr)
		}
		if !active {
			t.Errorf("%s: the token was not actually left live, so this is not measuring what it claims", name)
		}
	}
	// The session rows went through, so the callers are reporting a partial
	// outcome rather than a failed one.
	for name, id := range map[string]uuid.UUID{
		"RevokeOwnedSession": byOwner, "RevokeSession": bySession, "RevokeAllUserSessions": byUser,
	} {
		var revoked bool
		if err := data.Pool.QueryRow(ctx,
			"SELECT revoked_at IS NOT NULL FROM sso_sessions WHERE id=$1", id).Scan(&revoked); err != nil {
			t.Fatal(err)
		}
		if !revoked {
			t.Errorf("%s: the session row was not revoked either", name)
		}
	}
}

// Disabling a provider is the third place an account stops being usable, and
// the only one that did not go through the call the other two share. It wrote
// the two revocations out by hand, discarded the outcome of each, and told no
// relying party — so it signed people out of ReSSO and left them signed in
// everywhere they had used it, while reporting a completed sign-out either way.
func TestIntegrationDisablingAProviderSignsItsPeopleOutEverywhere(t *testing.T) {
	directory := strings.TrimSpace(os.Getenv("RESSO_TEST_LDAP_URL"))
	if directory == "" {
		t.Skip("set RESSO_TEST_LDAP_URL to run federation tests")
	}
	data := openIntegrationStore(t, integrationSealer(t))
	bootstrap := bootstrapIntegrationStore(t, data)
	ctx := context.Background()
	realm, err := data.RealmByID(ctx, bootstrap.RealmID)
	if err != nil {
		t.Fatal(err)
	}
	branch := "ou=provider-disable,dc=example,dc=test"
	createDirectoryBranch(t, branch, "worker")
	credential := "adminpassword"
	input := LDAPFederationInput{
		Name: "corp", Vendor: "OTHER", ConnectionURL: directory,
		BindDN: "cn=admin,dc=example,dc=test", BindCredential: &credential,
		UsersDN: branch, UsernameLDAPAttribute: "uid", RDNLDAPAttribute: "uid",
		UUIDLDAPAttribute: "entryUUID", UserObjectClasses: []string{"inetOrgPerson"},
		SearchScope: "SUBTREE", BatchSize: 100, EditMode: "READ_ONLY", MissingUserAction: "KEEP",
		EmailLDAPAttribute: "mail", DisplayNameLDAPAttribute: "cn",
		ImportEnabled: true, Enabled: true,
	}
	provider, err := data.CreateLDAPFederation(ctx, realm.ID, input)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := data.SyncLDAPFederation(ctx, provider.ID); err != nil {
		t.Fatal(err)
	}
	people, err := data.ListUsers(ctx, realm.ID, "worker", UserSort{}, 5, 0)
	if err != nil || len(people) != 1 {
		t.Fatalf("imported users = %d (%v)", len(people), err)
	}
	worker := people[0]
	client, err := data.CreateClient(ctx, realm.ID, CreateClientInput{
		ClientID: "provider-rp", Name: "RP", Type: "confidential",
		RedirectURIs: []string{"https://rp.example.test/cb"},
		GrantTypes:   []string{"authorization_code", "refresh_token"}, DefaultScopes: []string{"openid"}})
	if err != nil {
		t.Fatal(err)
	}
	session, err := data.CreateSession(ctx, realm.ID, worker.ID, time.Hour, "127.0.0.1", "provider", "password")
	if err != nil {
		t.Fatal(err)
	}
	sessionID := session.Session.ID
	raw, err := data.CreateRefreshToken(ctx, RefreshToken{RealmID: realm.ID, ClientID: client.Client.ID,
		UserID: &worker.ID, SessionID: &sessionID, Scope: []string{"openid"},
		ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}

	var told []RevokedSession
	data.OnSessionRevoked = func(revoked RevokedSession) { told = append(told, revoked) }
	input.Enabled = false
	if _, err := data.UpdateLDAPFederation(ctx, provider.ID, input); err != nil {
		t.Fatal(err)
	}

	if len(told) != 1 || told[0].SessionID != sessionID {
		t.Errorf("relying parties told about the sign-out = %d, want the one open session", len(told))
	}
	var revoked bool
	if err := data.Pool.QueryRow(ctx,
		"SELECT revoked_at IS NOT NULL FROM sso_sessions WHERE id=$1", sessionID).Scan(&revoked); err != nil {
		t.Fatal(err)
	}
	if !revoked {
		t.Error("the session survived the provider being disabled")
	}
	if _, active, inspectErr := data.InspectRefreshToken(ctx, raw); inspectErr != nil || active {
		t.Errorf("the refresh token survived the provider being disabled: %v %v", active, inspectErr)
	}

	// And a sign-out that cannot finish is not reported as one that did.
	input.Enabled = true
	if _, err := data.UpdateLDAPFederation(ctx, provider.ID, input); err != nil {
		t.Fatal(err)
	}
	if _, err := data.Pool.Exec(ctx,
		"ALTER TABLE refresh_tokens RENAME COLUMN revoked_at TO revoked_at_moved"); err != nil {
		t.Fatal(err)
	}
	input.Enabled = false
	_, disableErr := data.UpdateLDAPFederation(ctx, provider.ID, input)
	if _, err := data.Pool.Exec(ctx,
		"ALTER TABLE refresh_tokens RENAME COLUMN revoked_at_moved TO revoked_at"); err != nil {
		t.Fatal(err)
	}
	if disableErr == nil {
		t.Error("a provider whose people could not be signed out reported a completed sign-out")
	}
}

// Unlinking a provider is the same act by another route: the accounts stop
// being usable, so the relying parties have to hear about it. It revoked the
// rows inside its transaction, discarded the outcome of each and told nobody.
func TestIntegrationUnlinkingAProviderSignsItsPeopleOutEverywhere(t *testing.T) {
	directory := strings.TrimSpace(os.Getenv("RESSO_TEST_LDAP_URL"))
	if directory == "" {
		t.Skip("set RESSO_TEST_LDAP_URL to run federation tests")
	}
	data := openIntegrationStore(t, integrationSealer(t))
	bootstrap := bootstrapIntegrationStore(t, data)
	ctx := context.Background()
	realm, err := data.RealmByID(ctx, bootstrap.RealmID)
	if err != nil {
		t.Fatal(err)
	}
	branch := "ou=provider-unlink,dc=example,dc=test"
	createDirectoryBranch(t, branch, "leaver")
	credential := "adminpassword"
	provider, err := data.CreateLDAPFederation(ctx, realm.ID, LDAPFederationInput{
		Name: "corp", Vendor: "OTHER", ConnectionURL: directory,
		BindDN: "cn=admin,dc=example,dc=test", BindCredential: &credential,
		UsersDN: branch, UsernameLDAPAttribute: "uid", RDNLDAPAttribute: "uid",
		UUIDLDAPAttribute: "entryUUID", UserObjectClasses: []string{"inetOrgPerson"},
		SearchScope: "SUBTREE", BatchSize: 100, EditMode: "READ_ONLY", MissingUserAction: "KEEP",
		EmailLDAPAttribute: "mail", DisplayNameLDAPAttribute: "cn",
		ImportEnabled: true, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := data.SyncLDAPFederation(ctx, provider.ID); err != nil {
		t.Fatal(err)
	}
	people, err := data.ListUsers(ctx, realm.ID, "leaver", UserSort{}, 5, 0)
	if err != nil || len(people) != 1 {
		t.Fatalf("imported users = %d (%v)", len(people), err)
	}
	leaver := people[0]
	client, err := data.CreateClient(ctx, realm.ID, CreateClientInput{
		ClientID: "unlink-rp", Name: "RP", Type: "confidential",
		RedirectURIs: []string{"https://rp.example.test/cb"},
		GrantTypes:   []string{"authorization_code", "refresh_token"}, DefaultScopes: []string{"openid"}})
	if err != nil {
		t.Fatal(err)
	}
	session, err := data.CreateSession(ctx, realm.ID, leaver.ID, time.Hour, "127.0.0.1", "unlink", "password")
	if err != nil {
		t.Fatal(err)
	}
	sessionID := session.Session.ID
	raw, err := data.CreateRefreshToken(ctx, RefreshToken{RealmID: realm.ID, ClientID: client.Client.ID,
		UserID: &leaver.ID, SessionID: &sessionID, Scope: []string{"openid"},
		ExpiresAt: time.Now().UTC().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}

	var told []RevokedSession
	data.OnSessionRevoked = func(revoked RevokedSession) { told = append(told, revoked) }
	if err := data.DeleteLDAPFederation(ctx, provider.ID, true); err != nil {
		t.Fatal(err)
	}

	if len(told) != 1 || told[0].SessionID != sessionID {
		t.Errorf("relying parties told about the sign-out = %d, want the one open session", len(told))
	}
	var revoked bool
	if err := data.Pool.QueryRow(ctx,
		"SELECT revoked_at IS NOT NULL FROM sso_sessions WHERE id=$1", sessionID).Scan(&revoked); err != nil {
		t.Fatal(err)
	}
	if !revoked {
		t.Error("the session survived the provider being unlinked")
	}
	if _, active, inspectErr := data.InspectRefreshToken(ctx, raw); inspectErr != nil || active {
		t.Errorf("the refresh token survived the provider being unlinked: %v %v", active, inspectErr)
	}
	// The unlink itself still did its job.
	unlinked, err := data.UserByID(ctx, leaver.ID)
	if err != nil {
		t.Fatal(err)
	}
	if unlinked.Enabled || unlinked.FederationID != nil {
		t.Errorf("the account was not unlinked and disabled: enabled=%v federation=%v",
			unlinked.Enabled, unlinked.FederationID)
	}
}

// Rotating the data encryption keyring means rewrapping everything sealed with
// the old key and then removing that key. A sealed column the rewrap does not
// know about survives the rotation still on the old key, and the moment the
// operator completes the documented procedure by removing it, that data cannot
// be read again — a signing key that no longer opens takes its Realm's token
// issuance with it, and a bind credential takes the directory connection.
//
// The rewrap reports success either way, because it only reports what it
// visited. So the guard is that it visits everything: the schema is asked which
// columns hold sealed values, rather than trusting a list written beside the
// code that seals them. docs/operations.md names the same two under
// "Data Encryption·Digest Keyring 회전", and tells the operator to remove the
// old key once rewrap reports success.
func TestIntegrationRewrapCoversEveryEncryptedColumn(t *testing.T) {
	data := openIntegrationStore(t, integrationSealer(t))
	ctx := context.Background()
	rows, err := data.Pool.Query(ctx, `SELECT table_name,column_name FROM information_schema.columns
		WHERE table_schema=current_schema() AND data_type='bytea' AND column_name LIKE '%\_cipher'
		ORDER BY table_name,column_name`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	found := map[string]bool{}
	for rows.Next() {
		var table, column string
		if err := rows.Scan(&table, &column); err != nil {
			t.Fatal(err)
		}
		found[table+"."+column] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}

	// What RewrapEncryptedSecrets reads and writes.
	rewrapped := map[string]bool{
		"signing_keys.private_key_cipher":         true,
		"user_federations.bind_credential_cipher": true,
	}
	if len(found) == 0 {
		t.Fatal("the schema holds no sealed columns, so this guard is checking nothing")
	}
	for column := range found {
		if !rewrapped[column] {
			t.Errorf("%s holds sealed values that RewrapEncryptedSecrets does not rewrap; "+
				"a keyring rotation would leave it on the removed key", column)
		}
	}
	for column := range rewrapped {
		if !found[column] {
			t.Errorf("RewrapEncryptedSecrets rewraps %s, which the schema no longer has", column)
		}
	}
}

// Signing the provider's people out happens after the change has landed, so it
// can fall short on its own. Reported as a failed request it would describe a
// change that happened as one that did not: the provider really is disabled,
// or really is gone with its accounts unlinked.
func TestIntegrationAProviderChangeThatCannotSignPeopleOutSaysSo(t *testing.T) {
	directory := strings.TrimSpace(os.Getenv("RESSO_TEST_LDAP_URL"))
	if directory == "" {
		t.Skip("set RESSO_TEST_LDAP_URL to run federation tests")
	}
	data := openIntegrationStore(t, integrationSealer(t))
	bootstrap := bootstrapIntegrationStore(t, data)
	ctx := context.Background()
	realm, err := data.RealmByID(ctx, bootstrap.RealmID)
	if err != nil {
		t.Fatal(err)
	}
	branch := "ou=partial-signout,dc=example,dc=test"
	createDirectoryBranch(t, branch, "worker")
	credential := "adminpassword"
	input := LDAPFederationInput{
		Name: "corp", Vendor: "OTHER", ConnectionURL: directory,
		BindDN: "cn=admin,dc=example,dc=test", BindCredential: &credential,
		UsersDN: branch, UsernameLDAPAttribute: "uid", RDNLDAPAttribute: "uid",
		UUIDLDAPAttribute: "entryUUID", UserObjectClasses: []string{"inetOrgPerson"},
		SearchScope: "SUBTREE", BatchSize: 100, EditMode: "READ_ONLY", MissingUserAction: "KEEP",
		EmailLDAPAttribute: "mail", DisplayNameLDAPAttribute: "cn",
		ImportEnabled: true, Enabled: true,
	}
	provider, err := data.CreateLDAPFederation(ctx, realm.ID, input)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := data.SyncLDAPFederation(ctx, provider.ID); err != nil {
		t.Fatal(err)
	}

	if _, err := data.Pool.Exec(ctx,
		"ALTER TABLE refresh_tokens RENAME COLUMN revoked_at TO revoked_at_moved"); err != nil {
		t.Fatal(err)
	}
	restored := false
	restore := func() {
		if restored {
			return
		}
		restored = true
		if _, err := data.Pool.Exec(context.Background(),
			"ALTER TABLE refresh_tokens RENAME COLUMN revoked_at_moved TO revoked_at"); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(restore)

	input.Enabled = false
	updated, updateErr := data.UpdateLDAPFederation(ctx, provider.ID, input)
	if !errors.Is(updateErr, ErrUsersNotSignedOut) {
		t.Fatalf("disabling reported %v, want it to name the sign-out that fell short", updateErr)
	}
	// The change itself landed, and the caller is handed it.
	if updated.Enabled {
		t.Error("the returned provider is still enabled, so the caller cannot see what happened")
	}
	stored, err := data.LDAPFederationByID(ctx, provider.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Enabled {
		t.Error("the provider was not disabled, so this is not measuring what it claims")
	}

	deleteErr := data.DeleteLDAPFederation(ctx, provider.ID, true)
	if !errors.Is(deleteErr, ErrUsersNotSignedOut) {
		t.Fatalf("unlinking reported %v, want it to name the sign-out that fell short", deleteErr)
	}
	restore()
	if _, err := data.LDAPFederationByID(ctx, provider.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("the provider survived a delete that reported only the sign-out: %v", err)
	}
	// A conflict still has to be its own answer, or the caller is told to
	// clear the imported users when that was never the problem.
	if !errors.Is(deleteErr, ErrConflict) {
		return
	}
	t.Error("a sign-out shortfall was reported as a conflict")
}
