package store

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hkjang/ReSSO/internal/cryptoutil"
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
	legitimate, err := data.CreateRoleApprovalRequest(ctx, alice, role.ID, "still need it")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := data.DecideApprovalRequest(ctx, legitimate.ID, lead.ID, false, false, uuid.Nil, true, "ok"); err != nil {
		t.Fatalf("a manager could not approve their report's request: %v", err)
	}
	if err := data.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM user_roles WHERE user_id=$1 AND role_id=$2)`,
		alice.ID, role.ID).Scan(&granted); err != nil {
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
