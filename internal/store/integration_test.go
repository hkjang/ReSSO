package store

import (
	"bytes"
	"context"
	"errors"
	"os"
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
		case errors.Is(redeemErr, ErrNotFound):
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
	if _, _, err := data.RotateRefreshToken(context.Background(), raw, nil); !errors.Is(err, ErrTokenReuse) {
		t.Fatalf("reuse error = %v, want ErrTokenReuse", err)
	}
	if _, active, err := data.InspectRefreshToken(context.Background(), rotatedRaw); err != nil || active {
		t.Fatalf("rotated family member remained active: active=%v err=%v", active, err)
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
	if len(diagnosis.AppliedMigrations) != 2 {
		t.Fatalf("applied migrations = %v", diagnosis.AppliedMigrations)
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
	if err := Migrate(ctx, pool); err != nil {
		pool.Close()
		admin.Close()
		t.Fatal(err)
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
