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
