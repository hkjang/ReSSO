package store

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/hkjang/ReSSO/internal/config"
	"github.com/hkjang/ReSSO/internal/password"
)

type RewrapResult struct {
	PrimaryKeyID     string `json:"primary_key_id"`
	SigningKeys      int    `json:"signing_keys"`
	LDAPCredentials  int    `json:"ldap_credentials"`
	AlreadyOnPrimary int    `json:"already_on_primary"`
}

// RewrapEncryptedSecrets verifies every encrypted database value and rewrites
// legacy/non-primary envelopes with the active data-encryption key.
func (s *Store) RewrapEncryptedSecrets(ctx context.Context) (RewrapResult, error) {
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return RewrapResult{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	type encryptedValue struct {
		kind, id, secondary string
		realmID             uuid.UUID
		cipher              []byte
	}
	values := make([]encryptedValue, 0)
	rows, err := tx.Query(ctx, `SELECT id::text,realm_id,kid,private_key_cipher FROM signing_keys FOR UPDATE`)
	if err != nil {
		return RewrapResult{}, err
	}
	for rows.Next() {
		var value encryptedValue
		value.kind = "signing_key"
		if err := rows.Scan(&value.id, &value.realmID, &value.secondary, &value.cipher); err != nil {
			rows.Close()
			return RewrapResult{}, err
		}
		values = append(values, value)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return RewrapResult{}, err
	}
	rows, err = tx.Query(ctx, `SELECT id::text,realm_id,bind_credential_cipher FROM user_federations
		WHERE bind_credential_cipher IS NOT NULL FOR UPDATE`)
	if err != nil {
		return RewrapResult{}, err
	}
	for rows.Next() {
		var value encryptedValue
		value.kind = "ldap_credential"
		if err := rows.Scan(&value.id, &value.realmID, &value.cipher); err != nil {
			rows.Close()
			return RewrapResult{}, err
		}
		values = append(values, value)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return RewrapResult{}, err
	}

	result := RewrapResult{PrimaryKeyID: s.Sealer.PrimaryEncryptionKeyID()}
	for _, value := range values {
		id, parseErr := uuid.Parse(value.id)
		if parseErr != nil {
			return RewrapResult{}, parseErr
		}
		var aad []byte
		if value.kind == "signing_key" {
			aad = keyAAD(value.realmID, value.secondary)
		} else {
			aad = ldapCredentialAAD(id)
		}
		plaintext, openErr := s.Sealer.Open(value.cipher, aad)
		if openErr != nil {
			return RewrapResult{}, fmt.Errorf("verify %s %s: %w", value.kind, value.id, openErr)
		}
		needs, inspectErr := s.Sealer.NeedsRewrap(value.cipher)
		if inspectErr != nil {
			return RewrapResult{}, fmt.Errorf("inspect %s %s: %w", value.kind, value.id, inspectErr)
		}
		if !needs {
			result.AlreadyOnPrimary++
			continue
		}
		rewrapped, sealErr := s.Sealer.Seal(plaintext, aad)
		if sealErr != nil {
			return RewrapResult{}, fmt.Errorf("rewrap %s %s: %w", value.kind, value.id, sealErr)
		}
		if value.kind == "signing_key" {
			if _, err := tx.Exec(ctx, `UPDATE signing_keys SET private_key_cipher=$2 WHERE id=$1`, id, rewrapped); err != nil {
				return RewrapResult{}, err
			}
			result.SigningKeys++
		} else {
			if _, err := tx.Exec(ctx, `UPDATE user_federations SET bind_credential_cipher=$2,
				updated_at=now() WHERE id=$1`, id, rewrapped); err != nil {
				return RewrapResult{}, err
			}
			result.LDAPCredentials++
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return RewrapResult{}, err
	}
	return result, nil
}

type RecoveryResult struct {
	UserID                   uuid.UUID `json:"user_id"`
	Username                 string    `json:"username"`
	Created                  bool      `json:"created"`
	SessionsRevoked          int64     `json:"sessions_revoked"`
	APIKeysRevoked           int64     `json:"api_keys_revoked"`
	LoginFailureBucketsReset int64     `json:"login_failure_buckets_reset"`
}

// RecoverPlatformAdmin creates or resets a local break-glass administrator.
// Federated identities are never converted implicitly.
func (s *Store) RecoverPlatformAdmin(ctx context.Context, username, replacement string) (RecoveryResult, error) {
	username = strings.TrimSpace(username)
	if username == "" || len([]rune(username)) > 128 || strings.ContainsAny(username, "\x00\r\n\t /\\") {
		return RecoveryResult{}, errors.New("recovery username is invalid")
	}
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return RecoveryResult{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var realmID uuid.UUID
	var minimum int
	if err := tx.QueryRow(ctx, `SELECT id,password_min_length FROM realms WHERE name=$1 FOR UPDATE`,
		config.DefaultBootstrapRealm).Scan(&realmID, &minimum); err != nil {
		return RecoveryResult{}, fmt.Errorf("load master Realm: %w", err)
	}
	if len([]rune(replacement)) < minimum || len([]rune(replacement)) > 1024 {
		return RecoveryResult{}, fmt.Errorf("recovery password must contain between %d and 1024 characters", minimum)
	}
	hashed, err := password.Hash(replacement)
	if err != nil {
		return RecoveryResult{}, err
	}
	result := RecoveryResult{Username: username}
	var federationID *uuid.UUID
	err = tx.QueryRow(ctx, `SELECT id,federation_id,username FROM users
		WHERE realm_id=$1 AND lower(username)=lower($2) FOR UPDATE`, realmID, username).
		Scan(&result.UserID, &federationID, &result.Username)
	if errors.Is(err, pgx.ErrNoRows) {
		result.UserID = uuid.New()
		result.Created = true
		result.Username = username
		_, err = tx.Exec(ctx, `INSERT INTO users(id,realm_id,username,email,email_verified,display_name,
			password_hash,enabled,platform_admin,password_changed_at)
			VALUES($1,$2,$3,'',false,'Recovery Administrator',$4,true,true,now())`,
			result.UserID, realmID, username, hashed)
	}
	if err != nil {
		return RecoveryResult{}, fmt.Errorf("load or create recovery administrator: %w", err)
	}
	if federationID != nil {
		return RecoveryResult{}, errors.New("refusing to convert a federated identity; choose a new local username")
	}
	if !result.Created {
		if _, err := tx.Exec(ctx, `UPDATE users SET password_hash=$2,enabled=true,platform_admin=true,
			failed_attempts=0,locked_until=NULL,password_changed_at=now(),updated_at=now() WHERE id=$1`,
			result.UserID, hashed); err != nil {
			return RecoveryResult{}, err
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO user_roles(user_id,role_id)
		SELECT $1,id FROM roles WHERE realm_id=$2 AND name='realm-admin' ON CONFLICT DO NOTHING`,
		result.UserID, realmID); err != nil {
		return RecoveryResult{}, err
	}
	accountBucket := "login/account/" + realmID.String() + "/" + strings.ToLower(result.Username)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, rateLimitLockID(accountBucket)); err != nil {
		return RecoveryResult{}, err
	}
	command, err := tx.Exec(ctx, `DELETE FROM login_rate_limits WHERE bucket_hash=ANY($1::bytea[])`,
		s.Sealer.Digests(accountBucket))
	if err != nil {
		return RecoveryResult{}, err
	}
	result.LoginFailureBucketsReset = command.RowsAffected()
	command, err = tx.Exec(ctx, `UPDATE sso_sessions SET revoked_at=COALESCE(revoked_at,now())
		WHERE user_id=$1 AND revoked_at IS NULL`, result.UserID)
	if err != nil {
		return RecoveryResult{}, err
	}
	result.SessionsRevoked = command.RowsAffected()
	if _, err := tx.Exec(ctx, `UPDATE refresh_tokens SET revoked_at=COALESCE(revoked_at,now())
		WHERE user_id=$1 AND revoked_at IS NULL`, result.UserID); err != nil {
		return RecoveryResult{}, err
	}
	command, err = tx.Exec(ctx, `UPDATE personal_api_keys SET revoked_at=COALESCE(revoked_at,now())
		WHERE user_id=$1 AND revoked_at IS NULL`, result.UserID)
	if err != nil {
		return RecoveryResult{}, err
	}
	result.APIKeysRevoked = command.RowsAffected()
	if _, err := tx.Exec(ctx, `INSERT INTO audit_events(realm_id,actor_name,event_type,result,target_type,
		target_id,detail) VALUES($1,'recovery-cli','PLATFORM_ADMIN_RECOVERY','SUCCESS','user',$2,
		jsonb_build_object('created',$3::boolean,'sessions_revoked',$4::bigint,'api_keys_revoked',$5::bigint,
			'login_failure_buckets_reset',$6::bigint))`, realmID, result.UserID.String(), result.Created,
		result.SessionsRevoked, result.APIKeysRevoked, result.LoginFailureBucketsReset); err != nil {
		return RecoveryResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return RecoveryResult{}, err
	}
	return result, nil
}

type RecoveryDiagnosis struct {
	DatabaseReady                bool     `json:"database_ready"`
	AppliedMigrations            []string `json:"applied_migrations"`
	RealmCount                   int      `json:"realm_count"`
	PlatformAdminCount           int      `json:"platform_admin_count"`
	ActiveSigningKeyCount        int      `json:"active_signing_key_count"`
	LDAPCredentialCount          int      `json:"ldap_credential_count"`
	EncryptedValuesVerified      int      `json:"encrypted_values_verified"`
	EncryptedValuesNeedingRewrap int      `json:"encrypted_values_needing_rewrap"`
	PrimaryEncryptionKeyID       string   `json:"primary_encryption_key_id"`
}

func (s *Store) DiagnoseRecovery(ctx context.Context) (RecoveryDiagnosis, error) {
	result := RecoveryDiagnosis{
		AppliedMigrations:      make([]string, 0),
		PrimaryEncryptionKeyID: s.Sealer.PrimaryEncryptionKeyID(),
	}
	var migrationTableExists bool
	if err := s.Pool.QueryRow(ctx, `SELECT to_regclass('schema_migrations') IS NOT NULL`).Scan(&migrationTableExists); err != nil {
		return RecoveryDiagnosis{}, err
	}
	if !migrationTableExists {
		return result, nil
	}
	rows, err := s.Pool.Query(ctx, `SELECT version FROM schema_migrations ORDER BY version`)
	if err != nil {
		return RecoveryDiagnosis{}, err
	}
	for rows.Next() {
		var version string
		if err := rows.Scan(&version); err != nil {
			rows.Close()
			return RecoveryDiagnosis{}, err
		}
		result.AppliedMigrations = append(result.AppliedMigrations, version)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return RecoveryDiagnosis{}, err
	}
	applied := make(map[string]bool, len(result.AppliedMigrations))
	for _, version := range result.AppliedMigrations {
		applied[version] = true
	}
	entries, err := fs.ReadDir(migrationFiles, "migrations")
	if err != nil {
		return RecoveryDiagnosis{}, fmt.Errorf("read embedded migrations: %w", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".sql") && !applied[entry.Name()] {
			return result, nil
		}
	}
	var requiredTablesExist bool
	if err := s.Pool.QueryRow(ctx, `SELECT
		to_regclass('realms') IS NOT NULL AND
		to_regclass('users') IS NOT NULL AND
		to_regclass('signing_keys') IS NOT NULL AND
		to_regclass('user_federations') IS NOT NULL`).Scan(&requiredTablesExist); err != nil {
		return RecoveryDiagnosis{}, err
	}
	if !requiredTablesExist {
		return result, nil
	}
	result.DatabaseReady = true
	if err := s.Pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM realms),
		(SELECT count(*) FROM users WHERE platform_admin=true AND enabled=true),
		(SELECT count(*) FROM signing_keys WHERE status='ACTIVE'),
		(SELECT count(*) FROM user_federations WHERE bind_credential_cipher IS NOT NULL)`).
		Scan(&result.RealmCount, &result.PlatformAdminCount, &result.ActiveSigningKeyCount,
			&result.LDAPCredentialCount); err != nil {
		return RecoveryDiagnosis{}, err
	}
	rows, err = s.Pool.Query(ctx, `SELECT realm_id,kid,private_key_cipher FROM signing_keys`)
	if err != nil {
		return RecoveryDiagnosis{}, err
	}
	for rows.Next() {
		var realmID uuid.UUID
		var kid string
		var encrypted []byte
		if err := rows.Scan(&realmID, &kid, &encrypted); err != nil {
			rows.Close()
			return RecoveryDiagnosis{}, err
		}
		if _, err := s.Sealer.Open(encrypted, keyAAD(realmID, kid)); err != nil {
			rows.Close()
			return RecoveryDiagnosis{}, fmt.Errorf("signing key %s is unreadable: %w", kid, err)
		}
		result.EncryptedValuesVerified++
		if needs, err := s.Sealer.NeedsRewrap(encrypted); err != nil {
			rows.Close()
			return RecoveryDiagnosis{}, fmt.Errorf("inspect signing key %s: %w", kid, err)
		} else if needs {
			result.EncryptedValuesNeedingRewrap++
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return RecoveryDiagnosis{}, err
	}
	rows, err = s.Pool.Query(ctx, `SELECT id,bind_credential_cipher FROM user_federations
		WHERE bind_credential_cipher IS NOT NULL`)
	if err != nil {
		return RecoveryDiagnosis{}, err
	}
	for rows.Next() {
		var id uuid.UUID
		var encrypted []byte
		if err := rows.Scan(&id, &encrypted); err != nil {
			rows.Close()
			return RecoveryDiagnosis{}, err
		}
		if _, err := s.Sealer.Open(encrypted, ldapCredentialAAD(id)); err != nil {
			rows.Close()
			return RecoveryDiagnosis{}, fmt.Errorf("LDAP credential %s is unreadable: %w", id, err)
		}
		result.EncryptedValuesVerified++
		if needs, err := s.Sealer.NeedsRewrap(encrypted); err != nil {
			rows.Close()
			return RecoveryDiagnosis{}, fmt.Errorf("inspect LDAP credential %s: %w", id, err)
		} else if needs {
			result.EncryptedValuesNeedingRewrap++
		}
	}
	rows.Close()
	return result, rows.Err()
}
