package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/hkjang/ReSSO/internal/config"
	"github.com/hkjang/ReSSO/internal/password"
)

type BootstrapResult struct {
	RealmID     uuid.UUID
	AdminUserID uuid.UUID
	Created     bool
}

// Bootstrap is idempotent. It never resets an existing administrator's
// password, which prevents a container restart from becoming a password
// reset mechanism.
func (s *Store) Bootstrap(ctx context.Context, adminUsername, adminPassword string) (BootstrapResult, error) {
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return BootstrapResult{}, fmt.Errorf("begin bootstrap: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var result BootstrapResult
	err = tx.QueryRow(ctx, "SELECT id FROM realms WHERE name=$1", config.DefaultBootstrapRealm).Scan(&result.RealmID)
	if errors.Is(err, pgx.ErrNoRows) {
		result.RealmID = uuid.New()
		_, err = tx.Exec(ctx, `INSERT INTO realms(id,name,display_name,issuer_url)
            VALUES($1,$2,$3,$4)`, result.RealmID, config.DefaultBootstrapRealm, "ReSSO Master", config.DefaultBootstrapIssuer)
	}
	if err != nil {
		return BootstrapResult{}, fmt.Errorf("ensure master realm: %w", err)
	}

	err = tx.QueryRow(ctx, `SELECT id FROM users
        WHERE realm_id=$1 AND username=$2`, result.RealmID, adminUsername).Scan(&result.AdminUserID)
	if errors.Is(err, pgx.ErrNoRows) {
		hashed, hashErr := password.HashContext(ctx, adminPassword)
		if hashErr != nil {
			return BootstrapResult{}, hashErr
		}
		result.AdminUserID = uuid.New()
		_, err = tx.Exec(ctx, `INSERT INTO users(
			id,realm_id,username,email,email_verified,display_name,password_hash,platform_admin,password_changed_at)
			VALUES($1,$2,$3,'',false,$4,$5,true,$6)`, result.AdminUserID, result.RealmID,
			adminUsername, "Bootstrap Administrator", hashed, time.Now().UTC())
		result.Created = err == nil
	}
	if err != nil {
		return BootstrapResult{}, fmt.Errorf("ensure bootstrap administrator: %w", err)
	}
	// The privileges are granted with the account and not re-applied after
	// that. This used to run on every start, so a restart undid an
	// administrator's decisions: an operator who disabled the bootstrap
	// account after creating named administrators — ordinary practice — found
	// it enabled again, with its original password, the next time the
	// container came up, and nothing said so. Revoking platform_admin came
	// back the same way.
	//
	// It also meant that pointing BOOTSTRAP_ADMIN at the name of an existing
	// ordinary user promoted them to platform administrator on the next start.
	//
	// Getting back in when the last administrator is locked out is what
	// `admin recover` is for: it is deliberate, it is audited, and it revokes
	// the sessions and keys of the account it restores.
	if result.Created {
		if _, err := tx.Exec(ctx, `UPDATE users SET platform_admin=true, enabled=true
	        WHERE id=$1`, result.AdminUserID); err != nil {
			return BootstrapResult{}, fmt.Errorf("ensure bootstrap privileges: %w", err)
		}
	}

	for _, role := range []struct{ name, description string }{
		{"user", "Default authenticated user"},
		{"realm-admin", "Realm administration"},
		{"offline_access", "Long-lived offline access eligibility"},
	} {
		_, err := tx.Exec(ctx, `INSERT INTO roles(id,realm_id,name,description)
            VALUES($1,$2,$3,$4) ON CONFLICT(realm_id,name) DO NOTHING`, uuid.New(), result.RealmID, role.name, role.description)
		if err != nil {
			return BootstrapResult{}, fmt.Errorf("ensure built-in role %s: %w", role.name, err)
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO user_roles(user_id,role_id)
        SELECT $1,id FROM roles WHERE realm_id=$2 AND name='realm-admin'
        ON CONFLICT DO NOTHING`, result.AdminUserID, result.RealmID); err != nil {
		return BootstrapResult{}, fmt.Errorf("assign bootstrap role: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return BootstrapResult{}, fmt.Errorf("commit bootstrap: %w", err)
	}
	return result, nil
}
