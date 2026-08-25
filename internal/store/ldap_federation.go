package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/hkjang/ReSSO/internal/domain"
	"github.com/hkjang/ReSSO/internal/federation"
	"github.com/hkjang/ReSSO/internal/password"
)

var ldapFederationColumns = `id,realm_id,name,vendor,priority,enabled,connection_url,start_tls,
    ca_certificate,bind_dn,bind_credential_cipher,users_dn,username_ldap_attribute,rdn_ldap_attribute,
    uuid_ldap_attribute,user_object_classes,user_ldap_filter,search_scope,email_ldap_attribute,
    first_name_ldap_attribute,last_name_ldap_attribute,display_name_ldap_attribute,member_of_ldap_attribute,
    group_role_mappings,import_enabled,sync_registrations,missing_user_action,edit_mode,batch_size,
    sync_period_seconds,next_sync_at,last_sync_at,last_sync_status,last_sync_error,last_sync_added,
    last_sync_updated,last_sync_failed,last_sync_disabled,
    (last_sync_status='RUNNING' AND updated_at >= now()-make_interval(secs => ` + staleSyncAfterSeconds + `)),
    created_at,updated_at`

// staleSyncAfterSeconds carries staleSyncAfter into the column list so the
// listed answer and the guard that refuses a second run cannot drift apart.
var staleSyncAfterSeconds = strconv.Itoa(int(staleSyncAfter.Seconds()))

type LDAPFederationInput struct {
	Name                     string            `json:"name"`
	Vendor                   string            `json:"vendor"`
	Priority                 int               `json:"priority"`
	Enabled                  bool              `json:"enabled"`
	ConnectionURL            string            `json:"connection_url"`
	StartTLS                 bool              `json:"start_tls"`
	CACertificate            string            `json:"ca_certificate"`
	BindDN                   string            `json:"bind_dn"`
	BindCredential           *string           `json:"bind_credential,omitempty"`
	ClearBindCredential      bool              `json:"clear_bind_credential,omitempty"`
	UsersDN                  string            `json:"users_dn"`
	UsernameLDAPAttribute    string            `json:"username_ldap_attribute"`
	RDNLDAPAttribute         string            `json:"rdn_ldap_attribute"`
	UUIDLDAPAttribute        string            `json:"uuid_ldap_attribute"`
	UserObjectClasses        []string          `json:"user_object_classes"`
	UserLDAPFilter           string            `json:"user_ldap_filter"`
	SearchScope              string            `json:"search_scope"`
	EmailLDAPAttribute       string            `json:"email_ldap_attribute"`
	FirstNameLDAPAttribute   string            `json:"first_name_ldap_attribute"`
	LastNameLDAPAttribute    string            `json:"last_name_ldap_attribute"`
	DisplayNameLDAPAttribute string            `json:"display_name_ldap_attribute"`
	MemberOfLDAPAttribute    string            `json:"member_of_ldap_attribute"`
	GroupRoleMappings        map[string]string `json:"group_role_mappings"`
	ImportEnabled            bool              `json:"import_enabled"`
	SyncRegistrations        bool              `json:"sync_registrations"`
	MissingUserAction        string            `json:"missing_user_action"`
	EditMode                 string            `json:"edit_mode"`
	BatchSize                int               `json:"batch_size"`
	SyncPeriodSeconds        int               `json:"sync_period_seconds"`
}

type LDAPSyncSummary struct {
	FederationID uuid.UUID `json:"federation_id"`
	StartedAt    time.Time `json:"started_at"`
	CompletedAt  time.Time `json:"completed_at"`
	Read         int       `json:"read"`
	Added        int       `json:"added"`
	Updated      int       `json:"updated"`
	Failed       int       `json:"failed"`
	Disabled     int64     `json:"disabled"`
	// Failures names the users a run could not synchronize and why, up to
	// namedSyncFailures of them. The count alone could not be acted on: the
	// reason is known where it happens — a username already held by a local
	// account, an address this Realm cannot store — and was discarded, leaving
	// the operator a number and no way to learn which users or what to fix.
	Failures []string `json:"failures,omitempty"`
	// RecordError reports that the run finished but its outcome did not reach
	// the provider row or the audit trail. Both writes used to be issued and
	// discarded, so a sweep that deactivated accounts could return success
	// while the console still showed the previous run and the trail held no
	// entry for this one — and the trail is where an operator is told to look
	// to find out whether a DISABLE policy acted on them.
	RecordError string `json:"record_error,omitempty"`
}

type LDAPAuthenticationTestResult struct {
	Username    string `json:"username"`
	DN          string `json:"dn"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
}

type ldapRuntime struct {
	Provider       domain.LDAPFederation
	BindCredential string
}

func (s *Store) scanLDAPFederation(row pgx.Row) (ldapRuntime, error) {
	var runtime ldapRuntime
	var cipher []byte
	var mappings []byte
	err := row.Scan(&runtime.Provider.ID, &runtime.Provider.RealmID, &runtime.Provider.Name,
		&runtime.Provider.Vendor, &runtime.Provider.Priority, &runtime.Provider.Enabled,
		&runtime.Provider.ConnectionURL, &runtime.Provider.StartTLS, &runtime.Provider.CACertificate,
		&runtime.Provider.BindDN, &cipher, &runtime.Provider.UsersDN, &runtime.Provider.UsernameLDAPAttribute,
		&runtime.Provider.RDNLDAPAttribute, &runtime.Provider.UUIDLDAPAttribute, &runtime.Provider.UserObjectClasses,
		&runtime.Provider.UserLDAPFilter, &runtime.Provider.SearchScope, &runtime.Provider.EmailLDAPAttribute,
		&runtime.Provider.FirstNameLDAPAttribute, &runtime.Provider.LastNameLDAPAttribute,
		&runtime.Provider.DisplayNameLDAPAttribute, &runtime.Provider.MemberOfLDAPAttribute, &mappings,
		&runtime.Provider.ImportEnabled, &runtime.Provider.SyncRegistrations, &runtime.Provider.MissingUserAction,
		&runtime.Provider.EditMode, &runtime.Provider.BatchSize, &runtime.Provider.SyncPeriodSeconds,
		&runtime.Provider.NextSyncAt, &runtime.Provider.LastSyncAt, &runtime.Provider.LastSyncStatus,
		&runtime.Provider.LastSyncError, &runtime.Provider.LastSyncAdded, &runtime.Provider.LastSyncUpdated,
		&runtime.Provider.LastSyncFailed, &runtime.Provider.LastSyncDisabled, &runtime.Provider.SyncRunning,
		&runtime.Provider.CreatedAt, &runtime.Provider.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ldapRuntime{}, ErrNotFound
	}
	if err != nil {
		return ldapRuntime{}, err
	}
	runtime.Provider.BindCredentialSet = len(cipher) > 0
	runtime.Provider.GroupRoleMappings = map[string]string{}
	if len(mappings) > 0 {
		if err := json.Unmarshal(mappings, &runtime.Provider.GroupRoleMappings); err != nil {
			return ldapRuntime{}, fmt.Errorf("decode LDAP group role mappings: %w", err)
		}
	}
	if len(cipher) > 0 {
		plaintext, err := s.Sealer.Open(cipher, ldapCredentialAAD(runtime.Provider.ID))
		if err != nil {
			return ldapRuntime{}, fmt.Errorf("decrypt LDAP bind credential: %w", err)
		}
		runtime.BindCredential = string(plaintext)
	}
	return runtime, nil
}

func ldapCredentialAAD(id uuid.UUID) []byte {
	return []byte("ReSSO LDAP bind credential v1:" + id.String())
}

func (s *Store) LDAPFederationByID(ctx context.Context, id uuid.UUID) (domain.LDAPFederation, error) {
	runtime, err := s.ldapRuntimeByID(ctx, id)
	return runtime.Provider, err
}

func (s *Store) ldapRuntimeByID(ctx context.Context, id uuid.UUID) (ldapRuntime, error) {
	return s.scanLDAPFederation(s.Pool.QueryRow(ctx, "SELECT "+ldapFederationColumns+" FROM user_federations WHERE id=$1", id))
}

func (s *Store) ListLDAPFederations(ctx context.Context, realmID uuid.UUID) ([]domain.LDAPFederation, error) {
	rows, err := s.Pool.Query(ctx, "SELECT "+ldapFederationColumns+` FROM user_federations
        WHERE realm_id=$1 ORDER BY priority,name`, realmID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]domain.LDAPFederation, 0)
	for rows.Next() {
		runtime, err := s.scanLDAPFederation(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, runtime.Provider)
	}
	return items, rows.Err()
}

func (s *Store) CreateLDAPFederation(ctx context.Context, realmID uuid.UUID, input LDAPFederationInput) (domain.LDAPFederation, error) {
	id := uuid.New()
	provider, credential, err := normalizeLDAPInput(id, realmID, input, "", true)
	if err != nil {
		return domain.LDAPFederation{}, err
	}
	var cipher []byte
	if credential != "" {
		cipher, err = s.Sealer.Seal([]byte(credential), ldapCredentialAAD(id))
		if err != nil {
			return domain.LDAPFederation{}, err
		}
	}
	mappings, _ := json.Marshal(provider.GroupRoleMappings)
	_, err = s.Pool.Exec(ctx, `INSERT INTO user_federations(id,realm_id,name,vendor,priority,enabled,
        connection_url,start_tls,ca_certificate,bind_dn,bind_credential_cipher,users_dn,
        username_ldap_attribute,rdn_ldap_attribute,uuid_ldap_attribute,user_object_classes,user_ldap_filter,
        search_scope,email_ldap_attribute,first_name_ldap_attribute,last_name_ldap_attribute,
        display_name_ldap_attribute,member_of_ldap_attribute,group_role_mappings,import_enabled,
        sync_registrations,missing_user_action,edit_mode,batch_size,sync_period_seconds,next_sync_at)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,
        $23,$24,$25,$26,$27,$28,$29,$30,CASE WHEN $30>0 THEN now()+make_interval(secs=>$30) END)`,
		id, realmID, provider.Name, provider.Vendor, provider.Priority, provider.Enabled, provider.ConnectionURL,
		provider.StartTLS, provider.CACertificate, provider.BindDN, cipher, provider.UsersDN,
		provider.UsernameLDAPAttribute, provider.RDNLDAPAttribute, provider.UUIDLDAPAttribute,
		provider.UserObjectClasses, provider.UserLDAPFilter, provider.SearchScope, provider.EmailLDAPAttribute,
		provider.FirstNameLDAPAttribute, provider.LastNameLDAPAttribute, provider.DisplayNameLDAPAttribute,
		provider.MemberOfLDAPAttribute, mappings, provider.ImportEnabled, provider.SyncRegistrations,
		provider.MissingUserAction, provider.EditMode, provider.BatchSize, provider.SyncPeriodSeconds)
	if err != nil {
		if conflict, taken := conflictFromUnique(err); taken {
			return domain.LDAPFederation{}, conflict
		}
		return domain.LDAPFederation{}, fmt.Errorf("create LDAP federation: %w", err)
	}
	return s.LDAPFederationByID(ctx, id)
}

func (s *Store) UpdateLDAPFederation(ctx context.Context, id uuid.UUID, input LDAPFederationInput) (domain.LDAPFederation, error) {
	current, err := s.ldapRuntimeByID(ctx, id)
	if err != nil {
		return domain.LDAPFederation{}, err
	}
	credential := current.BindCredential
	if input.ClearBindCredential {
		credential = ""
	} else if input.BindCredential != nil {
		credential = *input.BindCredential
	}
	provider, credential, err := normalizeLDAPInput(id, current.Provider.RealmID, input, credential, false)
	if err != nil {
		return domain.LDAPFederation{}, err
	}
	var cipher []byte
	if credential != "" {
		cipher, err = s.Sealer.Seal([]byte(credential), ldapCredentialAAD(id))
		if err != nil {
			return domain.LDAPFederation{}, err
		}
	}
	mappings, _ := json.Marshal(provider.GroupRoleMappings)
	command, err := s.Pool.Exec(ctx, `UPDATE user_federations SET name=$2,vendor=$3,priority=$4,enabled=$5,
        connection_url=$6,start_tls=$7,ca_certificate=$8,bind_dn=$9,bind_credential_cipher=$10,users_dn=$11,
        username_ldap_attribute=$12,rdn_ldap_attribute=$13,uuid_ldap_attribute=$14,user_object_classes=$15,
        user_ldap_filter=$16,search_scope=$17,email_ldap_attribute=$18,first_name_ldap_attribute=$19,
        last_name_ldap_attribute=$20,display_name_ldap_attribute=$21,member_of_ldap_attribute=$22,
        group_role_mappings=$23,import_enabled=$24,sync_registrations=$25,missing_user_action=$26,
        edit_mode=$27,batch_size=$28,sync_period_seconds=$29,
        next_sync_at=CASE WHEN $29>0 THEN COALESCE(next_sync_at,now()+make_interval(secs=>$29)) END,
        updated_at=now() WHERE id=$1`, id, provider.Name, provider.Vendor, provider.Priority, provider.Enabled,
		provider.ConnectionURL, provider.StartTLS, provider.CACertificate, provider.BindDN, cipher, provider.UsersDN,
		provider.UsernameLDAPAttribute, provider.RDNLDAPAttribute, provider.UUIDLDAPAttribute,
		provider.UserObjectClasses, provider.UserLDAPFilter, provider.SearchScope, provider.EmailLDAPAttribute,
		provider.FirstNameLDAPAttribute, provider.LastNameLDAPAttribute, provider.DisplayNameLDAPAttribute,
		provider.MemberOfLDAPAttribute, mappings, provider.ImportEnabled, provider.SyncRegistrations,
		provider.MissingUserAction, provider.EditMode, provider.BatchSize, provider.SyncPeriodSeconds)
	if err != nil {
		if conflict, taken := conflictFromUnique(err); taken {
			return domain.LDAPFederation{}, conflict
		}
		return domain.LDAPFederation{}, fmt.Errorf("update LDAP federation: %w", err)
	}
	if command.RowsAffected() == 0 {
		return domain.LDAPFederation{}, ErrNotFound
	}
	if current.Provider.Enabled && !provider.Enabled {
		// Two statements written out here revoked the rows and stopped there:
		// the outcome of each was discarded, so a failure was reported as a
		// completed sign-out, and no relying party was ever told. Measured, it
		// signed the people out of ReSSO and left them signed in everywhere
		// they had used it — which is the gap the account-disable work closed
		// for the console and for the DISABLE sweep by sending all of them
		// through one call. This was the third place and did not go through it.
		linked, linkedErr := s.federatedUserIDs(ctx, id)
		if linkedErr != nil {
			return domain.LDAPFederation{}, linkedErr
		}
		if err := s.EndSessionsOfDisabledUsers(ctx, linked); err != nil {
			// The provider is already disabled; only the sign-out fell short.
			// Reported as a failed update it would describe a change that
			// happened as one that did not, and leave no record of it.
			updated, loadErr := s.LDAPFederationByID(ctx, id)
			if loadErr != nil {
				return domain.LDAPFederation{}, loadErr
			}
			return updated, fmt.Errorf("%w: %v", ErrUsersNotSignedOut, err)
		}
	}
	return s.LDAPFederationByID(ctx, id)
}

// federatedUserIDs names the accounts a provider owns, so that signing them
// out can go through the same call every other disable path uses.
func (s *Store) federatedUserIDs(ctx context.Context, providerID uuid.UUID) ([]uuid.UUID, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id FROM users WHERE federation_id=$1`, providerID)
	if err != nil {
		return nil, fmt.Errorf("list the provider's users: %w", err)
	}
	defer rows.Close()
	ids := make([]uuid.UUID, 0)
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (s *Store) DeleteLDAPFederation(ctx context.Context, id uuid.UUID, unlinkUsers bool) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// Who the provider owns has to be read before the unlink clears the
	// column that says so, and kept for after the commit: signing them out is
	// what tells the relying parties, and that cannot be done from inside this
	// transaction.
	linked, err := s.federatedUserIDsTx(ctx, tx, id)
	if err != nil {
		return err
	}
	if len(linked) > 0 && !unlinkUsers {
		return ErrConflict
	}
	if len(linked) > 0 {
		if _, err := tx.Exec(ctx, `DELETE FROM user_roles ur USING federation_role_assignments fra
            WHERE fra.federation_id=$1 AND ur.user_id=fra.user_id AND ur.role_id=fra.role_id`, id); err != nil {
			return fmt.Errorf("remove the roles the provider granted: %w", err)
		}
		if _, err := tx.Exec(ctx, `UPDATE users SET enabled=false,federation_id=NULL,external_id=NULL,
            external_dn=NULL,federation_synced_at=NULL,failed_attempts=0,locked_until=NULL,updated_at=now()
            WHERE federation_id=$1`, id); err != nil {
			return err
		}
	}
	command, err := tx.Exec(ctx, "DELETE FROM user_federations WHERE id=$1", id)
	if err != nil {
		return fmt.Errorf("delete LDAP federation: %w", err)
	}
	if command.RowsAffected() == 0 {
		return ErrNotFound
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	// The accounts are disabled the moment that commit lands, and a disabled
	// account's session is refused everywhere already, so nothing is open in
	// the gap. What this adds is the durable revocation and the notification —
	// the sessions and refresh tokens used to be revoked inside the
	// transaction, with each statement's outcome discarded and no relying
	// party told, which left everyone signed in wherever they had used ReSSO.
	if err := s.EndSessionsOfDisabledUsers(ctx, linked); err != nil {
		// The provider is gone and its accounts are unlinked and disabled;
		// what did not finish is signing them out everywhere.
		return fmt.Errorf("%w: %v", ErrUsersNotSignedOut, err)
	}
	return nil
}

// federatedUserIDsTx is federatedUserIDs inside a caller's transaction.
func (s *Store) federatedUserIDsTx(ctx context.Context, tx pgx.Tx, providerID uuid.UUID) ([]uuid.UUID, error) {
	rows, err := tx.Query(ctx, `SELECT id FROM users WHERE federation_id=$1`, providerID)
	if err != nil {
		return nil, fmt.Errorf("list the provider's users: %w", err)
	}
	defer rows.Close()
	ids := make([]uuid.UUID, 0)
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func normalizeLDAPInput(id, realmID uuid.UUID, input LDAPFederationInput, credential string, creating bool) (domain.LDAPFederation, string, error) {
	provider := domain.LDAPFederation{ID: id, RealmID: realmID, Name: strings.TrimSpace(input.Name),
		Vendor: strings.ToUpper(strings.TrimSpace(input.Vendor)), Priority: input.Priority, Enabled: input.Enabled,
		ConnectionURL: strings.TrimSpace(input.ConnectionURL), StartTLS: input.StartTLS,
		CACertificate: strings.TrimSpace(input.CACertificate), BindDN: strings.TrimSpace(input.BindDN),
		UsersDN: strings.TrimSpace(input.UsersDN), UsernameLDAPAttribute: strings.TrimSpace(input.UsernameLDAPAttribute),
		RDNLDAPAttribute: strings.TrimSpace(input.RDNLDAPAttribute), UUIDLDAPAttribute: strings.TrimSpace(input.UUIDLDAPAttribute),
		UserObjectClasses: cleanStrings(input.UserObjectClasses), UserLDAPFilter: strings.TrimSpace(input.UserLDAPFilter),
		SearchScope: strings.ToUpper(strings.TrimSpace(input.SearchScope)), EmailLDAPAttribute: strings.TrimSpace(input.EmailLDAPAttribute),
		FirstNameLDAPAttribute: strings.TrimSpace(input.FirstNameLDAPAttribute), LastNameLDAPAttribute: strings.TrimSpace(input.LastNameLDAPAttribute),
		DisplayNameLDAPAttribute: strings.TrimSpace(input.DisplayNameLDAPAttribute), MemberOfLDAPAttribute: strings.TrimSpace(input.MemberOfLDAPAttribute),
		GroupRoleMappings: normalizeMappings(input.GroupRoleMappings), ImportEnabled: input.ImportEnabled,
		SyncRegistrations: input.SyncRegistrations, MissingUserAction: strings.ToUpper(strings.TrimSpace(input.MissingUserAction)),
		EditMode: strings.ToUpper(strings.TrimSpace(input.EditMode)), BatchSize: input.BatchSize,
		SyncPeriodSeconds: input.SyncPeriodSeconds}
	if provider.Vendor == "" {
		provider.Vendor = "OTHER"
	}
	if provider.SearchScope == "" {
		provider.SearchScope = "SUBTREE"
	}
	if provider.MissingUserAction == "" {
		provider.MissingUserAction = "KEEP"
	}
	if provider.EditMode == "" {
		provider.EditMode = "READ_ONLY"
	}
	if provider.BatchSize == 0 {
		provider.BatchSize = 500
	}
	if input.BindCredential != nil && creating {
		credential = *input.BindCredential
	}
	if provider.Name == "" || len([]rune(provider.Name)) > 120 {
		return domain.LDAPFederation{}, "", errors.New("federation name is required and must be at most 120 characters")
	}
	if provider.Vendor != "OTHER" && provider.Vendor != "AD" {
		return domain.LDAPFederation{}, "", errors.New("vendor must be OTHER or AD")
	}
	if provider.Priority < 0 || provider.Priority > 1000 || provider.BatchSize < 50 || provider.BatchSize > 5000 {
		return domain.LDAPFederation{}, "", errors.New("priority or batch size is outside the supported range")
	}
	if provider.SyncPeriodSeconds != 0 && (provider.SyncPeriodSeconds < 300 || provider.SyncPeriodSeconds > 604800) {
		return domain.LDAPFederation{}, "", errors.New("sync period must be zero or between 300 and 604800 seconds")
	}
	if !provider.ImportEnabled && provider.SyncPeriodSeconds > 0 {
		return domain.LDAPFederation{}, "", errors.New("automatic synchronization requires user import to be enabled")
	}
	if provider.MissingUserAction != "KEEP" && provider.MissingUserAction != "DISABLE" {
		return domain.LDAPFederation{}, "", errors.New("missing user action must be KEEP or DISABLE")
	}
	if provider.EditMode != "READ_ONLY" && provider.EditMode != "WRITABLE" && provider.EditMode != "UNSYNCED" {
		return domain.LDAPFederation{}, "", errors.New("edit mode must be READ_ONLY, WRITABLE, or UNSYNCED")
	}
	if err := federation.Validate(provider, credential, provider.BindDN != ""); err != nil {
		return domain.LDAPFederation{}, "", err
	}
	return provider, credential, nil
}

func cleanStrings(values []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		key := strings.ToLower(value)
		if value == "" {
			continue
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, value)
	}
	return result
}

func normalizeMappings(mappings map[string]string) map[string]string {
	result := map[string]string{}
	for group, role := range mappings {
		group, role = strings.ToLower(strings.TrimSpace(group)), strings.TrimSpace(role)
		if group != "" && role != "" {
			result[group] = role
		}
	}
	return result
}

func (s *Store) TestLDAPFederation(ctx context.Context, id uuid.UUID) error {
	runtime, err := s.ldapRuntimeByID(ctx, id)
	if err != nil {
		return err
	}
	return federation.TestConnection(ctx, federation.RuntimeConfig{Provider: runtime.Provider, BindCredential: runtime.BindCredential})
}

// TestLDAPAuthentication reports whether the directory accepts a credential.
//
// Not being able to ask is separated from being told no, because this exists
// to tell an administrator what is wrong. Both came back as "authentication
// failed", so a directory that was unreachable, a bind account that had
// stopped working and a keyring that could not open the stored credential all
// read as the person's password being wrong — and the administrator goes and
// resets a password that was never the problem.
func (s *Store) TestLDAPAuthentication(ctx context.Context, id uuid.UUID, username, suppliedPassword string) (LDAPAuthenticationTestResult, error) {
	runtime, err := s.ldapRuntimeByID(ctx, id)
	if err != nil {
		return LDAPAuthenticationTestResult{}, fmt.Errorf("%w: %v", ErrFederationOperation, err)
	}
	user, ok, err := federation.Authenticate(ctx,
		federation.RuntimeConfig{Provider: runtime.Provider, BindCredential: runtime.BindCredential}, username, suppliedPassword)
	if err != nil {
		return LDAPAuthenticationTestResult{}, fmt.Errorf("%w: %v", ErrFederationOperation, err)
	}
	if !ok {
		return LDAPAuthenticationTestResult{}, errors.New("LDAP credentials are invalid or the user is not unique")
	}
	return LDAPAuthenticationTestResult{Username: user.Username, DN: user.DN, Email: user.Email, DisplayName: user.DisplayName}, nil
}

// ErrSyncInProgress reports that a synchronization is already running for the
// provider. A full synchronization walks the whole directory, so starting a
// second one concurrently duplicates the work and interleaves writes to the
// same users.
var ErrSyncInProgress = errors.New("a synchronization is already running for this provider")

// staleSyncAfter releases a claim whose owner disappeared, so a crash or a
// restart mid-synchronization cannot wedge the provider permanently.
const staleSyncAfter = 30 * time.Minute

// LDAPSyncRunning reports whether a run is currently claimed, so the console
// can refuse to start a second one and show progress for the first.
func (s *Store) LDAPSyncRunning(ctx context.Context, id uuid.UUID) (bool, error) {
	var running bool
	err := s.Pool.QueryRow(ctx, `SELECT last_sync_status='RUNNING'
        AND updated_at >= now()-make_interval(secs => `+staleSyncAfterSeconds+`)
        FROM user_federations WHERE id=$1`, id).Scan(&running)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrNotFound
	}
	return running, err
}

func (s *Store) claimLDAPSync(ctx context.Context, id uuid.UUID) (bool, error) {
	command, err := s.Pool.Exec(ctx, `UPDATE user_federations
        SET last_sync_status='RUNNING',last_sync_error='',updated_at=now()
        WHERE id=$1 AND (last_sync_status <> 'RUNNING' OR updated_at < now()-make_interval(secs => $2))`,
		id, int(staleSyncAfter.Seconds()))
	if err != nil {
		return false, err
	}
	return command.RowsAffected() == 1, nil
}

func (s *Store) SyncLDAPFederation(ctx context.Context, id uuid.UUID) (LDAPSyncSummary, error) {
	runtime, err := s.ldapRuntimeByID(ctx, id)
	if err != nil {
		return LDAPSyncSummary{}, err
	}
	summary := LDAPSyncSummary{FederationID: id, StartedAt: time.Now().UTC()}
	if !runtime.Provider.ImportEnabled {
		err := errors.New("full user synchronization is disabled; enable user import or use just-in-time registration")
		summary.RecordError = recordError(s.finishLDAPSync(context.WithoutCancel(ctx), runtime.Provider, summary, err))
		return summary, err
	}
	claimed, err := s.claimLDAPSync(ctx, id)
	if err != nil {
		return summary, err
	}
	if !claimed {
		return summary, ErrSyncInProgress
	}
	users, err := federation.FetchUsers(ctx, federation.RuntimeConfig{Provider: runtime.Provider, BindCredential: runtime.BindCredential})
	if err != nil {
		summary.RecordError = recordError(s.finishLDAPSync(context.WithoutCancel(ctx), runtime.Provider, summary, err))
		return summary, err
	}
	summary.Read = len(users)
	for _, external := range users {
		added, upsertErr := s.upsertFederatedUser(ctx, runtime.Provider, external, summary.StartedAt)
		if upsertErr != nil {
			summary.Failed++
			if len(summary.Failures) < namedSyncFailures {
				summary.Failures = append(summary.Failures, fmt.Sprintf("%s: %v", external.Username, upsertErr))
			}
			continue
		}
		if added {
			summary.Added++
		} else {
			summary.Updated++
		}
	}
	// Skipping the sweep after a failed import is deliberate: the users that
	// failed are exactly the ones whose federation_synced_at did not move, so
	// sweeping now would deactivate people the directory still holds. The
	// consequence is worth saying out loud rather than leaving to be inferred —
	// while anything is failing, the DISABLE policy is not running at all, and
	// the accounts of people who have left stay enabled until it is fixed.
	sweepSkipped := summary.Failed > 0 && runtime.Provider.MissingUserAction == "DISABLE"
	var sweepErr error
	if summary.Failed == 0 && runtime.Provider.MissingUserAction == "DISABLE" {
		summary.Disabled, sweepErr = s.disableUnseenFederatedUsers(ctx, id, summary.StartedAt, summary.Read)
		if sweepErr != nil && !errors.Is(sweepErr, ErrSyncReadNothing) {
			summary.Failed++
		}
	}
	summary.CompletedAt = time.Now().UTC()
	var syncErr error
	switch {
	case errors.Is(sweepErr, ErrSyncReadNothing):
		syncErr = sweepErr
	case summary.Failed > 0:
		syncErr = fmt.Errorf("%d LDAP users could not be synchronized: %s",
			summary.Failed, describeSyncFailures(summary.Failures, summary.Failed))
		if sweepSkipped {
			syncErr = fmt.Errorf("%w; accounts missing from the directory were left enabled until this is resolved", syncErr)
		}
	}
	summary.RecordError = recordError(s.finishLDAPSync(context.WithoutCancel(ctx), runtime.Provider, summary, syncErr))
	return summary, syncErr
}

// namedSyncFailures bounds how many rejected users a run names. The reasons
// repeat in practice — one misconfiguration produces the same sentence for
// everybody it touches — so a handful is enough to act on, and the outcome
// message is stored in a column and an audit detail that both have to stay a
// reasonable size.
const namedSyncFailures = 5

// describeSyncFailures renders the named failures and says how many more there
// were, so a truncated list never reads as the whole list.
func describeSyncFailures(failures []string, total int) string {
	if len(failures) == 0 {
		return "no reason was recorded"
	}
	described := strings.Join(failures, "; ")
	if remaining := total - len(failures); remaining > 0 {
		described += fmt.Sprintf("; and %d more", remaining)
	}
	return described
}

// ErrUsersNotSignedOut reports that a provider change landed but signing its
// people out did not finish. The change itself is done — the provider is
// disabled, or gone and its accounts unlinked — so reporting it as a failed
// request describes something that did happen as something that did not, and
// leaves no record of it.
var ErrUsersNotSignedOut = errors.New("the provider changed but its people were not signed out everywhere")

// ErrSyncReadNothing reports a sync that saw no users at all in a directory
// that is known to hold some.
var ErrSyncReadNothing = errors.New("LDAP directory returned no users; accounts were left enabled")

// disableUnseenFederatedUsers deactivates the accounts a completed sync did
// not encounter, which is what the DISABLE policy is for.
//
// It refuses to act on an empty read. A search that returns nothing looks
// identical whether everybody really left the directory or the search simply
// pointed somewhere wrong — a mistyped users DN, a subtree the bind account
// lost permission to read, a base that was renamed. Those are ordinary
// mistakes, and the previous behaviour turned each of them into every
// federated account in the Realm being disabled and every one of their
// sessions revoked on the next scheduled sweep. When the directory says
// nothing and the database knows otherwise, the database is the better
// witness, so the run reports a failure instead.
func (s *Store) disableUnseenFederatedUsers(ctx context.Context, providerID uuid.UUID, startedAt time.Time, read int) (int64, error) {
	if read == 0 {
		var known int
		if err := s.Pool.QueryRow(ctx,
			"SELECT count(*) FROM users WHERE federation_id=$1 AND enabled=true", providerID).Scan(&known); err != nil {
			return 0, err
		}
		if known > 0 {
			return 0, ErrSyncReadNothing
		}
	}
	rows, err := s.Pool.Query(ctx, `UPDATE users SET enabled=false,updated_at=now()
        WHERE federation_id=$1 AND (federation_synced_at IS NULL OR federation_synced_at<$2) AND enabled=true
        RETURNING id`, providerID, startedAt)
	if err != nil {
		return 0, err
	}
	disabled := make([]uuid.UUID, 0)
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		disabled = append(disabled, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	// Named accounts rather than every already-disabled account of the
	// provider, so a sweep that finds nothing new stops resending logouts for
	// people who left long ago.
	if err := s.EndSessionsOfDisabledUsers(ctx, disabled); err != nil {
		return int64(len(disabled)), err
	}
	return int64(len(disabled)), nil
}

// finishLDAPSync records how a run ended and reports whether the recording
// itself worked.
//
// Both writes were previously issued and discarded. A run whose bookkeeping
// failed returned success to its caller while the provider stayed at RUNNING
// showing the previous run's numbers, and nothing at all was written to the
// audit trail — including for a sweep that had just deactivated accounts and
// signed them out everywhere. The trail is exactly where an operator is told
// to look to find out whether a DISABLE policy acted on them, so it cannot
// lose an entry quietly. The Store performs no logging of its own, so the
// failure travels back on the summary for the callers, which already report
// what a run did.
// recordError renders a bookkeeping failure for the summary, which travels to
// the console as JSON.
func recordError(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func (s *Store) finishLDAPSync(ctx context.Context, provider domain.LDAPFederation, summary LDAPSyncSummary, syncErr error) error {
	status, message := "SUCCESS", ""
	if syncErr != nil {
		status, message = "FAILURE", syncErr.Error()
	}
	if len(message) > 1000 {
		message = message[:1000]
	}
	var failures []error
	if _, err := s.Pool.Exec(ctx, `UPDATE user_federations SET last_sync_at=now(),last_sync_status=$2,last_sync_error=$3,
        last_sync_added=$4,last_sync_updated=$5,last_sync_failed=$6,last_sync_disabled=$7,
        next_sync_at=CASE WHEN sync_period_seconds>0 THEN now()+make_interval(secs=>sync_period_seconds) END,
        updated_at=now() WHERE id=$1`, provider.ID, status, message,
		summary.Added, summary.Updated, summary.Failed, summary.Disabled); err != nil {
		failures = append(failures, fmt.Errorf("record the outcome on the provider: %w", err))
	}

	// The outcome belongs in the audit trail, not only in the server log: a
	// run under the DISABLE policy deactivates accounts and ends their
	// sessions, and audit events are retained far longer than logs. Recording
	// it here covers the scheduled sweep as well as a manual run, neither of
	// which reported its result to the trail before.
	realmID := provider.RealmID
	detail := map[string]any{"provider": provider.Name, "read": summary.Read, "added": summary.Added,
		"updated": summary.Updated, "failed": summary.Failed, "disabled": summary.Disabled}
	if len(summary.Failures) > 0 {
		detail["failures"] = summary.Failures
	}
	if message != "" {
		detail["error"] = message
	}
	if err := s.WriteAudit(ctx, AuditEvent{RealmID: &realmID, ActorName: "system",
		EventType: "LDAP_FEDERATION_SYNC", Result: status, TargetType: "user_federation",
		TargetID: provider.ID.String(), Detail: detail}); err != nil {
		failures = append(failures, fmt.Errorf("write the audit event: %w", err))
	}
	return errors.Join(failures...)
}

func (s *Store) upsertFederatedUser(ctx context.Context, provider domain.LDAPFederation, external federation.User, syncedAt time.Time) (bool, error) {
	email, err := normalizeOptionalEmail(external.Email)
	if err != nil {
		return false, fmt.Errorf("normalize LDAP user email: %w", err)
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var userID uuid.UUID
	var existingFederation *uuid.UUID
	err = tx.QueryRow(ctx, `SELECT id,federation_id FROM users WHERE realm_id=$1 AND federation_id=$2 AND external_id=$3 FOR UPDATE`,
		provider.RealmID, provider.ID, external.ExternalID).Scan(&userID, &existingFederation)
	if errors.Is(err, pgx.ErrNoRows) {
		err = tx.QueryRow(ctx, `SELECT id,federation_id FROM users WHERE realm_id=$1 AND lower(username)=lower($2) FOR UPDATE`,
			provider.RealmID, external.Username).Scan(&userID, &existingFederation)
	}
	added := false
	if errors.Is(err, pgx.ErrNoRows) {
		added = true
		userID = uuid.New()
		_, err = tx.Exec(ctx, `INSERT INTO users(id,realm_id,username,email,display_name,password_hash,enabled,
            federation_id,external_id,external_dn,federation_synced_at,password_changed_at,created_at,updated_at)
            VALUES($1,$2,$3,$4,$5,$6,true,$7,$8,$9,$10,$10,$10,$10)`, userID, provider.RealmID,
			external.Username, email, external.DisplayName, s.dummyPasswordHash, provider.ID, external.ExternalID,
			external.DN, syncedAt)
	} else if err == nil {
		if existingFederation == nil || *existingFederation != provider.ID {
			return false, fmt.Errorf("username %q already belongs to a local account or another federation", external.Username)
		}
		if provider.EditMode == "UNSYNCED" {
			_, err = tx.Exec(ctx, `UPDATE users SET external_id=$2,external_dn=$3,federation_synced_at=$4,
                enabled=true,updated_at=now() WHERE id=$1`, userID, external.ExternalID, external.DN, syncedAt)
		} else {
			_, err = tx.Exec(ctx, `UPDATE users SET username=$2,
				email_verified=CASE WHEN $3='' OR lower(btrim(email))<>$3 THEN false ELSE email_verified END,
				email=$3,display_name=$4,external_id=$5,
				external_dn=$6,federation_synced_at=$7,enabled=true,updated_at=now() WHERE id=$1`, userID,
				external.Username, email, external.DisplayName, external.ExternalID, external.DN, syncedAt)
		}
	}
	if err != nil {
		return false, err
	}
	_, _ = tx.Exec(ctx, `INSERT INTO user_roles(user_id,role_id)
        SELECT $1,id FROM roles WHERE realm_id=$2 AND name='user' ON CONFLICT DO NOTHING`, userID, provider.RealmID)
	if err := syncFederatedRoles(ctx, tx, provider, userID, federation.MappedRoles(provider, external.MemberOf)); err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return added, nil
}

func syncFederatedRoles(ctx context.Context, tx pgx.Tx, provider domain.LDAPFederation, userID uuid.UUID, names []string) error {
	rows, err := tx.Query(ctx, `SELECT id FROM roles WHERE realm_id=$1 AND name=ANY($2)`, provider.RealmID, names)
	if err != nil {
		return err
	}
	desired := map[uuid.UUID]struct{}{}
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		desired[id] = struct{}{}
	}
	rows.Close()
	oldRows, err := tx.Query(ctx, `SELECT role_id FROM federation_role_assignments WHERE federation_id=$1 AND user_id=$2`, provider.ID, userID)
	if err != nil {
		return err
	}
	var obsolete []uuid.UUID
	for oldRows.Next() {
		var id uuid.UUID
		if err := oldRows.Scan(&id); err != nil {
			oldRows.Close()
			return err
		}
		if _, keep := desired[id]; !keep {
			obsolete = append(obsolete, id)
		}
	}
	oldRows.Close()
	for _, roleID := range obsolete {
		_, _ = tx.Exec(ctx, `DELETE FROM federation_role_assignments WHERE federation_id=$1 AND user_id=$2 AND role_id=$3`, provider.ID, userID, roleID)
		_, _ = tx.Exec(ctx, `DELETE FROM user_roles WHERE user_id=$1 AND role_id=$2`, userID, roleID)
	}
	for roleID := range desired {
		command, err := tx.Exec(ctx, `INSERT INTO user_roles(user_id,role_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, userID, roleID)
		if err != nil {
			return err
		}
		if command.RowsAffected() > 0 {
			_, err = tx.Exec(ctx, `INSERT INTO federation_role_assignments(federation_id,user_id,role_id) VALUES($1,$2,$3)`, provider.ID, userID, roleID)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Store) ClaimDueLDAPFederations(ctx context.Context, limit int) ([]uuid.UUID, error) {
	if limit < 1 || limit > 20 {
		limit = 5
	}
	rows, err := s.Pool.Query(ctx, `WITH due AS (
        SELECT id FROM user_federations WHERE enabled=true AND sync_period_seconds>0 AND next_sync_at<=now()
        ORDER BY next_sync_at FOR UPDATE SKIP LOCKED LIMIT $1
      ) UPDATE user_federations f SET next_sync_at=now()+make_interval(secs=>f.sync_period_seconds),
        last_sync_status='RUNNING',updated_at=now() FROM due WHERE f.id=due.id RETURNING f.id`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (s *Store) Authenticate(ctx context.Context, realm domain.Realm, username, suppliedPassword string) (AuthenticationResult, error) {
	username = strings.TrimSpace(username)
	var federationID *uuid.UUID
	err := s.Pool.QueryRow(ctx, `SELECT federation_id FROM users WHERE realm_id=$1 AND lower(username)=lower($2)`,
		realm.ID, username).Scan(&federationID)
	if err == nil && federationID == nil {
		return s.AuthenticatePassword(ctx, realm, username, suppliedPassword)
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return AuthenticationResult{}, err
	}
	if federationID != nil {
		return s.authenticateLinkedLDAPUser(ctx, realm, username, suppliedPassword, *federationID)
	}
	rows, err := s.Pool.Query(ctx, "SELECT "+ldapFederationColumns+` FROM user_federations
        WHERE realm_id=$1 AND enabled=true AND sync_registrations=true ORDER BY priority,name`, realm.ID)
	if err != nil {
		return AuthenticationResult{}, err
	}
	var runtimes []ldapRuntime
	for rows.Next() {
		runtime, scanErr := s.scanLDAPFederation(rows)
		if scanErr != nil {
			rows.Close()
			return AuthenticationResult{}, scanErr
		}
		runtimes = append(runtimes, runtime)
	}
	rows.Close()
	var federationErr error
	for _, runtime := range runtimes {
		external, ok, authErr := federation.Authenticate(ctx,
			federation.RuntimeConfig{Provider: runtime.Provider, BindCredential: runtime.BindCredential}, username, suppliedPassword)
		if authErr != nil {
			federationErr = errors.Join(federationErr, fmt.Errorf("%s: %w", runtime.Provider.Name, authErr))
			continue
		}
		if !ok {
			continue
		}
		if _, err := s.upsertFederatedUser(ctx, runtime.Provider, external, time.Now().UTC()); err != nil {
			return AuthenticationResult{}, err
		}
		user, err := s.userByRealmUsername(ctx, realm.ID, username)
		if err != nil {
			return AuthenticationResult{}, err
		}
		return s.finishFederatedAuthentication(ctx, realm, user, true, runtime.Provider.Name)
	}
	if federationErr != nil {
		return AuthenticationResult{}, federationErr
	}
	_, _ = s.dummyPasswordVerification(ctx, suppliedPassword)
	return AuthenticationResult{FailureReason: "INVALID_CREDENTIALS"}, nil
}

func (s *Store) authenticateLinkedLDAPUser(ctx context.Context, realm domain.Realm, username, suppliedPassword string, federationID uuid.UUID) (AuthenticationResult, error) {
	user, err := s.userByRealmUsername(ctx, realm.ID, username)
	if err != nil {
		return AuthenticationResult{}, err
	}
	if reason := accountFailureReason(realm, user, time.Now().UTC()); reason != "" {
		return AuthenticationResult{User: user, FailureReason: reason}, nil
	}
	runtime, err := s.ldapRuntimeByID(ctx, federationID)
	if err != nil {
		return AuthenticationResult{}, err
	}
	if !runtime.Provider.Enabled {
		return AuthenticationResult{User: user, FailureReason: "FEDERATION_DISABLED"}, nil
	}
	external, ok, err := federation.Authenticate(ctx,
		federation.RuntimeConfig{Provider: runtime.Provider, BindCredential: runtime.BindCredential}, username, suppliedPassword)
	if err != nil {
		return AuthenticationResult{}, err
	}
	if ok {
		_, err = s.upsertFederatedUser(ctx, runtime.Provider, external, time.Now().UTC())
		if err != nil {
			return AuthenticationResult{}, err
		}
		user, err = s.userByRealmUsername(ctx, realm.ID, external.Username)
		if err != nil {
			return AuthenticationResult{}, err
		}
	}
	return s.finishFederatedAuthentication(ctx, realm, user, ok, runtime.Provider.Name)
}

func (s *Store) finishFederatedAuthentication(ctx context.Context, realm domain.Realm, user domain.User, verified bool, providerName string) (AuthenticationResult, error) {
	if !verified {
		locked, err := s.recordFailedLogin(ctx, user.ID)
		if err != nil {
			return AuthenticationResult{}, err
		}
		reason := "INVALID_CREDENTIALS"
		if locked {
			reason = "ACCOUNT_LOCKED"
		}
		return AuthenticationResult{User: user, FailureReason: reason}, nil
	}
	accepted, err := s.completeSuccessfulLogin(ctx, user.ID)
	if err != nil {
		return AuthenticationResult{}, err
	}
	if !accepted {
		return AuthenticationResult{User: user, FailureReason: "ACCOUNT_LOCKED"}, nil
	}
	user.FailedAttempts, user.LockedUntil = 0, nil
	return AuthenticationResult{User: user, Success: true, SessionSeconds: realm.SessionTTLSeconds,
		AuthMethod: "ldap:" + providerName}, nil
}

func (s *Store) userByRealmUsername(ctx context.Context, realmID uuid.UUID, username string) (domain.User, error) {
	return scanUser(s.Pool.QueryRow(ctx, "SELECT "+userColumns+` FROM users WHERE realm_id=$1 AND lower(username)=lower($2)`, realmID, username))
}

func accountFailureReason(realm domain.Realm, user domain.User, now time.Time) string {
	if !realm.Enabled || !user.Enabled {
		return "ACCOUNT_DISABLED"
	}
	if user.LockedUntil != nil && user.LockedUntil.After(now) {
		return "ACCOUNT_LOCKED"
	}
	return ""
}

func (s *Store) dummyPasswordVerification(ctx context.Context, value string) (bool, error) {
	return password.VerifyContext(ctx, value, s.dummyPasswordHash)
}

func (s *Store) updateFederatedAttributes(ctx context.Context, user domain.User, email, displayName string) error {
	if user.FederationID == nil || user.ExternalDN == nil {
		return nil
	}
	runtime, err := s.ldapRuntimeByID(ctx, *user.FederationID)
	if err != nil {
		return err
	}
	switch runtime.Provider.EditMode {
	case "READ_ONLY":
		return ErrFederationReadOnly
	case "WRITABLE":
		if err := federation.UpdateUser(ctx, federation.RuntimeConfig{Provider: runtime.Provider, BindCredential: runtime.BindCredential},
			*user.ExternalDN, email, displayName); err != nil {
			return fmt.Errorf("%w: %v", ErrFederationOperation, err)
		}
		return nil
	case "UNSYNCED":
		return nil
	default:
		return errors.New("unsupported LDAP edit mode")
	}
}

func (s *Store) changeFederatedPassword(ctx context.Context, user domain.User, current, replacement string) error {
	if user.FederationID == nil || user.ExternalDN == nil {
		return ErrNotFound
	}
	runtime, err := s.ldapRuntimeByID(ctx, *user.FederationID)
	if err != nil {
		return err
	}
	if runtime.Provider.EditMode != "WRITABLE" {
		return ErrFederationPasswordExternal
	}
	if err := federation.ChangePassword(ctx, federation.RuntimeConfig{Provider: runtime.Provider, BindCredential: runtime.BindCredential},
		*user.ExternalDN, current, replacement); err != nil {
		return fmt.Errorf("%w: %v", ErrFederationOperation, err)
	}
	return nil
}

// ClaimLDAPSyncForTest exposes the claim for tests that need to simulate a run
// already in progress without reaching a directory server.
func (s *Store) ClaimLDAPSyncForTest(ctx context.Context, id uuid.UUID) (bool, error) {
	return s.claimLDAPSync(ctx, id)
}
