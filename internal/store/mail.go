package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/hkjang/ReSSO/internal/domain"
	"github.com/hkjang/ReSSO/internal/mail"
)

// MailSettings reads every mail.* row of platform_settings into the map the
// mail package reads its configuration from. No rows is the default: off.
func (s *Store) MailSettings(ctx context.Context) (map[string]any, error) {
	rows, err := s.Pool.Query(ctx, "SELECT key,value FROM platform_settings WHERE key LIKE 'mail.%'")
	if err != nil {
		return nil, fmt.Errorf("read mail settings: %w", err)
	}
	defer rows.Close()
	values := map[string]any{}
	for rows.Next() {
		var key string
		var raw []byte
		if err := rows.Scan(&key, &raw); err != nil {
			return nil, err
		}
		var value any
		if err := json.Unmarshal(raw, &value); err != nil {
			return nil, fmt.Errorf("decode mail setting %s: %w", key, err)
		}
		values[key] = value
	}
	return values, rows.Err()
}

// SaveMailSettings writes the keys given and leaves the rest as they are,
// which is how the password stays put while the screen saves everything
// else. A key outside the standard list is the caller's mistake, refused
// before anything is written. Values that can never reach a relay — a port
// outside the range, an unknown security mode — are refused too; an empty
// host is not, because the screen is saved before the relay is known.
func (s *Store) SaveMailSettings(ctx context.Context, values map[string]any, actorID *uuid.UUID) error {
	known := map[string]bool{}
	for _, key := range mail.Keys() {
		known[key] = true
	}
	for key := range values {
		if !known[key] {
			return invalidf("알 수 없는 메일 설정 키입니다: %s", key)
		}
	}
	current, err := s.MailSettings(ctx)
	if err != nil {
		return err
	}
	for key, value := range values {
		current[key] = value
	}
	if err := mail.Read(current).ValidateShape(); err != nil {
		return invalidf("%s", err.Error())
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for key, value := range values {
		raw, err := json.Marshal(value)
		if err != nil {
			return fmt.Errorf("encode mail setting %s: %w", key, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO platform_settings(key,value,updated_at,updated_by) VALUES($1,$2,now(),$3)
            ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=now(), updated_by=EXCLUDED.updated_by`,
			key, raw, actorID); err != nil {
			return fmt.Errorf("save mail setting %s: %w", key, err)
		}
	}
	return tx.Commit(ctx)
}

// ClearMailPassword removes the stored relay password.
func (s *Store) ClearMailPassword(ctx context.Context) error {
	_, err := s.Pool.Exec(ctx, "DELETE FROM platform_settings WHERE key=$1", mail.KeyPassword)
	return err
}

// MailAddresses is the one lookup the mail package borrows from the account
// table: identifiers in, addresses out. Disabled accounts and accounts
// without an address are left out, so the caller skips them.
func (s *Store) MailAddresses(ctx context.Context, userIDs []uuid.UUID) (map[uuid.UUID]string, error) {
	rows, err := s.Pool.Query(ctx, "SELECT id,email FROM users WHERE id=ANY($1) AND enabled AND email<>''", userIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	addresses := map[uuid.UUID]string{}
	for rows.Next() {
		var id uuid.UUID
		var email string
		if err := rows.Scan(&id, &email); err != nil {
			return nil, err
		}
		addresses[id] = email
	}
	return addresses, rows.Err()
}

func (s *Store) RecordMailDelivery(ctx context.Context, delivery mail.Delivery) error {
	_, err := s.Pool.Exec(ctx, `INSERT INTO mail_deliveries(id,event,recipient,subject,reference,actor_id,status,attempts,created_at,updated_at)
        VALUES($1,$2,$3,$4,$5,$6,$7,0,$8,$8)`, delivery.ID, delivery.Event, delivery.Recipient, delivery.Subject,
		delivery.Reference, delivery.ActorID, delivery.Status, delivery.CreatedAt)
	return err
}

func (s *Store) CompleteMailDelivery(ctx context.Context, id uuid.UUID, status string, attempts int, errorMessage string) error {
	_, err := s.Pool.Exec(ctx, `UPDATE mail_deliveries SET status=$2,attempts=GREATEST(attempts,$3),error_message=$4,updated_at=now() WHERE id=$1`,
		id, status, attempts, errorMessage)
	return err
}

// MailDeliveryPage is the delivery record as the console lists it: newest
// first, with the count of every status so the summary does not depend on
// the page.
type MailDeliveryPage struct {
	Items   []mail.Delivery `json:"items"`
	Total   int             `json:"total"`
	ByState map[string]int  `json:"by_status"`
}

func (s *Store) ListMailDeliveries(ctx context.Context, status string, limit int) (MailDeliveryPage, error) {
	if limit < 1 || limit > 200 {
		limit = 50
	}
	page := MailDeliveryPage{Items: []mail.Delivery{}, ByState: map[string]int{}}
	rows, err := s.Pool.Query(ctx, `SELECT id,event,recipient,subject,reference,actor_id,status,attempts,error_message,created_at,updated_at
        FROM mail_deliveries WHERE ($1='' OR status=$1) ORDER BY created_at DESC, id LIMIT $2`, strings.TrimSpace(status), limit)
	if err != nil {
		return MailDeliveryPage{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var item mail.Delivery
		if err := rows.Scan(&item.ID, &item.Event, &item.Recipient, &item.Subject, &item.Reference, &item.ActorID,
			&item.Status, &item.Attempts, &item.ErrorMessage, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return MailDeliveryPage{}, err
		}
		page.Items = append(page.Items, item)
	}
	if err := rows.Err(); err != nil {
		return MailDeliveryPage{}, err
	}
	counts, err := s.Pool.Query(ctx, "SELECT status,count(*) FROM mail_deliveries GROUP BY 1")
	if err != nil {
		return MailDeliveryPage{}, err
	}
	defer counts.Close()
	for counts.Next() {
		var key string
		var count int
		if err := counts.Scan(&key, &count); err != nil {
			return MailDeliveryPage{}, err
		}
		page.ByState[key] = count
		page.Total += count
	}
	return page, counts.Err()
}

// ApprovalReviewers is who should hear that a request is waiting: the
// designated reviewer when the requester has a manager, otherwise the Realm's
// administrators, and failing those the service administrators — the same
// people DecideApprovalRequest lets decide it.
func (s *Store) ApprovalReviewers(ctx context.Context, request domain.ApprovalRequest) ([]uuid.UUID, error) {
	if request.ReviewerID != nil {
		return []uuid.UUID{*request.ReviewerID}, nil
	}
	admins, err := s.userIDs(ctx, `SELECT u.id FROM users u JOIN user_roles ur ON ur.user_id=u.id JOIN roles r ON r.id=ur.role_id
        WHERE u.realm_id=$1 AND u.enabled AND r.name='realm-admin'`, request.RealmID)
	if err != nil || len(admins) > 0 {
		return admins, err
	}
	return s.PlatformAdministrators(ctx)
}

// PlatformAdministrators lists the enabled service administrators.
func (s *Store) PlatformAdministrators(ctx context.Context) ([]uuid.UUID, error) {
	return s.userIDs(ctx, "SELECT id FROM users WHERE platform_admin AND enabled")
}

func (s *Store) userIDs(ctx context.Context, query string, arguments ...any) ([]uuid.UUID, error) {
	rows, err := s.Pool.Query(ctx, query, arguments...)
	if err != nil {
		return nil, err
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

// ApprovalRequestNames resolves what a request mail has to say: who asked,
// in which Realm, for which Role.
func (s *Store) ApprovalRequestNames(ctx context.Context, request domain.ApprovalRequest) (requester, realm, role string, err error) {
	err = s.Pool.QueryRow(ctx, `SELECT COALESCE(NULLIF(u.display_name,''),u.username),rl.display_name,COALESCE(ro.name,'')
        FROM approval_requests a JOIN users u ON u.id=a.requester_id JOIN realms rl ON rl.id=a.realm_id
        LEFT JOIN roles ro ON a.kind='ROLE_ASSIGNMENT' AND ro.id::text=a.payload->>'role_id'
        WHERE a.id=$1`, request.ID).Scan(&requester, &realm, &role)
	return requester, realm, role, err
}

// ExpiringAPIKeyOwner is one account with the keys of theirs that expire
// within the warning window and have not been warned about.
type ExpiringAPIKeyOwner struct {
	UserID uuid.UUID
	Keys   []mail.ExpiringKey
}

// ClaimExpiringAPIKeys lists, per owner, the usable personal API keys that
// expire within the window the dashboard already uses and marks them as
// warned, so the hourly sweep sends each warning once. The mark is set when
// the warning is queued rather than when it is delivered: a delivery that
// failed is in the record for an administrator to see, and a key warned
// about every hour for a week is the noise that gets the whole channel
// filtered.
func (s *Store) ClaimExpiringAPIKeys(ctx context.Context) ([]ExpiringAPIKeyOwner, error) {
	rows, err := s.Pool.Query(ctx, `UPDATE personal_api_keys k SET expiry_notice_sent_at=now()
        FROM users u WHERE u.id=k.user_id AND u.enabled AND k.expiry_notice_sent_at IS NULL AND `+ExpiringAPIKeyFilter+`
        RETURNING k.user_id,k.id,k.name,k.prefix,k.expires_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	byOwner := map[uuid.UUID]*ExpiringAPIKeyOwner{}
	order := []uuid.UUID{}
	for rows.Next() {
		var userID uuid.UUID
		var key mail.ExpiringKey
		var id uuid.UUID
		var expiresAt time.Time
		if err := rows.Scan(&userID, &id, &key.Name, &key.Prefix, &expiresAt); err != nil {
			return nil, err
		}
		key.ID, key.ExpiresAt = id.String(), expiresAt
		owner, seen := byOwner[userID]
		if !seen {
			owner = &ExpiringAPIKeyOwner{UserID: userID}
			byOwner[userID] = owner
			order = append(order, userID)
		}
		owner.Keys = append(owner.Keys, key)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	owners := make([]ExpiringAPIKeyOwner, 0, len(order))
	for _, userID := range order {
		owners = append(owners, *byOwner[userID])
	}
	return owners, nil
}
