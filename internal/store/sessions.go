package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/hkjang/ReSSO/internal/cryptoutil"
	"github.com/hkjang/ReSSO/internal/domain"
)

// sessionIsLive is the single definition of an acceptable session, applied
// wherever one is checked. Splitting it across call sites is how a path gets
// forgotten: the absolute lifetime was enforced in four places and an idle
// timeout added to only some of them would let a stale session keep issuing
// tokens. `s` must alias sso_sessions and `r` the owning realm.
const sessionIsLive = `s.revoked_at IS NULL AND s.expires_at>now()
        AND (r.idle_timeout_seconds = 0 OR s.last_access > now()-make_interval(secs => r.idle_timeout_seconds))`

type NewSession struct {
	Session   domain.Session
	Token     string
	CSRFToken string
}

func (s *Store) CreateSession(ctx context.Context, realmID, userID uuid.UUID, ttl time.Duration, ip, userAgent, method string) (NewSession, error) {
	token, err := cryptoutil.RandomToken(32)
	if err != nil {
		return NewSession{}, err
	}
	csrf, err := cryptoutil.RandomToken(24)
	if err != nil {
		return NewSession{}, err
	}
	now := time.Now().UTC()
	session := domain.Session{ID: uuid.New(), RealmID: realmID, UserID: userID, IPAddress: ip,
		UserAgent: userAgent, AuthMethod: method, CreatedAt: now, LastAccess: now, ExpiresAt: now.Add(ttl)}
	_, err = s.Pool.Exec(ctx, `INSERT INTO sso_sessions(id,realm_id,user_id,token_hash,csrf_hash,ip_address,
        user_agent,auth_method,created_at,last_access,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$9,$10)`,
		session.ID, realmID, userID, s.Sealer.Digest(token), s.Sealer.Digest(csrf), ip, userAgent, method, now, session.ExpiresAt)
	if err != nil {
		return NewSession{}, fmt.Errorf("create SSO session: %w", err)
	}
	return NewSession{Session: session, Token: token, CSRFToken: csrf}, nil
}

type AuthenticatedSession struct {
	Session    domain.Session
	User       domain.User
	CSRFHash   []byte
	RealmAdmin bool
}

// touchSession records that a session was used.
//
// Idle expiry ends sessions nobody is using, so every path that enforces it
// has to be a path that also renews it. Only the browser console did, which
// meant a session driven entirely through OIDC — a relying party refreshing
// tokens for somebody working in it all day — looked idle from the moment they
// signed in. The write is skipped while the timestamp is fresh, because
// otherwise every token verification would write a row; the staleness test is
// part of the statement so it costs nothing and asks the same clock that
// decides whether the session is live at all.
func (s *Store) touchSession(ctx context.Context, id uuid.UUID) {
	_, _ = s.Pool.Exec(ctx, `UPDATE sso_sessions SET last_access=now()
        WHERE id=$1 AND last_access < now()-interval '1 minute'`, id)
}

func (s *Store) SessionByToken(ctx context.Context, rawToken string) (AuthenticatedSession, error) {
	if rawToken == "" {
		return AuthenticatedSession{}, ErrNotFound
	}
	var result AuthenticatedSession
	err := s.Pool.QueryRow(ctx, `SELECT s.id,s.realm_id,s.user_id,u.username,s.ip_address,s.user_agent,s.auth_method,
        s.created_at,s.last_access,s.expires_at,s.revoked_at,s.csrf_hash,
		u.id,u.realm_id,u.username,u.email,u.email_verified,u.display_name,u.enabled,u.platform_admin,u.manager_id,
		u.federation_id,u.external_id,u.external_dn,u.federation_synced_at,
		u.failed_attempts,u.locked_until,u.password_changed_at,u.created_at,u.updated_at,
		EXISTS(SELECT 1 FROM user_roles ur JOIN roles rr ON rr.id=ur.role_id
		    WHERE ur.user_id=u.id AND rr.name='realm-admin')
        FROM sso_sessions s JOIN users u ON u.id=s.user_id JOIN realms r ON r.id=s.realm_id
        WHERE s.token_hash=ANY($1::bytea[]) AND `+sessionIsLive+` AND u.enabled=true`, s.Sealer.Digests(rawToken)).Scan(
		&result.Session.ID, &result.Session.RealmID, &result.Session.UserID, &result.Session.Username,
		&result.Session.IPAddress, &result.Session.UserAgent, &result.Session.AuthMethod, &result.Session.CreatedAt,
		&result.Session.LastAccess, &result.Session.ExpiresAt, &result.Session.RevokedAt, &result.CSRFHash,
		&result.User.ID, &result.User.RealmID, &result.User.Username, &result.User.Email, &result.User.EmailVerified, &result.User.DisplayName,
		&result.User.Enabled, &result.User.PlatformAdmin, &result.User.ManagerID, &result.User.FederationID,
		&result.User.ExternalID, &result.User.ExternalDN, &result.User.FederationSyncedAt,
		&result.User.FailedAttempts, &result.User.LockedUntil, &result.User.PasswordChanged,
		&result.User.CreatedAt, &result.User.UpdatedAt, &result.RealmAdmin)
	if errors.Is(err, pgx.ErrNoRows) {
		return AuthenticatedSession{}, ErrNotFound
	}
	if err != nil {
		return AuthenticatedSession{}, err
	}
	s.touchSession(ctx, result.Session.ID)
	return result, nil
}

// SessionAuthenticatedRecently reports whether the session proved who the user
// is within the given number of seconds.
//
// The comparison belongs to the database rather than to this process. It is
// the answer to a relying party's max_age, so getting it wrong in one
// direction accepts an authentication older than was asked for — which is the
// whole point of the parameter — and in the other turns a working sign-in into
// an unexplained loop back to the login page. Every other lifetime in the
// schema is judged by now(), and this one is judged against a timestamp the
// same database wrote.
func (s *Store) SessionAuthenticatedRecently(ctx context.Context, id uuid.UUID, withinSeconds int) (bool, error) {
	var recent bool
	err := s.Pool.QueryRow(ctx, `SELECT s.created_at > now()-make_interval(secs => $2)
		FROM sso_sessions s JOIN realms r ON r.id=s.realm_id
		WHERE s.id=$1 AND `+sessionIsLive, id, withinSeconds).Scan(&recent)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrNotFound
	}
	return recent, err
}

func (s *Store) SessionAuthTime(ctx context.Context, id uuid.UUID) (time.Time, error) {
	var authTime time.Time
	err := s.Pool.QueryRow(ctx, `SELECT s.created_at FROM sso_sessions s
		JOIN realms r ON r.id=s.realm_id
		WHERE s.id=$1 AND `+sessionIsLive, id).Scan(&authTime)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, ErrNotFound
	}
	if err == nil {
		s.touchSession(ctx, id)
	}
	return authTime, err
}

// ValidateActiveSessionBinding verifies that a user access token's signed sid
// still names an active session for the exact subject and Realm. Checking all
// three identifiers prevents a non-user token from borrowing an unrelated
// user's UUID as its subject.
func (s *Store) ValidateActiveSessionBinding(ctx context.Context, sessionID, userID, realmID uuid.UUID) error {
	var valid bool
	err := s.Pool.QueryRow(ctx, `SELECT EXISTS(
		SELECT 1 FROM sso_sessions s
		JOIN users u ON u.id=s.user_id
		JOIN realms r ON r.id=s.realm_id
		WHERE s.id=$1 AND s.user_id=$2 AND s.realm_id=$3 AND u.realm_id=$3
			AND `+sessionIsLive+` AND u.enabled=true
	)`, sessionID, userID, realmID).Scan(&valid)
	if err != nil {
		return err
	}
	if !valid {
		return ErrNotFound
	}
	s.touchSession(ctx, sessionID)
	return nil
}

func (s *Store) ValidateCSRF(session AuthenticatedSession, csrf string) bool {
	return csrf != "" && s.Sealer.MatchDigest(csrf, session.CSRFHash)
}

// RevokedSession identifies a session that has just ended, so that relying
// parties registered for back-channel logout can be told about it.
type RevokedSession struct {
	RealmID   uuid.UUID
	SessionID uuid.UUID
	UserID    uuid.UUID
}

// SessionRevocationHook is called after each session is revoked. Store.
// OnSessionRevoked is wired to the back-channel logout notifier in cmd/resso;
// the Store itself performs no outbound requests, keeping HTTP and JWT signing
// out of the data layer. Implementations must not block the caller.
type SessionRevocationHook func(RevokedSession)

func (s *Store) notifyRevoked(sessions []RevokedSession) {
	if s.OnSessionRevoked == nil {
		return
	}
	for _, session := range sessions {
		s.OnSessionRevoked(session)
	}
}

func (s *Store) RevokeSession(ctx context.Context, id uuid.UUID) error {
	var revoked RevokedSession
	err := s.Pool.QueryRow(ctx, `UPDATE sso_sessions SET revoked_at=COALESCE(revoked_at,now())
        WHERE id=$1 RETURNING realm_id,id,user_id`, id).Scan(&revoked.RealmID, &revoked.SessionID, &revoked.UserID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	_, _ = s.Pool.Exec(ctx, `UPDATE refresh_tokens SET revoked_at=COALESCE(revoked_at,now()) WHERE session_id=$1`, id)
	s.notifyRevoked([]RevokedSession{revoked})
	return nil
}

func (s *Store) RevokeAllUserSessions(ctx context.Context, userID uuid.UUID, except *uuid.UUID) error {
	rows, err := s.Pool.Query(ctx, `UPDATE sso_sessions SET revoked_at=COALESCE(revoked_at,now())
        WHERE user_id=$1 AND ($2::uuid IS NULL OR id<>$2) AND revoked_at IS NULL
        RETURNING realm_id,id,user_id`, userID, except)
	if err != nil {
		return err
	}
	revoked := make([]RevokedSession, 0)
	for rows.Next() {
		var session RevokedSession
		if err := rows.Scan(&session.RealmID, &session.SessionID, &session.UserID); err != nil {
			rows.Close()
			return err
		}
		revoked = append(revoked, session)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	_, _ = s.Pool.Exec(ctx, `UPDATE refresh_tokens SET revoked_at=COALESCE(revoked_at,now())
        WHERE user_id=$1 AND ($2::uuid IS NULL OR session_id<>$2)`, userID, except)
	s.notifyRevoked(revoked)
	return nil
}

// BackchannelLogoutTargets lists the enabled clients of a Realm that registered
// a back-channel logout URI and actually took part in the given session.
func (s *Store) BackchannelLogoutTargets(ctx context.Context, realmID, sessionID uuid.UUID) ([]domain.Client, error) {
	rows, err := s.Pool.Query(ctx, "SELECT "+clientColumns+` FROM clients c
        WHERE c.realm_id=$1 AND c.enabled=true AND c.backchannel_logout_uri <> ''
        AND (EXISTS(SELECT 1 FROM refresh_tokens t WHERE t.client_id=c.id AND t.session_id=$2)
            OR EXISTS(SELECT 1 FROM authorization_codes a WHERE a.client_id=c.id AND a.session_id=$2))
        ORDER BY c.client_id`, realmID, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	clients := make([]domain.Client, 0)
	for rows.Next() {
		client, err := scanClient(rows)
		if err != nil {
			return nil, err
		}
		clients = append(clients, client)
	}
	return clients, rows.Err()
}

func (s *Store) ListSessions(ctx context.Context, realmID *uuid.UUID, userID *uuid.UUID, limit int) ([]domain.Session, error) {
	if limit < 1 || limit > 500 {
		limit = 100
	}
	// Whether a session is still usable is answered here with the same
	// predicate that decides it everywhere else. A reader cannot derive it
	// from the columns: idle expiry refuses a session while expires_at is
	// still comfortably in the future.
	rows, err := s.Pool.Query(ctx, `SELECT s.id,s.realm_id,s.user_id,u.username,s.ip_address,s.user_agent,
        s.auth_method,s.created_at,s.last_access,s.expires_at,s.revoked_at,`+sessionIsLive+`
        FROM sso_sessions s
        JOIN users u ON u.id=s.user_id
        JOIN realms r ON r.id=s.realm_id
        WHERE ($1::uuid IS NULL OR s.realm_id=$1)
        AND ($2::uuid IS NULL OR s.user_id=$2) ORDER BY s.last_access DESC LIMIT $3`, realmID, userID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	sessions := make([]domain.Session, 0)
	for rows.Next() {
		var session domain.Session
		if err := rows.Scan(&session.ID, &session.RealmID, &session.UserID, &session.Username,
			&session.IPAddress, &session.UserAgent, &session.AuthMethod, &session.CreatedAt,
			&session.LastAccess, &session.ExpiresAt, &session.RevokedAt, &session.Active); err != nil {
			return nil, err
		}
		sessions = append(sessions, session)
	}
	return sessions, rows.Err()
}
