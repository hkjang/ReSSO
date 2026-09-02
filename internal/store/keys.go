package store

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/hkjang/ReSSO/internal/domain"
)

// SigningKeyTTL bounds how long an instance keeps serving a cached key set
// after another instance rotates. A rotated key stays PASSIVE — and therefore
// published and accepted — for two hours, so signing with it for a few more
// seconds cannot produce a token that fails verification.
//
// Exported because it is also the longest a key set this instance publishes can
// be out of date, which is what the JWKS endpoint may let a relying party hold
// it for. See the freshness note there.
const SigningKeyTTL = 30 * time.Second

// minimumKeyReload floors how often an unrecognised key identifier may force a
// read. The reload below turns a cache miss into a database query, and the
// identifier comes off a token the caller supplies, so without a floor anyone
// able to reach an endpoint that parses a token could ask for one query per
// request by inventing identifiers.
const minimumKeyReload = time.Second

type signingKeyEntry struct {
	privateKey *rsa.PrivateKey
	active     domain.SigningKey
	published  []domain.SigningKey
	loadedAt   time.Time
}

// signingKeys caches the per-Realm key material used on the hot path. Loading
// it per request meant a query, an AES-GCM open and a PKCS#8 parse for every
// token issued, and a query plus a JWK unmarshal for every token verified.
// The zero value is usable, so a Store built literally in tests still works.
func (s *Store) cachedSigningKeys(ctx context.Context, realmID uuid.UUID) (signingKeyEntry, error) {
	if cached, found := s.signingKeys.Load(realmID); found {
		if entry, ok := cached.(signingKeyEntry); ok && time.Since(entry.loadedAt) < SigningKeyTTL {
			return entry, nil
		}
	}
	entry, err := s.loadSigningKeys(ctx, realmID)
	if err != nil {
		return signingKeyEntry{}, err
	}
	s.signingKeys.Store(realmID, entry)
	return entry, nil
}

// InvalidateSigningKeys drops the cached key material for a Realm. Rotation
// calls it so the new key is used immediately on this instance.
func (s *Store) InvalidateSigningKeys(realmID uuid.UUID) {
	s.signingKeys.Delete(realmID)
}

// InvalidateAllSigningKeys drops every cached Realm key set. Rewrapping the
// stored ciphertexts does not change the key material, but clearing the cache
// keeps the in-memory state provably consistent with the database.
func (s *Store) InvalidateAllSigningKeys() {
	s.signingKeys.Range(func(key, _ any) bool {
		s.signingKeys.Delete(key)
		return true
	})
}

func (s *Store) loadSigningKeys(ctx context.Context, realmID uuid.UUID) (signingKeyEntry, error) {
	published, err := s.ListSigningKeys(ctx, realmID)
	if err != nil {
		return signingKeyEntry{}, err
	}
	entry := signingKeyEntry{published: published, loadedAt: time.Now()}
	privateKey, active, err := s.loadActivePrivateKey(ctx, realmID)
	if err != nil {
		return signingKeyEntry{}, err
	}
	// Precompute once, while the key is still private to this goroutine.
	// crypto/rsa mutates the key on first use otherwise, which would be a data
	// race between concurrent signers sharing the cached pointer.
	privateKey.Precompute()
	// The set that is published and the key that signs come from two queries,
	// and they have to agree: signing with a key the JWKS omits produces tokens
	// that every relying party refuses, which looks like the signature being
	// wrong rather than like a key that is missing. The two could not disagree
	// until retirement started being decided by retire_at — the active key was
	// simply never RETIRED — so this closes what that opened. Refusing here is
	// the better failure: it names the key, in one place, instead of appearing
	// as every token being rejected everywhere.
	if _, found := findSigningKey(published, active.KID); !found {
		return signingKeyEntry{}, fmt.Errorf(
			"signing key %s of Realm %s is active but not published; refusing to sign with a key the JWKS omits",
			active.KID, realmID)
	}
	entry.privateKey, entry.active = privateKey, active
	return entry, nil
}

func keyAAD(realmID uuid.UUID, kid string) []byte {
	return []byte("ReSSO/signing-key/" + realmID.String() + "/" + kid)
}

func (s *Store) EnsureActiveSigningKey(ctx context.Context, realmID uuid.UUID) error {
	var exists bool
	if err := s.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM signing_keys
        WHERE realm_id=$1 AND status='ACTIVE')`, realmID).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return nil
	}
	_, err := s.RotateSigningKey(ctx, realmID)
	return err
}

func (s *Store) RotateSigningKey(ctx context.Context, realmID uuid.UUID) (domain.SigningKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return domain.SigningKey{}, fmt.Errorf("generate RSA signing key: %w", err)
	}
	kid := "rsa-" + time.Now().UTC().Format("20060102") + "-" + uuid.NewString()[:8]
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return domain.SigningKey{}, fmt.Errorf("encode RSA signing key: %w", err)
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	ciphertext, err := s.Sealer.Seal(privatePEM, keyAAD(realmID, kid))
	if err != nil {
		return domain.SigningKey{}, err
	}
	jwk := jose.JSONWebKey{Key: &privateKey.PublicKey, KeyID: kid, Algorithm: "RS256", Use: "sig"}
	publicJSON, err := json.Marshal(jwk)
	if err != nil {
		return domain.SigningKey{}, fmt.Errorf("encode public JWK: %w", err)
	}

	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return domain.SigningKey{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, "SELECT id FROM realms WHERE id=$1 FOR UPDATE", realmID); err != nil {
		return domain.SigningKey{}, fmt.Errorf("lock realm for key rotation: %w", err)
	}
	retireAt := time.Now().UTC().Add(2 * time.Hour)
	if _, err := tx.Exec(ctx, `UPDATE signing_keys SET status='PASSIVE',retire_at=$2
        WHERE realm_id=$1 AND status='ACTIVE'`, realmID, retireAt); err != nil {
		return domain.SigningKey{}, fmt.Errorf("retire prior signing key: %w", err)
	}
	defer s.InvalidateSigningKeys(realmID)
	result := domain.SigningKey{ID: uuid.New(), RealmID: realmID, KID: kid, Algorithm: "RS256", Status: "ACTIVE", PublicJWK: publicJSON, CreatedAt: time.Now().UTC()}
	if _, err := tx.Exec(ctx, `INSERT INTO signing_keys(id,realm_id,kid,algorithm,status,private_key_cipher,public_jwk,created_at)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, result.ID, realmID, kid, result.Algorithm, result.Status,
		ciphertext, publicJSON, result.CreatedAt); err != nil {
		return domain.SigningKey{}, fmt.Errorf("save signing key: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.SigningKey{}, err
	}
	return result, nil
}

// ActivePrivateKey returns the Realm's current signing key, served from the
// per-Realm cache. Callers must not mutate the returned key.
func (s *Store) ActivePrivateKey(ctx context.Context, realmID uuid.UUID) (*rsa.PrivateKey, domain.SigningKey, error) {
	entry, err := s.cachedSigningKeys(ctx, realmID)
	if err != nil {
		return nil, domain.SigningKey{}, err
	}
	return entry.privateKey, entry.active, nil
}

// PublishedSigningKeys returns every non-retired key of a Realm for the JWKS
// document, served from the same cache.
func (s *Store) PublishedSigningKeys(ctx context.Context, realmID uuid.UUID) ([]domain.SigningKey, error) {
	entry, err := s.cachedSigningKeys(ctx, realmID)
	if err != nil {
		return nil, err
	}
	return entry.published, nil
}

// SigningKeyByKID returns the published key a token names, reading through the
// cache once when the identifier is one this instance has never seen.
//
// The cache was reasoned about in one direction only: an instance that keeps
// signing with the key another instance just rotated away is safe, because the
// old key stays published and accepted for two hours. The other direction was
// the problem. A rotation on one instance invalidates that instance's cache
// alone, so every other instance kept a key set that did not contain the new
// identifier and rejected the tokens the first instance was issuing — for as
// long as its cache had left. The same stale set is what those instances served
// as their JWKS, so a relying party fetching in that window, which is exactly
// what a relying party does when it meets an identifier it does not know, could
// cache a set missing the new key for as long as its own cache lives — well
// past the window that caused it.
//
// An identifier this instance has never seen is a precise signal that the set
// may be out of date, so it is worth one read. Refreshing here also refreshes
// what the JWKS endpoint serves, which is the same entry.
func (s *Store) SigningKeyByKID(ctx context.Context, realmID uuid.UUID, kid string) (domain.SigningKey, error) {
	entry, err := s.cachedSigningKeys(ctx, realmID)
	if err != nil {
		return domain.SigningKey{}, err
	}
	if key, found := findSigningKey(entry.published, kid); found {
		return key, nil
	}
	if time.Since(entry.loadedAt) < minimumKeyReload {
		return domain.SigningKey{}, ErrNotFound
	}
	refreshed, err := s.loadSigningKeys(ctx, realmID)
	if err != nil {
		return domain.SigningKey{}, err
	}
	s.signingKeys.Store(realmID, refreshed)
	if key, found := findSigningKey(refreshed.published, kid); found {
		return key, nil
	}
	return domain.SigningKey{}, ErrNotFound
}

func findSigningKey(keys []domain.SigningKey, kid string) (domain.SigningKey, bool) {
	for _, key := range keys {
		if key.KID == kid {
			return key, true
		}
	}
	return domain.SigningKey{}, false
}

// ErrNoActiveSigningKey reports that the Realm has no key to sign with.
//
// It wraps ErrNotFound so that callers which only ask "was something missing"
// keep working, and is distinguishable because the token endpoint must not
// answer invalid_grant for it. That answer tells a relying party its code or
// refresh token is bad, and the ordinary response is to discard it and send
// the person back to sign in — which also cannot work while the key is gone.
// A Realm that lost its signing key would come back to find the sessions that
// could have survived thrown away by every client that tried during it.
var ErrNoActiveSigningKey = fmt.Errorf("realm has no active signing key: %w", ErrNotFound)

func (s *Store) loadActivePrivateKey(ctx context.Context, realmID uuid.UUID) (*rsa.PrivateKey, domain.SigningKey, error) {
	var key domain.SigningKey
	var encrypted []byte
	err := s.Pool.QueryRow(ctx, `SELECT id,realm_id,kid,algorithm,status,public_jwk,created_at,retire_at,private_key_cipher
        FROM signing_keys WHERE realm_id=$1 AND status='ACTIVE'`, realmID).Scan(&key.ID, &key.RealmID, &key.KID,
		&key.Algorithm, &key.Status, &key.PublicJWK, &key.CreatedAt, &key.RetireAt, &encrypted)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.SigningKey{}, ErrNoActiveSigningKey
	}
	if err != nil {
		return nil, domain.SigningKey{}, err
	}
	plain, err := s.Sealer.Open(encrypted, keyAAD(realmID, key.KID))
	if err != nil {
		return nil, domain.SigningKey{}, fmt.Errorf("decrypt signing key %s: %w", key.KID, err)
	}
	block, _ := pem.Decode(plain)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, domain.SigningKey{}, errors.New("stored signing key is not PKCS#8 PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, domain.SigningKey{}, fmt.Errorf("parse stored signing key: %w", err)
	}
	privateKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, domain.SigningKey{}, errors.New("stored signing key is not RSA")
	}
	return privateKey, key, nil
}

// ListSigningKeys returns the keys of a Realm that are still in effect: the
// JWKS document, signature verification and the console all read this.
//
// A key is out of effect the moment retire_at passes, and that moment is now
// what decides it. Only the status column used to, and nothing writes that
// column except the hourly retention pass — so a key stayed published, stayed
// accepted, and stayed on the console as PASSIVE for up to an hour after the
// time it was retired, next to a column stating the retirement time that had
// already gone by. Rotation is what an operator reaches for when a key may
// have leaked, and the window it promises is not one to leave in the hands of
// a job that exists to delete old rows. The retention pass still marks the
// status so the row records what happened; it no longer decides it.
//
// The per-Realm cache can still serve a key for its own lifetime past that
// moment, which is bounded by SigningKeyTTL rather than by an hour.
func (s *Store) ListSigningKeys(ctx context.Context, realmID uuid.UUID) ([]domain.SigningKey, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id,realm_id,kid,algorithm,status,public_jwk,created_at,retire_at,
        GREATEST(0, EXTRACT(day FROM now()-created_at))::int
        FROM signing_keys WHERE realm_id=$1 AND status <> 'RETIRED'
        AND (retire_at IS NULL OR retire_at > now()) ORDER BY created_at DESC`, realmID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	// Empty is an empty list, not the absence of one: the console reads this
	// straight into .length, and a Realm whose key could not be created — which
	// this service records as a partial creation and sends the operator here to
	// put right — is exactly when it is empty.
	keys := make([]domain.SigningKey, 0)
	for rows.Next() {
		var key domain.SigningKey
		if err := rows.Scan(&key.ID, &key.RealmID, &key.KID, &key.Algorithm, &key.Status,
			&key.PublicJWK, &key.CreatedAt, &key.RetireAt, &key.AgeDays); err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, rows.Err()
}
