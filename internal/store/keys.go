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

func (s *Store) ActivePrivateKey(ctx context.Context, realmID uuid.UUID) (*rsa.PrivateKey, domain.SigningKey, error) {
	var key domain.SigningKey
	var encrypted []byte
	err := s.Pool.QueryRow(ctx, `SELECT id,realm_id,kid,algorithm,status,public_jwk,created_at,retire_at,private_key_cipher
        FROM signing_keys WHERE realm_id=$1 AND status='ACTIVE'`, realmID).Scan(&key.ID, &key.RealmID, &key.KID,
		&key.Algorithm, &key.Status, &key.PublicJWK, &key.CreatedAt, &key.RetireAt, &encrypted)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.SigningKey{}, ErrNotFound
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

func (s *Store) ListSigningKeys(ctx context.Context, realmID uuid.UUID) ([]domain.SigningKey, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id,realm_id,kid,algorithm,status,public_jwk,created_at,retire_at
        FROM signing_keys WHERE realm_id=$1 AND status <> 'RETIRED' ORDER BY created_at DESC`, realmID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var keys []domain.SigningKey
	for rows.Next() {
		var key domain.SigningKey
		if err := rows.Scan(&key.ID, &key.RealmID, &key.KID, &key.Algorithm, &key.Status,
			&key.PublicJWK, &key.CreatedAt, &key.RetireAt); err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, rows.Err()
}
