// Package cryptoutil provides ReSSO's authenticated encryption and keyed
// digest primitives, including the split data-encryption and digest keyrings
// that allow rewrapping stored secrets without invalidating live credentials.
package cryptoutil

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
)

const (
	legacyEnvelopeVersion byte = 1
	keyedEnvelopeVersion  byte = 2
	maximumKeyIDLength         = 64
)

// NamedKey identifies 32 bytes of key material. The first key in each
// keyring is active for new values; remaining keys are accepted while old
// encrypted values and opaque credentials age out.
type NamedKey struct {
	ID       string
	Material []byte
}

type encryptionKey struct {
	id   string
	aead cipher.AEAD
}

type digestKey struct {
	id  string
	key []byte
}

// Sealer keeps data encryption and opaque-credential hashing on independent
// keyrings. This permits encryption rewrapping without invalidating sessions,
// authorization codes, refresh tokens, or personal API keys.
type Sealer struct {
	encryptionKeys      []encryptionKey
	digestKeys          []digestKey
	writeLegacyEnvelope bool
}

// NewSealer preserves the v0.2 single-key envelope for rolling upgrades and
// rollback. New deployments should use NewKeyring through keyring config.
func NewSealer(key []byte) (*Sealer, error) {
	legacy := []NamedKey{{ID: "legacy", Material: key}}
	result, err := NewKeyring(legacy, legacy)
	if err == nil {
		result.writeLegacyEnvelope = true
	}
	return result, err
}

func NewKeyring(encryptionKeys, digestKeys []NamedKey) (*Sealer, error) {
	if len(encryptionKeys) == 0 || len(digestKeys) == 0 {
		return nil, errors.New("encryption and digest keyrings must not be empty")
	}
	result := &Sealer{}
	seen := map[string]bool{}
	for _, key := range encryptionKeys {
		if key.ID == "" || len(key.ID) > maximumKeyIDLength || seen[key.ID] {
			return nil, fmt.Errorf("invalid or duplicate encryption key ID %q", key.ID)
		}
		if len(key.Material) != 32 {
			return nil, fmt.Errorf("encryption key %q must be exactly 32 bytes", key.ID)
		}
		block, err := aes.NewCipher(key.Material)
		if err != nil {
			return nil, fmt.Errorf("create AES cipher for %q: %w", key.ID, err)
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("create AES-GCM for %q: %w", key.ID, err)
		}
		result.encryptionKeys = append(result.encryptionKeys, encryptionKey{id: key.ID, aead: aead})
		seen[key.ID] = true
	}
	seen = map[string]bool{}
	for _, key := range digestKeys {
		if key.ID == "" || len(key.ID) > maximumKeyIDLength || seen[key.ID] {
			return nil, fmt.Errorf("invalid or duplicate digest key ID %q", key.ID)
		}
		if len(key.Material) != 32 {
			return nil, fmt.Errorf("digest key %q must be exactly 32 bytes", key.ID)
		}
		macSeed := hmac.New(sha256.New, key.Material)
		_, _ = macSeed.Write([]byte("ReSSO credential hashing v1"))
		result.digestKeys = append(result.digestKeys, digestKey{id: key.ID, key: macSeed.Sum(nil)})
		seen[key.ID] = true
	}
	return result, nil
}

func (s *Sealer) PrimaryEncryptionKeyID() string {
	return s.encryptionKeys[0].id
}

func (s *Sealer) Seal(plaintext, additionalData []byte) ([]byte, error) {
	key := s.encryptionKeys[0]
	nonce := make([]byte, key.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate encryption nonce: %w", err)
	}
	if s.writeLegacyEnvelope {
		out := make([]byte, 0, 1+len(nonce)+len(plaintext)+key.aead.Overhead())
		out = append(out, legacyEnvelopeVersion)
		out = append(out, nonce...)
		return key.aead.Seal(out, nonce, plaintext, additionalData), nil
	}
	out := make([]byte, 0, 2+len(key.id)+len(nonce)+len(plaintext)+key.aead.Overhead())
	out = append(out, keyedEnvelopeVersion, byte(len(key.id)))
	out = append(out, key.id...)
	out = append(out, nonce...)
	out = key.aead.Seal(out, nonce, plaintext, additionalData)
	return out, nil
}

func (s *Sealer) Open(envelope, additionalData []byte) ([]byte, error) {
	if len(envelope) == 0 {
		return nil, errors.New("unsupported or truncated encrypted value")
	}
	switch envelope[0] {
	case legacyEnvelopeVersion:
		for _, key := range s.encryptionKeys {
			if plaintext, err := openWithKey(key, envelope[1:], additionalData); err == nil {
				return plaintext, nil
			}
		}
		return nil, errors.New("encrypted value authentication failed")
	case keyedEnvelopeVersion:
		if len(envelope) < 2 {
			return nil, errors.New("unsupported or truncated encrypted value")
		}
		idLength := int(envelope[1])
		if idLength == 0 || len(envelope) < 2+idLength {
			return nil, errors.New("unsupported or truncated encrypted value")
		}
		keyID := string(envelope[2 : 2+idLength])
		for _, key := range s.encryptionKeys {
			if key.id == keyID {
				return openWithKey(key, envelope[2+idLength:], additionalData)
			}
		}
		return nil, fmt.Errorf("encrypted value references unavailable key %q", keyID)
	default:
		return nil, errors.New("unsupported or truncated encrypted value")
	}
}

func openWithKey(key encryptionKey, payload, additionalData []byte) ([]byte, error) {
	minimum := key.aead.NonceSize() + key.aead.Overhead()
	if len(payload) < minimum {
		return nil, errors.New("unsupported or truncated encrypted value")
	}
	nonceEnd := key.aead.NonceSize()
	plaintext, err := key.aead.Open(nil, payload[:nonceEnd], payload[nonceEnd:], additionalData)
	if err != nil {
		return nil, errors.New("encrypted value authentication failed")
	}
	return plaintext, nil
}

// NeedsRewrap reports whether an encrypted value is legacy or references a
// non-primary data-encryption key. Invalid values are surfaced to the caller.
func (s *Sealer) NeedsRewrap(envelope []byte) (bool, error) {
	if len(envelope) == 0 {
		return false, errors.New("encrypted value is empty")
	}
	if envelope[0] == legacyEnvelopeVersion {
		return !s.writeLegacyEnvelope, nil
	}
	if envelope[0] != keyedEnvelopeVersion || len(envelope) < 2 {
		return false, errors.New("unsupported or truncated encrypted value")
	}
	idLength := int(envelope[1])
	if idLength == 0 || len(envelope) < 2+idLength {
		return false, errors.New("unsupported or truncated encrypted value")
	}
	return string(envelope[2:2+idLength]) != s.PrimaryEncryptionKeyID(), nil
}

func (s *Sealer) Digest(value string) []byte {
	return digestWithKey(value, s.digestKeys[0].key)
}

// Digests returns lookup candidates for every configured digest key, active
// first. Database lookups use these candidates during a rolling key change.
func (s *Sealer) Digests(value string) [][]byte {
	result := make([][]byte, 0, len(s.digestKeys))
	for _, key := range s.digestKeys {
		result = append(result, digestWithKey(value, key.key))
	}
	return result
}

func digestWithKey(value string, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(value))
	return mac.Sum(nil)
}

func (s *Sealer) MatchDigest(value string, expected []byte) bool {
	matched := 0
	for _, actual := range s.Digests(value) {
		matched |= subtle.ConstantTimeCompare(actual, expected)
	}
	return matched == 1
}
