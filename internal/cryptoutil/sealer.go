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

const envelopeVersion byte = 1

// Sealer encrypts private signing material and creates keyed hashes for
// opaque credentials. Keeping these operations in one component prevents
// accidental plaintext secret persistence.
type Sealer struct {
	aead    cipher.AEAD
	hmacKey []byte
}

func NewSealer(key []byte) (*Sealer, error) {
	if len(key) != 32 {
		return nil, errors.New("encryption key must be exactly 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create AES-GCM: %w", err)
	}
	macSeed := hmac.New(sha256.New, key)
	_, _ = macSeed.Write([]byte("ReSSO credential hashing v1"))
	return &Sealer{aead: aead, hmacKey: macSeed.Sum(nil)}, nil
}

func (s *Sealer) Seal(plaintext, additionalData []byte) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate encryption nonce: %w", err)
	}
	out := make([]byte, 1, 1+len(nonce)+len(plaintext)+s.aead.Overhead())
	out[0] = envelopeVersion
	out = append(out, nonce...)
	out = s.aead.Seal(out, nonce, plaintext, additionalData)
	return out, nil
}

func (s *Sealer) Open(envelope, additionalData []byte) ([]byte, error) {
	minimum := 1 + s.aead.NonceSize() + s.aead.Overhead()
	if len(envelope) < minimum || envelope[0] != envelopeVersion {
		return nil, errors.New("unsupported or truncated encrypted value")
	}
	nonceEnd := 1 + s.aead.NonceSize()
	plaintext, err := s.aead.Open(nil, envelope[1:nonceEnd], envelope[nonceEnd:], additionalData)
	if err != nil {
		return nil, errors.New("encrypted value authentication failed")
	}
	return plaintext, nil
}

func (s *Sealer) Digest(value string) []byte {
	mac := hmac.New(sha256.New, s.hmacKey)
	_, _ = mac.Write([]byte(value))
	return mac.Sum(nil)
}

func (s *Sealer) MatchDigest(value string, expected []byte) bool {
	actual := s.Digest(value)
	return subtle.ConstantTimeCompare(actual, expected) == 1
}
