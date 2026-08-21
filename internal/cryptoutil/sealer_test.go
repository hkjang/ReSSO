package cryptoutil

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"strings"
	"testing"
)

func TestSealRoundTripAndAAD(t *testing.T) {
	s, err := NewSealer([]byte(strings.Repeat("x", 32)))
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := s.Seal([]byte("private-key"), []byte("realm/key"))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := s.Open(encrypted, []byte("realm/key"))
	if err != nil || !bytes.Equal(plain, []byte("private-key")) {
		t.Fatalf("round trip failed: plain=%q err=%v", plain, err)
	}
	if _, err := s.Open(encrypted, []byte("other/key")); err == nil {
		t.Fatal("Open accepted different associated data")
	}
}

func TestDigest(t *testing.T) {
	s, _ := NewSealer([]byte(strings.Repeat("y", 32)))
	if !s.MatchDigest("token", s.Digest("token")) || s.MatchDigest("other", s.Digest("token")) {
		t.Fatal("digest comparison mismatch")
	}
}

func TestSingleKeyModeKeepsLegacyEnvelopeForRollback(t *testing.T) {
	s, err := NewSealer([]byte(strings.Repeat("z", 32)))
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := s.Seal([]byte("private-key"), []byte("realm/key"))
	if err != nil {
		t.Fatal(err)
	}
	if encrypted[0] != legacyEnvelopeVersion {
		t.Fatalf("single-key envelope version = %d, want %d", encrypted[0], legacyEnvelopeVersion)
	}
	if needs, err := s.NeedsRewrap(encrypted); err != nil || needs {
		t.Fatalf("single-key legacy envelope should remain primary: needs=%v err=%v", needs, err)
	}
}

func TestKeyringReadsLegacyEnvelopeAndDigest(t *testing.T) {
	oldMaterial := []byte(strings.Repeat("o", 32))
	newMaterial := []byte(strings.Repeat("n", 32))
	legacy, err := legacySealForTest(oldMaterial, []byte("private-key"), []byte("realm/key"))
	if err != nil {
		t.Fatal(err)
	}
	old, _ := NewSealer(oldMaterial)
	keyring, err := NewKeyring(
		[]NamedKey{{ID: "new", Material: newMaterial}, {ID: "old", Material: oldMaterial}},
		[]NamedKey{{ID: "new", Material: newMaterial}, {ID: "old", Material: oldMaterial}},
	)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := keyring.Open(legacy, []byte("realm/key"))
	if err != nil || !bytes.Equal(plain, []byte("private-key")) {
		t.Fatalf("legacy envelope failed: plain=%q err=%v", plain, err)
	}
	if !keyring.MatchDigest("token", old.Digest("token")) {
		t.Fatal("old digest key was not accepted")
	}
	if bytes.Equal(keyring.Digest("token"), old.Digest("token")) {
		t.Fatal("new values did not use the primary digest key")
	}
	if needs, err := keyring.NeedsRewrap(legacy); err != nil || !needs {
		t.Fatalf("legacy rewrap decision = %v, %v", needs, err)
	}
	rewrapped, err := keyring.Seal(plain, []byte("realm/key"))
	if err != nil {
		t.Fatal(err)
	}
	if needs, err := keyring.NeedsRewrap(rewrapped); err != nil || needs {
		t.Fatalf("primary rewrap decision = %v, %v", needs, err)
	}
}

func legacySealForTest(material, plaintext, additionalData []byte) ([]byte, error) {
	block, err := aes.NewCipher(material)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := bytes.Repeat([]byte{7}, aead.NonceSize())
	out := append([]byte{legacyEnvelopeVersion}, nonce...)
	return aead.Seal(out, nonce, plaintext, additionalData), nil
}
