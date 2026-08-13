package cryptoutil

import (
	"bytes"
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
