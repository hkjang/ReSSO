package oidc

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
)

func ValidatePKCE(challenge, method, verifier string) error {
	if challenge == "" {
		return errors.New("authorization code has no PKCE challenge")
	}
	if method != "S256" {
		return errors.New("only the S256 PKCE method is supported")
	}
	if len(verifier) < 43 || len(verifier) > 128 {
		return errors.New("code_verifier length must be between 43 and 128 characters")
	}
	digest := sha256.Sum256([]byte(verifier))
	actual := base64.RawURLEncoding.EncodeToString(digest[:])
	if subtle.ConstantTimeCompare([]byte(actual), []byte(challenge)) != 1 {
		return errors.New("code_verifier does not match the authorization request")
	}
	return nil
}
