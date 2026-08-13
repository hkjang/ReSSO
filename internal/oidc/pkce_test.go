package oidc

import "testing"

func TestValidatePKCERFC7636Example(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if err := ValidatePKCE(challenge, "S256", verifier); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePKCE(challenge, "plain", verifier); err == nil {
		t.Fatal("plain PKCE unexpectedly accepted")
	}
}
