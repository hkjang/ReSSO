package httpserver

import (
	"slices"
	"testing"
)

func TestValidatedScopesRequireOpenIDAndPreventEscalation(t *testing.T) {
	allowed := []string{"openid", "profile", "email", "roles"}
	got, err := validatedScopes("openid email email", allowed, true)
	if err != nil || !slices.Equal(got, []string{"openid", "email"}) {
		t.Fatalf("validatedScopes() = %v, %v", got, err)
	}
	if _, err := validatedScopes("profile", allowed, true); err == nil {
		t.Fatal("scope without openid was accepted")
	}
	if _, err := validatedScopes("openid admin:read", allowed, true); err == nil {
		t.Fatal("scope escalation was accepted")
	}
}
