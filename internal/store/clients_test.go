package store

import (
	"slices"
	"testing"
)

func TestNormalizeWebOrigins(t *testing.T) {
	got, err := normalizeWebOrigins([]string{" HTTPS://Example.COM/ ", "https://example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{"https://example.com"}) {
		t.Fatalf("normalizeWebOrigins() = %#v", got)
	}
	for _, invalid := range []string{"http://example.com", "https://example.com/path", "https://user@example.com", "*"} {
		if _, err := normalizeWebOrigins([]string{invalid}); err == nil {
			t.Fatalf("invalid origin %q was accepted", invalid)
		}
	}
}

func TestValidateURIsAllowsIPv6Loopback(t *testing.T) {
	if err := validateURIs([]string{"http://[::1]:8080/callback"}, false); err != nil {
		t.Fatalf("IPv6 loopback URI rejected: %v", err)
	}
}
