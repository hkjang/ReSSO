package store

import (
	"errors"
	"strings"
	"testing"
)

func TestNormalizeOptionalEmail(t *testing.T) {
	label := strings.Repeat("a", 63)
	maxDomain := strings.Join([]string{label, label, label, label}, ".")
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "empty", input: " \t ", want: ""},
		{name: "trim and lowercase", input: "  Alice.Example+Tag@EXAMPLE.COM  ", want: "alice.example+tag@example.com"},
		{name: "maximum supported length", input: strings.Repeat("a", 64) + "@" + maxDomain, want: strings.Repeat("a", 64) + "@" + maxDomain},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := normalizeOptionalEmail(test.input)
			if err != nil || got != test.want {
				t.Fatalf("normalizeOptionalEmail(%q) = %q, %v; want %q", test.input, got, err, test.want)
			}
		})
	}
}

func TestNormalizeOptionalEmailRejectsInvalidMailbox(t *testing.T) {
	invalid := []string{
		"Display Name <user@example.com>",
		"first@example.com,second@example.com",
		"missing-at.example.com",
		"two@@example.com",
		"user name@example.com",
		"\"quoted\"@example.com",
		"usér@example.com",
		".user@example.com",
		"user..name@example.com",
		"user@-example.com",
		"user@example-.com",
		"user@example..com",
		strings.Repeat("a", 65) + "@example.com",
		"user@" + strings.Repeat("a", 64) + ".com",
		strings.Repeat("a", 64) + "@" + strings.Repeat("b", 256),
	}
	for _, input := range invalid {
		t.Run(input, func(t *testing.T) {
			if _, err := normalizeOptionalEmail(input); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("normalizeOptionalEmail(%q) error = %v; want ErrInvalidInput", input, err)
			}
		})
	}
}
