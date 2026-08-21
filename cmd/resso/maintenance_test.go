package main

import (
	"strings"
	"testing"
)

func TestReadPassword(t *testing.T) {
	password, err := readPassword(strings.NewReader("correct horse battery staple\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if password != "correct horse battery staple" {
		t.Fatalf("password = %q", password)
	}
}

func TestReadPasswordRejectsEmptyAndOversizedInput(t *testing.T) {
	if _, err := readPassword(strings.NewReader("\r\n")); err == nil {
		t.Fatal("empty password was accepted")
	}
	if _, err := readPassword(strings.NewReader(strings.Repeat("x", 4097))); err == nil {
		t.Fatal("oversized password was accepted")
	}
	if _, err := readPassword(strings.NewReader("first-line\nsecond-line\n")); err == nil {
		t.Fatal("multiline password was accepted")
	}
	if _, err := readPassword(strings.NewReader("contains\x00nul\n")); err == nil {
		t.Fatal("NUL-containing password was accepted")
	}
}

func TestMaintenanceCommandRequiresSubcommand(t *testing.T) {
	err := runMaintenanceCommand([]string{"admin"}, strings.NewReader(""), &strings.Builder{}, &strings.Builder{})
	if err == nil || !strings.Contains(err.Error(), "usage:") {
		t.Fatalf("error = %v", err)
	}
}
