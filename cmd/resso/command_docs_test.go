package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The documentation tells an operator what to type during an incident, and a
// command that does not exist is discovered at the worst moment, by someone
// already having a bad day. It has happened: a line added here said `resso
// diagnose` where the binary accepts `admin diagnose`.
//
// So every maintenance command the documents name has to be one the binary
// answers. The direction is one way — a command the binary has and the
// documents do not mention is not a fault, since not everything belongs in a
// guide.
func TestDocumentedMaintenanceCommandsExist(t *testing.T) {
	accepted := map[string]bool{
		"healthcheck":    true,
		"admin diagnose": true,
		"admin recover":  true,
		"crypto rewrap":  true,
	}
	// A command named in the documents appears one of two ways: run through
	// the maintenance compose service, or written in backticks on its own.
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`resso-maintenance ([a-z]+(?: [a-z]+)?)`),
		regexp.MustCompile("`((?:admin|crypto) [a-z]+)`"),
		regexp.MustCompile("`resso ([a-z]+(?: [a-z]+)?)`"),
	}
	root := filepath.Join("..", "..")
	documents := []string{"README.md", filepath.Join("docs", "operations.md"),
		filepath.Join("docs", "compatibility.md"), filepath.Join("docs", "user-federation.md"),
		"CHANGELOG.md"}
	found := 0
	for _, name := range documents {
		body, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		for _, pattern := range patterns {
			for _, match := range pattern.FindAllStringSubmatch(string(body), -1) {
				command := strings.TrimSpace(match[1])
				found++
				if !accepted[command] {
					t.Errorf("%s tells an operator to run %q, which the binary does not accept", name, command)
				}
			}
		}
	}
	if found == 0 {
		t.Fatal("no maintenance command was found in the documents; the patterns no longer match how they are written")
	}
}
