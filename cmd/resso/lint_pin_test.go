package main

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// The linter version is named twice: CI installs one, and the Makefile tells a
// contributor which to install. A newer local binary passes on rules the CI one
// reports, and an older one reports rules CI does not have — either way `make
// lint` says the work is fine and the push disagrees, naming a rule the local
// binary never mentioned. Two places holding the same fact is the shape this
// service keeps finding, so the two are compared here.
func TestLinterVersionIsTheSameLocallyAndInCI(t *testing.T) {
	root := filepath.Join("..", "..")
	read := func(name string) string {
		t.Helper()
		content, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		return string(content)
	}

	makefile := regexp.MustCompile(`(?m)^GOLANGCI_VERSION\s*=\s*(v[\d.]+)\s*$`).
		FindStringSubmatch(read("Makefile"))
	if makefile == nil {
		t.Fatal("the Makefile no longer pins GOLANGCI_VERSION, so nothing tells a contributor which linter CI uses")
	}
	workflow := regexp.MustCompile(`golangci-lint-action@[^\n]*\n(?:.*\n)?\s*with:\s*\n\s*version:\s*(v[\d.]+)`).
		FindStringSubmatch(read(filepath.Join(".github", "workflows", "ci.yaml")))
	if workflow == nil {
		t.Fatal("CI no longer pins a golangci-lint version, so the Makefile's pin cannot be checked against it")
	}

	if makefile[1] != workflow[1] {
		t.Errorf("the Makefile installs golangci-lint %s and CI runs %s: `make lint` and the push "+
			"will disagree about which rules apply", makefile[1], workflow[1])
	}
}
