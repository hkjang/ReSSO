package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
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

// The image's VERSION build argument is passed by `make image` and by the
// release workflow, so its default only applies to a bare `docker build .` —
// and a real version number there goes stale the moment the next release
// lands. It had been sitting at v0.4.1-dev five releases later, which meant an
// image built that way labelled itself, and answered /api/v1/meta with, a
// version that shipped months earlier. For an appliance whose images are
// carried between machines on a disk, that label is how you tell what you have.
//
// So the default must not be able to pass for a release. Comparing it against
// the changelog is the check that says exactly that, and it keeps saying it
// without anyone maintaining a list.
func TestImageVersionDefaultCannotPassForARelease(t *testing.T) {
	root := filepath.Join("..", "..")
	dockerfile, err := os.ReadFile(filepath.Join(root, "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	defaults := regexp.MustCompile(`(?m)^ARG VERSION=(\S+)`).FindAllStringSubmatch(string(dockerfile), -1)
	if len(defaults) == 0 {
		t.Fatal("the Dockerfile no longer declares a VERSION build argument")
	}
	changelog, err := os.ReadFile(filepath.Join(root, "CHANGELOG.md"))
	if err != nil {
		t.Fatal(err)
	}
	released := map[string]bool{}
	for _, match := range regexp.MustCompile(`(?m)^## (v[\d.]+)\s*$`).FindAllStringSubmatch(string(changelog), -1) {
		released[match[1]] = true
	}
	if len(released) == 0 {
		t.Fatal("no released versions were found in the changelog, so nothing is being compared")
	}
	for _, match := range defaults {
		bare := strings.TrimSuffix(match[1], "-dev")
		if released[bare] || released[match[1]] {
			t.Errorf("the Dockerfile defaults VERSION to %s, which names a release: an image built "+
				"without --build-arg VERSION would claim to be one", match[1])
		}
	}
}
