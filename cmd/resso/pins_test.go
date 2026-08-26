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

// The toolchains are pinned in more than one place: go.mod names the Go
// version, ci.yaml and the release workflow resolve it from there, and the
// Dockerfile names its own base image. Node is pinned in the Dockerfile and in
// both workflows.
//
// They agree today. Nothing keeps them agreeing, and the drift is quiet in the
// direction that matters: raise go.mod's toolchain for a fix in the standard
// library and forget the Dockerfile, and everything is tested on the new Go
// while the binary that ships is still built on the old one. The image is the
// artifact; the tests are not.
func TestToolchainPinsAgreeAcrossTheBuild(t *testing.T) {
	root := filepath.Join("..", "..")
	read := func(name string) string {
		t.Helper()
		content, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		return string(content)
	}
	dockerfile := read("Dockerfile")

	image := regexp.MustCompile(`FROM golang:(\d+\.\d+\.\d+)`).FindStringSubmatch(dockerfile)
	if image == nil {
		t.Fatal("the Dockerfile no longer builds on a pinned golang image")
	}
	toolchain := regexp.MustCompile(`(?m)^toolchain go(\d+\.\d+\.\d+)`).FindStringSubmatch(read("go.mod"))
	if toolchain == nil {
		t.Fatal("go.mod no longer names a toolchain, so the image has nothing to agree with")
	}
	if image[1] != toolchain[1] {
		t.Errorf("the image builds on Go %s and go.mod names %s: everything is tested on one and "+
			"the binary that ships is built on the other", image[1], toolchain[1])
	}

	node := regexp.MustCompile(`FROM node:(\d+\.\d+\.\d+)`).FindStringSubmatch(dockerfile)
	if node == nil {
		t.Fatal("the Dockerfile no longer builds the console on a pinned node image")
	}
	for _, workflow := range []string{"ci.yaml", "release.yaml"} {
		path := filepath.Join(".github", "workflows", workflow)
		for _, match := range regexp.MustCompile(`node-version:\s*(\d+\.\d+\.\d+)`).
			FindAllStringSubmatch(read(path), -1) {
			if match[1] != node[1] {
				t.Errorf("%s builds the console on Node %s and the image uses %s",
					workflow, match[1], node[1])
			}
		}
	}
}
