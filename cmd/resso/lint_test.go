package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// `make lint` is the command the README gives as the way to check Go work
// before pushing, and both tools it runs reach the code by running `go` as a
// subprocess. go.mod names a toolchain, and the ordinary way to have that
// toolchain is `go install golang.org/dl/go1.26.9@latest`, which puts a program
// of that name in GOBIN. A Go that has to switch toolchains prefers a goX.Y.Z
// program it finds on PATH over the copy in the module cache, and the installed
// one is a downloader stub that refuses unless the SDK was also unpacked under
// $HOME/sdk. So a target that puts GOBIN on the PATH its tools inherit answers
// every `go` call they make with
//
//	go1.26.9: not downloaded. Run 'go1.26.9 download' to install to $HOME/sdk/go1.26.9
//
// and lint dies in context loading, naming no rule, on a tree that is clean.
// Where the target looks the tools up and what PATH it hands them are two
// separate questions, and it must not answer the second one with the first.
//
// CI never meets this: it installs the tools and invokes them itself rather
// than through `make`, and its Go is the one go.mod asks for, so nothing is
// switched to. Only the local gate is affected - the gate whose failure told
// nobody anything.

// lintTools are the two Go tools `make lint` runs. The frontend linter is left
// out: it does not run `go`.
var lintTools = []string{"golangci-lint", "govulncheck"}

var toolchainDirective = regexp.MustCompile(`(?m)^toolchain\s+(go\S+)\s*$`)

// moduleToolchain reports the toolchain go.mod asks for, which is the name the
// shadowing program would have.
func moduleToolchain(t *testing.T, root string) string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	match := toolchainDirective.FindSubmatch(content)
	if match == nil {
		t.Skip("go.mod names no toolchain, so there is nothing to switch to and this cannot happen")
	}
	return string(match[1])
}

func writeStub(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("#!/usr/bin/env bash\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
}

// fakeGOPATH builds the GOPATH of someone who installed the lint tools and the
// toolchain program the ordinary way, and returns it along with the directory
// the stubs report into. Each tool stub records the PATH it was handed and then
// makes the `go` call golangci-lint's own error message shows it making.
func fakeGOPATH(t *testing.T, toolchain string) (gopath, reports string) {
	t.Helper()
	gopath, reports = t.TempDir(), t.TempDir()
	bin := filepath.Join(gopath, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	// What golang.org/dl's program does when its SDK was never unpacked.
	writeStub(t, filepath.Join(bin, toolchain),
		"echo \""+toolchain+": not downloaded. Run '"+toolchain+" download' to install\" >&2\nexit 1\n")
	for _, tool := range lintTools {
		report := filepath.Join(reports, tool)
		writeStub(t, filepath.Join(bin, tool),
			"printf '%s' \"$PATH\" > "+report+".path\n"+
				"go env -json GOMOD > "+report+".go 2>&1 || exit 7\n")
	}
	return gopath, reports
}

// shellGo reports the `go` a shell in this repository would find, which is not
// the one running this test: `go test` has already switched to the toolchain
// go.mod asks for and put that toolchain's bin first on PATH. Only a `go` that
// still has to switch looks for the toolchain program on PATH at all, so using
// the switched one would leave the stub unconsulted and the check toothless.
func shellGo(t *testing.T, goEnv func(string) string) string {
	t.Helper()
	switched := filepath.Join(goEnv("GOROOT"), "bin")
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if dir == "" || dir == switched {
			continue
		}
		candidate := filepath.Join(dir, "go")
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() && info.Mode().Perm()&0o111 != 0 {
			return candidate
		}
	}
	// Nothing but the switched toolchain is reachable, so no switch happens and
	// only the PATH the tools are handed can be checked.
	found, err := exec.LookPath("go")
	if err != nil {
		t.Skipf("no go on PATH: %v", err)
	}
	return found
}

// lintEnvironment is what both `make` and the lines it renders run under: the
// tools and the toolchain program reachable only through GOPATH, and the real
// caches, so a toolchain switch resolves the way it would on a machine that has
// already built this module.
func lintEnvironment(t *testing.T, gopath string) []string {
	t.Helper()
	read := func(name string) string {
		out, err := exec.Command("go", "env", name).Output()
		if err != nil {
			t.Fatalf("go env %s: %v", name, err)
		}
		return strings.TrimSpace(string(out))
	}
	separator := string(os.PathListSeparator)
	return []string{
		"PATH=" + filepath.Dir(shellGo(t, read)) + separator + "/usr/bin" + separator + "/bin",
		"HOME=" + os.Getenv("HOME"),
		"GOPATH=" + gopath,
		"GOMODCACHE=" + read("GOMODCACHE"),
		"GOCACHE=" + read("GOCACHE"),
	}
}

// renderedLintCommands asks make itself for the lines the lint recipe would
// run, so the expansion under test is make's and not this test's. The two tool
// invocations are the only lines carrying the package list; the rest of the
// recipe is the installed check and the frontend linter.
func renderedLintCommands(t *testing.T, root string, env []string) map[string]string {
	t.Helper()
	command := exec.Command("make", "-n", "lint")
	command.Dir = root
	command.Env = env
	out, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("make -n lint failed: %v\n%s", err, out)
	}
	rendered := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, "./cmd/...") {
			continue
		}
		for _, tool := range lintTools {
			if !strings.Contains(line, tool) {
				continue
			}
			if existing, ok := rendered[tool]; ok {
				t.Fatalf("the lint recipe runs %s on more than one line, so this test is reading "+
					"the wrong one:\n%s\n%s", tool, existing, line)
			}
			rendered[tool] = strings.TrimSpace(line)
		}
	}
	for _, tool := range lintTools {
		if rendered[tool] == "" {
			t.Fatalf("the lint recipe no longer runs %s over the package list, so nothing here "+
				"checks how it is run:\n%s", tool, out)
		}
	}
	return rendered
}

func TestLintDoesNotHandItsToolsTheToolchainProgramOnPath(t *testing.T) {
	root := filepath.Join("..", "..")
	toolchain := moduleToolchain(t, root)
	gopath, reports := fakeGOPATH(t, toolchain)
	env := lintEnvironment(t, gopath)
	rendered := renderedLintCommands(t, root, env)

	for _, tool := range lintTools {
		t.Run(tool, func(t *testing.T) {
			line := rendered[tool]
			// The Makefile's own shell, so quoting and pipefail behave as they do
			// in the real recipe.
			command := exec.Command("bash", "-o", "pipefail", "-c", line)
			command.Dir = root
			command.Env = env
			out, runErr := command.CombinedOutput()

			report := filepath.Join(reports, tool)
			handedPath, pathErr := os.ReadFile(report + ".path")
			if pathErr != nil {
				t.Fatalf("the rendered line never reached %s, so this proves nothing about it: %v\n  %s\n%s",
					tool, pathErr, line, out)
			}
			if runErr != nil {
				goOut, _ := os.ReadFile(report + ".go")
				t.Errorf("`make lint` leaves %s unable to run `go` when GOBIN holds %s: %v\n  %s\n%s%s",
					tool, toolchain, runErr, line, out, goOut)
			}
			for _, dir := range filepath.SplitList(string(handedPath)) {
				if dir != filepath.Join(gopath, "bin") {
					continue
				}
				t.Errorf("`make lint` hands %s a PATH with GOBIN (%s) on it, where %s sits and "+
					"shadows the module cache copy for every `go` the tool runs:\n  %s",
					tool, dir, toolchain, line)
			}
		})
	}
}
