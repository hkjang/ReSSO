package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// scripts/test-services.sh prints the environment the integration tests are
// run with, so what it prints is the only thing standing between a contributor
// and sixty tests that fail on an address. The two checks below cover the ways
// that address can be wrong while every readiness check in the script passes,
// because none of them ever goes through the published port: they all reach
// their service with `docker exec`, from inside the container.
//
// A stub docker stands in for the real one. It reports containers that already
// exist — the state the script is wrong about — and real listeners give the
// ports it names something behind them.

// stubDocker writes a docker that answers the three subcommands the script
// asks of an already-running container, mapping each to the given host port.
func stubDocker(t *testing.T, ports map[string]int) string {
	t.Helper()
	dir := t.TempDir()
	var mappings strings.Builder
	for container, port := range ports {
		fmt.Fprintf(&mappings, "      %s) echo \"127.0.0.1:%d\" ;;\n", container, port)
	}
	stub := `#!/usr/bin/env bash
case "$1" in
  inspect)
    # ` + "`docker inspect -f '{{.State.Status}}'`" + ` asks whether it is running;
    # a bare inspect asks only whether it is there.
    if [ "$2" = "-f" ]; then echo running; fi
    exit 0 ;;
  port)
    case "$2" in
` + mappings.String() + `    esac
    exit 0 ;;
  exec) exit 0 ;;
esac
exit 0
`
	path := filepath.Join(dir, "docker")
	if err := os.WriteFile(path, []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

// listenOn opens a real listener on a free port and reports it. The port is
// released only when the test ends, so the script finds something there.
func listenOn(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener.Addr().(*net.TCPAddr).Port
}

func runTestServices(t *testing.T, stubDir string) (string, string, error) {
	t.Helper()
	script := filepath.Join("..", "..", "scripts", "test-services.sh")
	if _, err := os.Stat(script); err != nil {
		t.Fatal(err)
	}
	// These port tests need a readable CA file to reach the port checks.
	// Actual certificate verification is covered by the real LDAPS tests.
	certs := t.TempDir()
	if err := os.WriteFile(filepath.Join(certs, "ca.crt"), []byte("port test CA placeholder\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("bash", script)
	command.Env = append(os.Environ(),
		"PATH="+stubDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"RESSO_TEST_CERT_DIR="+certs,
	)
	var out, errOut strings.Builder
	command.Stdout = &out
	command.Stderr = &errOut
	err := command.Run()
	return out.String(), errOut.String(), err
}

// A container only has the port it was published on when it was created. The
// defaults in the script are a request that applies to a container this run
// makes, and every path in it reuses one that is already there — so the
// environment described the request while the tests connected to the
// container. The DSN said 55439, the container had been started on 55450, and
// nothing between the two ever noticed.
func TestTheEnvironmentNamesThePortTheContainerIsActuallyOn(t *testing.T) {
	postgres, directory, tls := listenOn(t), listenOn(t), listenOn(t)
	stub := stubDocker(t, map[string]int{
		"resso-test-pg":    postgres,
		"resso-test-ldap":  directory,
		"resso-test-ldaps": tls,
	})

	out, errOut, err := runTestServices(t, stub)
	if err != nil {
		t.Fatalf("the script failed: %v\n%s%s", err, out, errOut)
	}
	for _, want := range []string{
		fmt.Sprintf("127.0.0.1:%d/resso", postgres),
		fmt.Sprintf("ldap://127.0.0.1:%d", directory),
		fmt.Sprintf("ldaps://localhost:%d", tls),
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the environment does not name %s, so the tests are pointed somewhere "+
				"the containers are not:\n%s", want, out)
		}
	}
	for _, requested := range []string{"55439", "13890", "13636"} {
		if strings.Contains(out, requested) {
			t.Errorf("the environment still names the requested port %s rather than the "+
				"container's own:\n%s", requested, out)
		}
	}
}

// Nothing in the script had ever tried the address it prints, so a port that
// led nowhere was reported as a working environment and first met by the
// tests, each blaming an address the script had handed them.
func TestAPortThatLeadsNowhereIsNotPrintedAsAnEnvironment(t *testing.T) {
	directory, tls := listenOn(t), listenOn(t)
	// Taken and given back, so the number is a plausible port with nothing
	// behind it — which is exactly what a stale container's mapping is.
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	postgres := dead.Addr().(*net.TCPAddr).Port
	if err := dead.Close(); err != nil {
		t.Fatal(err)
	}

	stub := stubDocker(t, map[string]int{
		"resso-test-pg":    postgres,
		"resso-test-ldap":  directory,
		"resso-test-ldaps": tls,
	})
	out, errOut, err := runTestServices(t, stub)
	if err == nil {
		t.Fatalf("the script reported a working environment for a port nothing listens on:\n%s", out)
	}
	if strings.Contains(out, "RESSO_TEST_POSTGRES_DSN") {
		t.Errorf("the script printed a DSN it could not reach:\n%s", out)
	}
	if !strings.Contains(errOut, fmt.Sprint(postgres)) {
		t.Errorf("the script did not say which port it could not reach:\n%s", errOut)
	}
}

// The four places that show how to start the services, and the shape each
// shows it in. A reader copies whichever one they land on, so every one of
// them has to behave the same way when preparation fails.
var preparationExampleFiles = []string{
	"README.md",
	filepath.Join("docs", "user-federation.md"),
	filepath.Join("scripts", "test-services.sh"),
	"Makefile",
}

// preparationInvocation finds the command substitution rather than the plain
// `--stop` mentions, which are a different instruction.
var preparationInvocation = "(scripts/test-services.sh)"

// trailingComment is stripped so the marker appended below is a command and
// not part of a comment the example ends with.
var trailingComment = regexp.MustCompile(`\s+#.*$`)

// preparationExample lifts the shown command out of one file. The shapes are
// a fenced block in the two documents, a header comment in the script, and an
// echoed message in the Makefile, so the line is unwrapped per file type and
// then the lines the shell would join to it - which in every shape here is a
// run of lines ending in `&&` - are taken with it.
func preparationExample(t *testing.T, root, name string) string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(root, name))
	if err != nil {
		t.Fatal(err)
	}
	unwrap := func(line string) string {
		s := strings.TrimSpace(line)
		switch {
		case strings.HasSuffix(name, "Makefile"):
			// A recipe line echoing the command: `$$` is one dollar to the
			// shell and `\"` is one quote.
			s = strings.TrimSpace(strings.TrimSuffix(s, `; \`))
			s = strings.TrimPrefix(s, `echo "`)
			s = strings.TrimSuffix(strings.TrimSpace(s), `"`)
			s = strings.ReplaceAll(s, `\$$`, `$`)
			s = strings.ReplaceAll(s, `\"`, `"`)
			s = strings.ReplaceAll(s, `$$`, `$`)
		case strings.HasSuffix(name, ".sh"):
			s = strings.TrimPrefix(s, "#")
		}
		return strings.TrimSpace(s)
	}
	lines := strings.Split(string(content), "\n")
	for i, line := range lines {
		if !strings.Contains(line, preparationInvocation) {
			continue
		}
		snippet := []string{unwrap(line)}
		for strings.HasSuffix(snippet[len(snippet)-1], "&&") && i+len(snippet) < len(lines) {
			snippet = append(snippet, unwrap(lines[i+len(snippet)]))
		}
		joined := strings.Join(snippet, "\n")
		return trailingComment.ReplaceAllString(joined, "")
	}
	t.Fatalf("%s no longer shows how to start the services, so nothing here checks it", name)
	return ""
}

// stubPreparation writes a stand-in for the preparation script, and stubs for
// the commands the examples go on to run so that a working preparation does
// not start the real suite from inside this test.
func stubPreparation(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{"make", "go", "npm"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/usr/bin/env bash\nexit 0\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	script := filepath.Join(dir, "test-services.sh")
	if err := os.WriteFile(script, []byte("#!/usr/bin/env bash\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	return script
}

// runPreparationExample runs one shown example with the given preparation
// standing in for the real script, and reports whether what the example goes
// on to do was reached.
func runPreparationExample(t *testing.T, example, script string) (reached bool, status error) {
	t.Helper()
	dir := filepath.Dir(script)
	marker := filepath.Join(t.TempDir(), "followup")
	// Joined onto the end of the example's own chain rather than put on a line
	// of its own, which would run whatever the example did.
	body := strings.ReplaceAll(example, "scripts/test-services.sh", script) +
		" && printf reached > " + marker + "\n"
	path := filepath.Join(t.TempDir(), "example.sh")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("bash", path)
	command.Env = append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	err := command.Run()
	if _, statErr := os.Stat(marker); statErr == nil {
		return true, err
	}
	return false, err
}

// One script starts the services the integration tests need, and four places
// tell a reader how to run it. Two of them showed
//
//	eval "$(scripts/test-services.sh)"
//
// which hides the one failure that must not be hidden: preparation that exits
// nonzero prints no environment, `eval ""` succeeds, and the reader goes on to
// run sixty tests against services that are not there - green locally, failed
// by CI, which is the whole thing the script exists to prevent. c1b71bb fixed
// the directory guide; the README was already right; the script's own header
// and the summary `make test` prints when it finds tests that did not run were
// still showing the form that swallows it - the Makefile one reached by a
// reader who has just been told something went wrong.
//
// Each example is run twice, so neither a form that swallows the failure nor
// one that simply never gets anywhere can pass.
func TestEveryShownPreparationStopsWhenPreparationFails(t *testing.T) {
	root := filepath.Join("..", "..")
	for _, name := range preparationExampleFiles {
		t.Run(name, func(t *testing.T) {
			example := preparationExample(t, root, name)
			if !strings.Contains(example, preparationInvocation) {
				t.Fatalf("the example lifted out of %s does not run the script:\n%s", name, example)
			}

			failing := stubPreparation(t, "echo 'preparation failed' >&2\nexit 1\n")
			reached, status := runPreparationExample(t, example, failing)
			if reached {
				t.Errorf("%s goes on past a preparation that exited 1, so a reader following it "+
					"runs the tests without the services:\n%s", name, example)
			}
			if status == nil {
				t.Errorf("%s reports success for a preparation that exited 1:\n%s", name, example)
			}

			working := stubPreparation(t, "echo \"export RESSO_TEST_PREPARED=yes\"\n")
			reached, status = runPreparationExample(t, example, working)
			if !reached {
				t.Errorf("%s does not get past a preparation that worked, so it cannot be the "+
					"instruction it is given as:\n%s", name, example)
			}
			if status != nil {
				t.Errorf("%s fails even when preparation worked: %v\n%s", name, status, example)
			}
		})
	}
}
