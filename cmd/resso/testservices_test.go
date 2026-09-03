package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
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
	command := exec.Command("bash", script)
	command.Env = append(os.Environ(),
		"PATH="+stubDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"RESSO_TEST_CERT_DIR="+filepath.Join(t.TempDir(), "certs"),
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
