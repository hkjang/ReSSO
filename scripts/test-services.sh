#!/usr/bin/env bash
# Starts the services the integration tests need, and prints the environment
# that points at them.
#
# Sixty tests skip without these, and a skipped test still lets `go test`
# report ok — so a contributor can see green locally and be failed by CI. One
# script rather than instructions in three places keeps what runs here and what
# runs in CI the same thing.
#
#   eval "$(scripts/test-services.sh)"    # start and export
#   scripts/test-services.sh --stop       # remove the containers
set -euo pipefail

# Defined before the --stop branch below, which reaches for it. A function is
# only there once its definition has run, and that one used to sit further
# down: the one path that reports a certificate directory it could not remove
# answered "log: command not found" instead of saying so.
log() { echo "$*" >&2; }

postgres_container="resso-test-pg"
directory_container="resso-test-ldap"
tls_container="resso-test-ldaps"
# These are what a container created by this run is published on. They are
# requests, not facts — a container left over from an earlier run keeps the
# port it was started with, and every path below reuses such a container
# without looking. So the environment printed at the end described the request
# while the tests connected to what was actually there: the DSN said 55439, the
# container had been started on 55450, and all sixty integration tests failed
# with "connection refused" naming a port nothing had ever listened on. Each
# variable is replaced with the container's real mapping before it is printed.
postgres_port="${RESSO_TEST_POSTGRES_PORT:-55439}"
directory_port="${RESSO_TEST_LDAP_PORT:-13890}"
tls_port="${RESSO_TEST_LDAPS_PORT:-13636}"
certs="${RESSO_TEST_CERT_DIR:-${TMPDIR:-/tmp}/resso-test-certs}"

if [ "${1:-}" = "--stop" ]; then
  docker rm -f "$postgres_container" "$directory_container" "$tls_container" >/dev/null 2>&1 || true
  # The directory chowns its certificate directory to root, so removing it
  # needs the same privileges rather than the caller's.
  # The directory takes ownership of this directory, so it has to be removed
  # with the same privileges — and the directory itself, not just its contents,
  # or the next run cannot write a new certificate into it.
  if [ -d "$certs" ]; then
    docker run --rm -v "$(dirname "$certs"):/parent" alpine:3 \
      rm -rf "/parent/$(basename "$certs")" || \
      log "could not remove $certs; a later run will need it gone"
  fi
  echo "removed the test services" >&2
  exit 0
fi

# ensure_running starts a container that is there but stopped, and says why
# when it will not start.
#
# `docker run -d` on a port another process already holds still creates the
# container and then fails to start it, leaving it behind in Created. Every
# path below treats an existing container as one it can reuse, so the next run
# skipped creation and met whatever the reuse path happened to fail on — for
# PostgreSQL an authentication error, which names neither the port that was
# taken nor the container that never started.
ensure_running() {
  local container="$1" state failure
  state="$(docker inspect -f '{{.State.Status}}' "$container" 2>/dev/null || true)"
  test "${state:-missing}" = running && return
  log "$container is ${state:-missing} rather than running; starting it"
  if ! failure="$(docker start "$container" 2>&1)"; then
    log "$container would not start: $failure"
    log "remove it and run again: scripts/test-services.sh --stop"
    exit 1
  fi
}

# published_port reports the host port a container is actually reachable on,
# having first made sure it is running. See the note on the port variables
# above for why the request is not enough.
published_port() {
  local container="$1" port="$2" mapping
  ensure_running "$container"
  # Captured and then trimmed rather than piped into `head -1`: under
  # `set -o pipefail` the consumer leaving first reports the producer's status,
  # a trap this script has already been caught by twice further down.
  mapping="$(docker port "$container" "$port" 2>/dev/null || true)"
  mapping="${mapping%%$'\n'*}"
  case "$mapping" in
    *:*) echo "${mapping##*:}" ;;
    *)
      log "$container publishes no host port for ${port}, so nothing can reach it"
      log "remove it and run again: scripts/test-services.sh --stop"
      exit 1
      ;;
  esac
}

start_postgres() {
  if ! docker inspect "$postgres_container" >/dev/null 2>&1; then
    log "starting PostgreSQL on ${postgres_port}"
    docker run -d --name "$postgres_container" -p "127.0.0.1:${postgres_port}:5432" \
      -e POSTGRES_USER=resso -e POSTGRES_PASSWORD=resso -e POSTGRES_DB=resso \
      postgres:17-alpine >/dev/null
  fi
  postgres_port="$(published_port "$postgres_container" 5432)"
  # The trigram indexes are only built when pg_trgm is present, and the test
  # that covers that path skips without it — quietly, which is the failure this
  # script exists to prevent. So this waits for the extension to actually be
  # there rather than asking once: pg_isready answers during initialisation,
  # while the server is still being restarted underneath it. It runs whether or
  # not the container was started here, because a container left over from an
  # earlier run has no reason to already have it.
  for _ in $(seq 1 60); do
    if docker exec "$postgres_container" psql -U resso -d resso \
         -c 'CREATE EXTENSION IF NOT EXISTS pg_trgm' >/dev/null 2>&1; then
      return
    fi
    sleep 1
  done
  log "PostgreSQL never accepted CREATE EXTENSION pg_trgm"; exit 1
}

# seed_directory writes the fixture accounts, retrying until they are there.
#
# Waiting for the directory to answer is not the same as it staying up. Adding
# the overlay makes the server reload, and a readiness probe that runs before
# the reload has begun passes against the process that is about to go away — so
# the write lands in the gap and fails. CI hit exactly that: "ldapadd reported
# an error", then "seeded 0 accounts, expected 2", on a commit that changed no
# Go code. Retrying the write is what actually closes that window, because it
# does not depend on guessing when the restart starts.
#
# -c keeps going past an entry that is already there, so a retry after a
# partial write finishes the rest instead of stopping on the first conflict.
# The count below decides the outcome either way.
seed_directory() {
  local container="$1"
  local attempt seeded
  # The condition is the accounts being there, not what ldapadd returned. On an
  # already-seeded directory every entry conflicts and ldapadd exits non-zero
  # with nothing wrong, so judging by exit code would retry fifteen times and
  # then complain about a directory that was correct all along.
  for attempt in $(seq 1 15); do
    seed_directory_once "$container" || true
    # grep -c exits non-zero when it counts nothing, which under set -e ends
    # the script before it can say what went wrong. The count is taken without
    # letting that decide the exit status.
    seeded="$(docker exec "$container" ldapsearch -x -H ldap://localhost \
      -b "ou=people,dc=example,dc=test" -D "cn=admin,dc=example,dc=test" -w adminpassword \
      "(objectClass=inetOrgPerson)" uid 2>/dev/null | grep -c '^uid:' || true)"
    test "${seeded:-0}" -eq 2 && return
    sleep 1
  done
  log "seeded ${seeded:-0} accounts in $container, expected 2"; exit 1
}

seed_directory_once() {
  local container="$1"
  docker exec -i "$container" ldapadd -c -x -H ldap://localhost \
    -D "cn=admin,dc=example,dc=test" -w adminpassword >/dev/null 2>&1 <<'LDIF'
dn: ou=people,dc=example,dc=test
objectClass: organizationalUnit
ou: people

dn: uid=alice,ou=people,dc=example,dc=test
objectClass: inetOrgPerson
uid: alice
cn: Alice Kim
sn: Kim
givenName: Alice
mail: alice@example.test
userPassword: alice-pass-1234

dn: uid=bob,ou=people,dc=example,dc=test
objectClass: inetOrgPerson
uid: bob
cn: Bob Lee
sn: Lee
givenName: Bob
mail: bob@example.test
userPassword: bob-pass-1234
LDIF
}

# Group membership only reaches an entry's memberOf through this overlay, and
# the role mapping tests read it there.
add_memberof_overlay() {
  local container="$1" database
  database="$(docker exec "$container" ldapsearch -Y EXTERNAL -H ldapi:/// -b cn=config \
    "(olcSuffix=dc=example,dc=test)" dn 2>/dev/null | awk '/^dn: / && !seen {print substr($0,5); seen=1}')"
  test -n "$database" || { log "the directory database was not found"; exit 1; }
  # Judged by the overlay being there, not by what ldapadd returned. Ignoring
  # the exit code let a failed add pass silently, and nothing downstream
  # notices: users still import, the directory still answers, and only the
  # group-to-role tests fail — with "membership of the mapped group did not
  # grant the role", which points at the mapping code rather than at a server
  # that never populates memberOf. CI failed that way twice.
  local attempt overlays
  for attempt in $(seq 1 15); do
    docker exec -i "$container" ldapadd -Y EXTERNAL -H ldapi:/// >/dev/null 2>&1 <<OVERLAY || true
dn: olcOverlay=memberof,$database
objectClass: olcOverlayConfig
objectClass: olcMemberOf
olcOverlay: memberof
olcMemberOfRefint: TRUE
OVERLAY
    # The report is captured and then searched. Piping into `grep -q` under
    # `set -o pipefail` reports the producer's status: grep stops reading at
    # the first match, ldapsearch takes SIGPIPE, and a successful search comes
    # back as 141. The same trap is noted further down for the TLS check.
    overlays="$(docker exec "$container" ldapsearch -Y EXTERNAL -H ldapi:/// -b cn=config \
      "(objectClass=olcMemberOf)" dn 2>/dev/null || true)"
    case "$overlays" in
      *"dn: olcOverlay="*) return ;;
    esac
    sleep 1
  done
  log "the memberof overlay never became active in $container"; exit 1
}

wait_for_directory() {
  local container="$1"
  for _ in $(seq 1 60); do
    docker exec "$container" ldapsearch -x -H ldap://localhost -b "dc=example,dc=test" \
      -D "cn=admin,dc=example,dc=test" -w adminpassword -s base >/dev/null 2>&1 && return
    sleep 1
  done
  log "the directory did not become ready"; exit 1
}

start_directory() {
  if docker inspect "$directory_container" >/dev/null 2>&1; then
    directory_port="$(published_port "$directory_container" 389)"
    return
  fi
  log "starting the directory on ${directory_port}"
  docker run -d --name "$directory_container" -p "127.0.0.1:${directory_port}:389" \
    -e LDAP_ORGANISATION="ReSSO Test" -e LDAP_DOMAIN="example.test" \
    -e LDAP_ADMIN_PASSWORD="adminpassword" osixia/openldap:1.5.0 >/dev/null
  directory_port="$(published_port "$directory_container" 389)"
  wait_for_directory "$directory_container"
  add_memberof_overlay "$directory_container"
  # Adding an overlay makes the server reload, so it has to be waited for again
  # before anything is written. Locally an already-warm container hid this; a
  # fresh one in CI did not.
  wait_for_directory "$directory_container"
  seed_directory "$directory_container"
}

make_certificates() {
  # Every file the directory needs has to be there, not just the first one
  # written. A run that stopped half way leaves the CA behind, and returning on
  # that alone left the server certificate missing while reporting success:
  # slapd then starts without one and the TLS readiness check blames the
  # container. Verified by deleting ldap.crt and running again — it stayed
  # deleted.
  if test -f "$certs/ca.crt" && test -f "$certs/ldap.crt" && test -f "$certs/ldap.key"; then
    return
  fi
  mkdir -p "$certs"
  openssl req -x509 -newkey rsa:2048 -sha256 -days 30 -nodes \
    -keyout "$certs/ca.key" -out "$certs/ca.crt" -subj "/CN=ReSSO Test CA" \
    -addext "basicConstraints=critical,CA:TRUE" 2>&1 | grep -vE '^[.+*]*$|self-signature ok|^-----' || true
  openssl req -newkey rsa:2048 -nodes -keyout "$certs/ldap.key" \
    -out "$certs/ldap.csr" -subj "/CN=localhost"
  printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' > "$certs/ext.cnf"
  openssl x509 -req -in "$certs/ldap.csr" -CA "$certs/ca.crt" -CAkey "$certs/ca.key" \
    -CAcreateserial -out "$certs/ldap.crt" -days 30 -sha256 -extfile "$certs/ext.cnf"
  chmod 644 "$certs"/*.crt "$certs"/*.key
}

start_tls_directory() {
  if docker inspect "$tls_container" >/dev/null 2>&1; then
    tls_port="$(published_port "$tls_container" 636)"
    return
  fi
  make_certificates
  log "starting the TLS directory on ${tls_port}"
  docker run -d --name "$tls_container" -p "127.0.0.1:${tls_port}:636" \
    -e LDAP_ORGANISATION="ReSSO Test" -e LDAP_DOMAIN="example.test" \
    -e LDAP_ADMIN_PASSWORD="adminpassword" -e LDAP_TLS_VERIFY_CLIENT="never" \
    -v "$certs:/container/service/slapd/assets/certs" osixia/openldap:1.5.0 >/dev/null
  tls_port="$(published_port "$tls_container" 636)"
  wait_for_directory "$tls_container"
  seed_directory "$tls_container"
  # The TLS listener answers some time after plain LDAP does, and how long
  # varies with the machine — thirty seconds was enough here and not always
  # enough on a loaded runner, which made the check itself the flaky part.
  # Waiting longer costs nothing except when something is genuinely wrong.
  #
  # Two things had to be right here, and each was hiding the other.
  #
  # The report is captured and then searched, rather than piped into `grep -q`.
  # Under `set -o pipefail` that pipeline reports the producer's status when the
  # consumer leaves first: grep -q exits on the matching line, openssl is still
  # writing the rest of its report, takes SIGPIPE, and the pipeline comes back
  # 141 — a successful match reported as a failure. Whether openssl has finished
  # writing by then depends on the machine, which is why this passed here and
  # failed on a loaded runner, with the diagnostic printed twenty milliseconds
  # after the give-up showing the certificate had been fine all along.
  #
  # And "Verify return code: 0" alone does not mean a certificate verified:
  # openssl prints it when there was no peer certificate to check, because
  # nothing failed. Docker publishes the port the moment the container starts,
  # so until slapd is listening the connection is accepted and closed, and that
  # empty exchange satisfies the string. The subject line only appears when a
  # certificate was actually presented, so both are required. The old check was
  # saved from this by the bug above — a false match returned 141 and the loop
  # kept waiting — and fixing only that one let the readiness check pass before
  # the directory was up.
  for _ in $(seq 1 120); do
    report="$(openssl s_client -connect "127.0.0.1:${tls_port}" -CAfile "$certs/ca.crt" </dev/null 2>&1 || true)"
    case "$report" in
      *"subject="*)
        case "$report" in
          *"Verify return code: 0"*) return ;;
        esac
        ;;
    esac
    sleep 1
  done
  log "the TLS directory never served a verifiable certificate"
  log "--- what it says about its own certificates ---"
  docker logs "$tls_container" 2>&1 | grep -iE 'tls|cert|error|fatal' | tail -20 >&2 || true
  log "--- what it is actually serving ---"
  openssl s_client -connect "127.0.0.1:${tls_port}" -CAfile "$certs/ca.crt" </dev/null 2>&1 \
    | grep -E 'subject=|issuer=|Verify return code|connect:' | head -5 >&2 || true
  log "--- what was mounted ---"
  ls -l "$certs" >&2 || true
  exit 1
}

start_postgres
start_directory
start_tls_directory

# Every readiness check above reaches its service through `docker exec`, from
# inside the container — which is not the path the environment below hands to
# the tests. So nothing had ever tried the published ports, and a port that
# went nowhere was first met by sixty integration tests failing at once, each
# blaming the address this script had just told them to use.
#
# Deliberately weak: docker publishes a port the moment the container starts,
# so an accepted connection does not mean the server behind it is ready. The
# loops above are what establish that. This only answers the question they
# cannot — whether the address being printed leads anywhere at all.
refuses_connection() {
  ! (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null
}

for service in "PostgreSQL:${postgres_port}" "the directory:${directory_port}" \
               "the TLS directory:${tls_port}"; do
  if refuses_connection "${service##*:}"; then
    log "${service%%:*} publishes ${service##*:} and nothing accepts a connection there"
    log "remove the containers and run again: scripts/test-services.sh --stop"
    exit 1
  fi
done

cat <<ENV
export RESSO_TEST_POSTGRES_DSN="postgres://resso:resso@127.0.0.1:${postgres_port}/resso?sslmode=disable"
export RESSO_TEST_LDAP_URL="ldap://127.0.0.1:${directory_port}"
export RESSO_TEST_LDAPS_URL="ldaps://localhost:${tls_port}"
export RESSO_TEST_LDAP_CA="${certs}/ca.crt"
ENV
