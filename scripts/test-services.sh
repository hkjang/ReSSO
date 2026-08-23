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

postgres_container="resso-test-pg"
directory_container="resso-test-ldap"
tls_container="resso-test-ldaps"
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

log() { echo "$*" >&2; }

start_postgres() {
  if ! docker inspect "$postgres_container" >/dev/null 2>&1; then
    log "starting PostgreSQL on ${postgres_port}"
    docker run -d --name "$postgres_container" -p "127.0.0.1:${postgres_port}:5432" \
      -e POSTGRES_USER=resso -e POSTGRES_PASSWORD=resso -e POSTGRES_DB=resso \
      postgres:17-alpine >/dev/null
  fi
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

seed_directory() {
  local container="$1"
  docker exec -i "$container" ldapadd -x -H ldap://localhost \
    -D "cn=admin,dc=example,dc=test" -w adminpassword >/dev/null 2>&1 <<'LDIF' || log "ldapadd reported an error in $container"
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
  # grep -c exits non-zero when it counts nothing, which under set -e ends the
  # script before it can say what went wrong. The count is taken without
  # letting that decide the exit status.
  local seeded
  seeded="$(docker exec "$container" ldapsearch -x -H ldap://localhost \
    -b "ou=people,dc=example,dc=test" -D "cn=admin,dc=example,dc=test" -w adminpassword \
    "(objectClass=inetOrgPerson)" uid 2>/dev/null | grep -c '^uid:' || true)"
  test "${seeded:-0}" -eq 2 || { log "seeded ${seeded:-0} accounts in $container, expected 2"; exit 1; }
}

# Group membership only reaches an entry's memberOf through this overlay, and
# the role mapping tests read it there.
add_memberof_overlay() {
  local container="$1" database
  database="$(docker exec "$container" ldapsearch -Y EXTERNAL -H ldapi:/// -b cn=config \
    "(olcSuffix=dc=example,dc=test)" dn 2>/dev/null | awk '/^dn: / && !seen {print substr($0,5); seen=1}')"
  test -n "$database" || { log "the directory database was not found"; exit 1; }
  docker exec -i "$container" ldapadd -Y EXTERNAL -H ldapi:/// >/dev/null 2>&1 <<OVERLAY || true
dn: olcOverlay=memberof,$database
objectClass: olcOverlayConfig
objectClass: olcMemberOf
olcOverlay: memberof
olcMemberOfRefint: TRUE
OVERLAY
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
  docker inspect "$directory_container" >/dev/null 2>&1 && return
  log "starting the directory on ${directory_port}"
  docker run -d --name "$directory_container" -p "127.0.0.1:${directory_port}:389" \
    -e LDAP_ORGANISATION="ReSSO Test" -e LDAP_DOMAIN="example.test" \
    -e LDAP_ADMIN_PASSWORD="adminpassword" osixia/openldap:1.5.0 >/dev/null
  wait_for_directory "$directory_container"
  add_memberof_overlay "$directory_container"
  # Adding an overlay makes the server reload, so it has to be waited for again
  # before anything is written. Locally an already-warm container hid this; a
  # fresh one in CI did not.
  wait_for_directory "$directory_container"
  seed_directory "$directory_container"
}

make_certificates() {
  test -f "$certs/ca.crt" && return
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
  docker inspect "$tls_container" >/dev/null 2>&1 && return
  make_certificates
  log "starting the TLS directory on ${tls_port}"
  docker run -d --name "$tls_container" -p "127.0.0.1:${tls_port}:636" \
    -e LDAP_ORGANISATION="ReSSO Test" -e LDAP_DOMAIN="example.test" \
    -e LDAP_ADMIN_PASSWORD="adminpassword" -e LDAP_TLS_VERIFY_CLIENT="never" \
    -v "$certs:/container/service/slapd/assets/certs" osixia/openldap:1.5.0 >/dev/null
  wait_for_directory "$tls_container"
  seed_directory "$tls_container"
  # The TLS listener answers some time after plain LDAP does, and how long
  # varies with the machine — thirty seconds was enough here and not always
  # enough on a loaded runner, which made the check itself the flaky part.
  # Waiting longer costs nothing except when something is genuinely wrong.
  for _ in $(seq 1 120); do
    openssl s_client -connect "127.0.0.1:${tls_port}" -CAfile "$certs/ca.crt" </dev/null 2>&1 \
      | grep -q "Verify return code: 0" && return
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

cat <<ENV
export RESSO_TEST_POSTGRES_DSN="postgres://resso:resso@127.0.0.1:${postgres_port}/resso?sslmode=disable"
export RESSO_TEST_LDAP_URL="ldap://127.0.0.1:${directory_port}"
export RESSO_TEST_LDAPS_URL="ldaps://localhost:${tls_port}"
export RESSO_TEST_LDAP_CA="${certs}/ca.crt"
ENV
