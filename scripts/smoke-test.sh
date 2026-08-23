#!/usr/bin/env sh
set -eu

base_url="${1:-http://127.0.0.1:8080}"
admin="${2:-admin}"
password="${3:-integration-password-123}"

for required in curl jq; do
  command -v "$required" >/dev/null 2>&1 || { echo "$required is required" >&2; exit 2; }
done

work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT INT TERM
cookie_jar="$work_dir/cookies"

meta="$(curl -fsS "$base_url/api/v1/meta")"
echo "$meta" | jq -e '.product == "ReSSO" and (.version | startswith("v"))' >/dev/null

login_payload="$(jq -nc --arg username "$admin" --arg password "$password" '{realm:"master",username:$username,password:$password,request:""}')"
login="$(curl -fsS -c "$cookie_jar" -H 'Content-Type: application/json' -d "$login_payload" "$base_url/api/v1/auth/login")"
csrf="$(echo "$login" | jq -er '.csrf_token')"

realms="$(curl -fsS -b "$cookie_jar" "$base_url/api/admin/v1/realms")"
realm_id="$(echo "$realms" | jq -er '.items[] | select(.name == "master") | .id')"

suffix="$(date +%s)-$$"
for empty_email_index in 1 2; do
  empty_email_user="empty-email-$empty_email_index-$suffix"
  curl -fsS -b "$cookie_jar" -H "X-CSRF-Token: $csrf" -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg username "$empty_email_user" '{username:$username,email:"",display_name:$username,password:"empty-email-password-123",enabled:true}')" \
    "$base_url/api/admin/v1/realms/$realm_id/users" | jq -e '.id != null' >/dev/null
done

client_identifier="smoke-$suffix"
client_payload="$(jq -nc --arg client "$client_identifier" '{client_id:$client,name:"Smoke test",type:"public",redirect_uris:["http://localhost:9999/callback"],post_logout_redirect_uris:["http://localhost:9999/logout"],web_origins:["http://localhost:9999"],grant_types:["authorization_code","refresh_token"],default_scopes:["openid","profile","email","roles"],require_pkce:true,backchannel_logout_uri:""}')"
curl -fsS -b "$cookie_jar" -H "X-CSRF-Token: $csrf" -H 'Content-Type: application/json' -d "$client_payload" "$base_url/api/admin/v1/realms/$realm_id/clients" | jq -e '.client.client_id != null' >/dev/null

curl -fsS -D "$work_dir/cors-headers" -o /dev/null -X OPTIONS \
  -H 'Origin: http://localhost:9999' \
  -H 'Access-Control-Request-Method: POST' \
  "$base_url/realms/master/protocol/openid-connect/token"
grep -Eiq '^access-control-allow-origin: http://localhost:9999' "$work_dir/cors-headers" || {
  echo "registered Web Origin did not receive CORS headers" >&2
  exit 1
}

verifier='dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
challenge='E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'
curl -fsS -b "$cookie_jar" -D "$work_dir/headers" -o /dev/null --get \
  --data-urlencode "client_id=$client_identifier" \
  --data-urlencode 'redirect_uri=http://localhost:9999/callback' \
  --data-urlencode 'response_type=code' \
  --data-urlencode 'scope=openid profile email' \
  --data-urlencode 'state=smoke-state' \
  --data-urlencode 'nonce=smoke-nonce' \
  --data-urlencode "code_challenge=$challenge" \
  --data-urlencode 'code_challenge_method=S256' \
  "$base_url/realms/master/protocol/openid-connect/auth"
location="$(sed -n 's/^location: //Ip' "$work_dir/headers" | tr -d '\r')"
code="$(echo "$location" | sed -n 's/.*[?&]code=\([^&]*\).*/\1/p')"
[ -n "$code" ] || { echo "authorization code was not returned" >&2; exit 1; }

wrong_status="$(curl -sS -o "$work_dir/wrong-pkce.json" -w '%{http_code}' -X POST \
  --data-urlencode 'grant_type=authorization_code' \
  --data-urlencode "client_id=$client_identifier" \
  --data-urlencode "code=$code" \
  --data-urlencode 'redirect_uri=http://localhost:9999/callback' \
  --data-urlencode 'code_verifier=wrong-verifier-that-is-long-enough-for-pkce-123456' \
  "$base_url/realms/master/protocol/openid-connect/token")"
[ "$wrong_status" = 400 ] || { echo "incorrect PKCE verifier was not rejected" >&2; exit 1; }

tokens="$(curl -fsS -X POST \
  --data-urlencode 'grant_type=authorization_code' \
  --data-urlencode "client_id=$client_identifier" \
  --data-urlencode "code=$code" \
  --data-urlencode 'redirect_uri=http://localhost:9999/callback' \
  --data-urlencode "code_verifier=$verifier" \
  "$base_url/realms/master/protocol/openid-connect/token")"
access_token="$(echo "$tokens" | jq -er '.access_token')"
refresh_token="$(echo "$tokens" | jq -er '.refresh_token')"
echo "$tokens" | jq -e '.token_type == "Bearer" and .id_token != null' >/dev/null

curl -fsS -H "Authorization: Bearer $access_token" "$base_url/realms/master/protocol/openid-connect/userinfo" | \
  jq -e '.preferred_username != null and (has("email") | not) and (has("email_verified") | not) and .realm_access == null' >/dev/null
refreshed="$(curl -fsS -X POST --data-urlencode 'grant_type=refresh_token' --data-urlencode "client_id=$client_identifier" --data-urlencode "refresh_token=$refresh_token" "$base_url/realms/master/protocol/openid-connect/token")"
rotated_refresh="$(echo "$refreshed" | jq -er '.refresh_token')"
echo "$refreshed" | jq -e '.access_token != null' >/dev/null
# Presenting the same token again immediately is a retry, not theft: parallel
# tabs and network retries do this routinely, so it must yield a fresh token
# instead of logging the user out of every client. Reuse outside the grace
# window still revokes the family; that path is covered by the Go integration
# test, which can age the recorded rotation without waiting.
grace="$(curl -fsS -X POST --data-urlencode 'grant_type=refresh_token' --data-urlencode "client_id=$client_identifier" --data-urlencode "refresh_token=$refresh_token" "$base_url/realms/master/protocol/openid-connect/token")"
grace_refresh="$(echo "$grace" | jq -er '.refresh_token')"
[ "$grace_refresh" != "$rotated_refresh" ] || { echo "grace rotation returned the same refresh token" >&2; exit 1; }
echo "$grace" | jq -e '.access_token != null' >/dev/null

# Revoking any member of the family must invalidate every sibling.
curl -fsS -o /dev/null -X POST --data-urlencode "client_id=$client_identifier" --data-urlencode "token=$grace_refresh" "$base_url/realms/master/protocol/openid-connect/revoke"
for revoked_token in "$rotated_refresh" "$grace_refresh"; do
  family_status="$(curl -sS -o "$work_dir/family.json" -w '%{http_code}' -X POST --data-urlencode 'grant_type=refresh_token' --data-urlencode "client_id=$client_identifier" --data-urlencode "refresh_token=$revoked_token" "$base_url/realms/master/protocol/openid-connect/token")"
  [ "$family_status" = 400 ] || { echo "refresh token family was not revoked" >&2; exit 1; }
done

# The ID token must bind to its access token so strict relying parties accept it.
echo "$tokens" | jq -er '.id_token' | cut -d. -f2 | tr '_-' '/+' | \
  awk '{ while (length($0) % 4 != 0) $0 = $0 "="; print }' | base64 -d 2>/dev/null | \
  jq -e '.at_hash != null and .nonce != null' >/dev/null || { echo "id_token is missing at_hash" >&2; exit 1; }

role_name="smoke-role-$suffix"
role_response="$(curl -fsS -b "$cookie_jar" -H "X-CSRF-Token: $csrf" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg name "$role_name" '{name:$name,description:"Smoke Realm Role"}')" \
  "$base_url/api/admin/v1/realms/$realm_id/roles")"
role_id="$(echo "$role_response" | jq -er '.id')"
client_uuid="$(curl -fsS -b "$cookie_jar" "$base_url/api/admin/v1/realms/$realm_id/clients" | jq -er --arg client "$client_identifier" '.items[] | select(.client_id == $client) | .id')"
client_role_response="$(curl -fsS -b "$cookie_jar" -H "X-CSRF-Token: $csrf" -H 'Content-Type: application/json' \
  -d '{"name":"operator","description":"Smoke Client Role"}' \
  "$base_url/api/admin/v1/realms/$realm_id/clients/$client_uuid/roles")"
client_role_id="$(echo "$client_role_response" | jq -er '.id')"
admin_id="$(curl -fsS -b "$cookie_jar" "$base_url/api/admin/v1/realms/$realm_id/users?q=$admin" | jq -er --arg admin "$admin" '.items[] | select(.username == $admin) | .id')"
current_mappings="$(curl -fsS -b "$cookie_jar" "$base_url/api/admin/v1/realms/$realm_id/users/$admin_id/role-mappings")"
mapping_payload="$(echo "$current_mappings" | jq -c --arg role "$role_id" --arg client_role "$client_role_id" \
  '{realm_role_ids:((.realm_role_ids + [$role]) | unique),client_role_ids:((.client_role_ids + [$client_role]) | unique)}')"
curl -fsS -b "$cookie_jar" -H "X-CSRF-Token: $csrf" -H 'Content-Type: application/json' -X PUT \
  -d "$mapping_payload" "$base_url/api/admin/v1/realms/$realm_id/users/$admin_id/role-mappings" | \
  jq -e --arg role "$role_id" --arg client_role "$client_role_id" '(.realm_role_ids | index($role)) != null and (.client_role_ids | index($client_role)) != null' >/dev/null

curl -fsS -b "$cookie_jar" -D "$work_dir/role-headers" -o /dev/null --get \
  --data-urlencode "client_id=$client_identifier" \
  --data-urlencode 'redirect_uri=http://localhost:9999/callback' \
  --data-urlencode 'response_type=code' \
  --data-urlencode 'scope=openid profile email roles' \
  --data-urlencode 'state=role-smoke-state' \
  --data-urlencode "code_challenge=$challenge" \
  --data-urlencode 'code_challenge_method=S256' \
  "$base_url/realms/master/protocol/openid-connect/auth"
role_location="$(sed -n 's/^location: //Ip' "$work_dir/role-headers" | tr -d '\r')"
role_code="$(echo "$role_location" | sed -n 's/.*[?&]code=\([^&]*\).*/\1/p')"
[ -n "$role_code" ] || { echo "role authorization code was not returned" >&2; exit 1; }
role_tokens="$(curl -fsS -X POST \
  --data-urlencode 'grant_type=authorization_code' \
  --data-urlencode "client_id=$client_identifier" \
  --data-urlencode "code=$role_code" \
  --data-urlencode 'redirect_uri=http://localhost:9999/callback' \
  --data-urlencode "code_verifier=$verifier" \
  "$base_url/realms/master/protocol/openid-connect/token")"
role_access_token="$(echo "$role_tokens" | jq -er '.access_token')"
curl -fsS -H "Authorization: Bearer $role_access_token" "$base_url/realms/master/protocol/openid-connect/userinfo" | \
  jq -e --arg realm_role "$role_name" --arg client "$client_identifier" \
  '(.realm_access.roles | index($realm_role)) != null and (.resource_access[$client].roles | index("operator")) != null' >/dev/null

secondary_name="smoke-secondary-$suffix"
secondary_realm="$(curl -fsS -b "$cookie_jar" -H "X-CSRF-Token: $csrf" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg name "$secondary_name" --arg issuer "https://sso.example.test/realms/$secondary_name" '{name:$name,display_name:"Smoke Secondary",issuer_url:$issuer}')" \
  "$base_url/api/admin/v1/realms")"
secondary_id="$(echo "$secondary_realm" | jq -er '.id')"
delegated_user="realm-admin-$suffix"
delegated_password='delegated-password-123'
delegated_response="$(curl -fsS -b "$cookie_jar" -H "X-CSRF-Token: $csrf" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg username "$delegated_user" --arg password "$delegated_password" '{username:$username,email:($username+"@example.test"),display_name:"Delegated Realm Admin",password:$password,enabled:true}')" \
  "$base_url/api/admin/v1/realms/$realm_id/users")"
delegated_id="$(echo "$delegated_response" | jq -er '.id')"
realm_admin_role_id="$(curl -fsS -b "$cookie_jar" "$base_url/api/admin/v1/realms/$realm_id/roles" | jq -er '.items[] | select(.name == "realm-admin") | .id')"
delegated_mappings="$(curl -fsS -b "$cookie_jar" "$base_url/api/admin/v1/realms/$realm_id/users/$delegated_id/role-mappings")"
delegated_mapping_payload="$(echo "$delegated_mappings" | jq -c --arg role "$realm_admin_role_id" '{realm_role_ids:((.realm_role_ids+[$role])|unique),client_role_ids:.client_role_ids}')"
curl -fsS -b "$cookie_jar" -H "X-CSRF-Token: $csrf" -H 'Content-Type: application/json' -X PUT \
  -d "$delegated_mapping_payload" "$base_url/api/admin/v1/realms/$realm_id/users/$delegated_id/role-mappings" >/dev/null
delegated_cookie_jar="$work_dir/delegated-cookies"
delegated_login_payload="$(jq -nc --arg username "$delegated_user" --arg password "$delegated_password" '{realm:"master",username:$username,password:$password,request:""}')"
delegated_login="$(curl -fsS -c "$delegated_cookie_jar" -H 'Content-Type: application/json' -d "$delegated_login_payload" "$base_url/api/v1/auth/login")"
delegated_csrf="$(echo "$delegated_login" | jq -er '.csrf_token')"
curl -fsS -b "$delegated_cookie_jar" "$base_url/api/admin/v1/realms" | jq -e '.items | length == 1 and .[0].name == "master"' >/dev/null
curl -fsS -b "$delegated_cookie_jar" "$base_url/api/admin/v1/realms/$realm_id/users?limit=1" | jq -e '.total > 0' >/dev/null
cross_realm_status="$(curl -sS -o "$work_dir/cross-realm.json" -w '%{http_code}' -b "$delegated_cookie_jar" "$base_url/api/admin/v1/realms/$secondary_id/clients")"
[ "$cross_realm_status" = 403 ] || { echo "Realm administrator crossed Realm boundary" >&2; exit 1; }
create_realm_status="$(curl -sS -o "$work_dir/create-realm.json" -w '%{http_code}' -b "$delegated_cookie_jar" -H "X-CSRF-Token: $delegated_csrf" -H 'Content-Type: application/json' -d '{"name":"forbidden","display_name":"Forbidden","issuer_url":"https://sso.example.test/realms/forbidden"}' "$base_url/api/admin/v1/realms")"
[ "$create_realm_status" = 403 ] || { echo "Realm administrator created a Realm" >&2; exit 1; }
logs_status="$(curl -sS -o "$work_dir/logs.json" -w '%{http_code}' -b "$delegated_cookie_jar" "$base_url/api/admin/v1/system-logs")"
[ "$logs_status" = 403 ] || { echo "Realm administrator accessed platform logs" >&2; exit 1; }
protected_admin_status="$(curl -sS -o "$work_dir/protected-admin.json" -w '%{http_code}' -b "$delegated_cookie_jar" \
  -H "X-CSRF-Token: $delegated_csrf" -H 'Content-Type: application/json' -X PUT \
  -d '{"new_password":"must-not-be-applied-123"}' "$base_url/api/admin/v1/realms/$realm_id/users/$admin_id/password")"
[ "$protected_admin_status" = 403 ] || { echo "Realm administrator changed a platform administrator" >&2; exit 1; }

api_key_payload='{"name":"Smoke MCP and REST","scopes":["mcp:read","api:read","admin:read"],"expires_days":1}'
api_key_response="$(curl -sS -b "$cookie_jar" -H "X-CSRF-Token: $csrf" -H 'Content-Type: application/json' -d "$api_key_payload" "$base_url/api/v1/me/api-keys")"
api_key="$(echo "$api_key_response" | jq -er '.secret')" || {
  echo "$api_key_response" | jq '{error,message,trace_id}' >&2
  exit 1
}
mcp_request='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"smoke","version":"1"}}}'
curl -fsS -H "Authorization: Bearer $api_key" -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' -d "$mcp_request" "$base_url/mcp" | jq -e '.result.serverInfo.name == "ReSSO"' >/dev/null
curl -fsS -H "Authorization: Bearer $api_key" "$base_url/api/v1/me" | jq -e --arg admin "$admin" '.user.username == $admin' >/dev/null
curl -fsS -H "Authorization: Bearer $api_key" "$base_url/api/admin/v1/realms" | jq -e '.items | length > 0' >/dev/null

# The MCP tools that read people and relying parties are gated on admin:read.
# Checking only the handshake left that boundary unverified end to end, which
# is where it last went wrong: any account may mint an mcp:read key.
mcp_call() {
  curl -fsS -H "Authorization: Bearer $1" -H 'Content-Type: application/json' \
    -H 'Accept: application/json, text/event-stream' -d "$2" "$base_url/mcp"
}
tools_list='{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
search_call='{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"resso_search_users","arguments":{"query":"ad"}}}'

mcp_call "$api_key" "$tools_list" \
  | jq -e '[.result.tools[].name] | index("resso_search_users") and index("resso_list_clients")' >/dev/null \
  || { echo "an admin:read key was not offered the directory tools" >&2; exit 1; }
mcp_call "$api_key" "$search_call" | jq -e '.result.isError == false and (.result.structuredContent | length > 0)' >/dev/null \
  || { echo "an admin:read key could not search users over MCP" >&2; exit 1; }

reader_key_payload='{"name":"Smoke MCP reader","scopes":["mcp:read"],"expires_days":1}'
reader_key="$(curl -fsS -b "$cookie_jar" -H "X-CSRF-Token: $csrf" -H 'Content-Type: application/json' \
  -d "$reader_key_payload" "$base_url/api/v1/me/api-keys" | jq -er '.secret')"
mcp_call "$reader_key" "$tools_list" \
  | jq -e '[.result.tools[].name] | (index("resso_search_users") | not) and (index("resso_list_clients") | not)' >/dev/null \
  || { echo "an mcp:read-only key was offered the directory tools" >&2; exit 1; }
mcp_call "$reader_key" "$search_call" | jq -e '.result.isError == true' >/dev/null \
  || { echo "an mcp:read-only key read the user directory" >&2; exit 1; }

# Everything below verifies behaviour that is only visible from outside: an
# account or a Realm being switched off has to stop what it is supposed to
# stop, in the built image, against a real database. The Go tests cover each
# of these, but the release runs this script and not those.
admin_json() {
  method="$1"
  path="$2"
  body="${3:-}"
  if [ -n "$body" ]; then
    curl -fsS -b "$cookie_jar" -H "X-CSRF-Token: $csrf" -H 'Content-Type: application/json' \
      -X "$method" -d "$body" "$base_url$path"
  else
    curl -fsS -b "$cookie_jar" -H "X-CSRF-Token: $csrf" -X "$method" "$base_url$path"
  fi
}
# Deliberately without -f: these expect a refusal, and the status is the point.
status_of() {
  curl -sS -o /dev/null -w '%{http_code}' "$@"
}

# Disabling an account is the emergency stop. It has to end the sessions that
# are open, and re-enabling the account must not hand them back — the session
# rows are revoked, not hidden, and that difference is invisible until somebody
# is let back in months later along with whoever else was signed in as them.
disabled_user="disabled-$suffix"
disabled_id="$(admin_json POST "/api/admin/v1/realms/$realm_id/users" \
  "$(jq -nc --arg username "$disabled_user" '{username:$username,email:"",display_name:$username,password:"smoke-disable-password-123",enabled:true}')" \
  | jq -er '.id')"
disabled_jar="$work_dir/disabled-cookies"
curl -fsS -c "$disabled_jar" -H 'Content-Type: application/json' \
  -d "$(jq -nc --arg username "$disabled_user" '{realm:"master",username:$username,password:"smoke-disable-password-123",request:""}')" \
  "$base_url/api/v1/auth/login" >/dev/null
[ "$(status_of -b "$disabled_jar" "$base_url/api/v1/me")" = "200" ] || {
  echo "a new account could not use the session it had just been given" >&2; exit 1; }

set_enabled() {
  admin_json PUT "/api/admin/v1/realms/$realm_id/users/$disabled_id" \
    "$(jq -nc --arg name "$disabled_user" --argjson enabled "$1" '{display_name:$name,email:"",enabled:$enabled}')" >/dev/null
}
set_enabled false
[ "$(status_of -b "$disabled_jar" "$base_url/api/v1/me")" = "401" ] || {
  echo "a disabled account kept its session" >&2; exit 1; }
set_enabled true
[ "$(status_of -b "$disabled_jar" "$base_url/api/v1/me")" = "401" ] || {
  echo "re-enabling an account brought its old session back" >&2; exit 1; }

# Suspending a Realm has to reach the endpoints that speak for tokens already
# issued, not only the ones that issue them. The token below is minted while
# the Realm is running and asked about after it stops.
tenant="tenant-$suffix"
tenant_id="$(admin_json POST /api/admin/v1/realms \
  "$(jq -nc --arg name "$tenant" --arg issuer "$base_url/realms/$tenant" '{name:$name,display_name:"Smoke tenant",issuer_url:$issuer}')" \
  | jq -er '.id')"
tenant_client="$(admin_json POST "/api/admin/v1/realms/$tenant_id/clients" \
  '{"client_id":"tenant-rs","name":"Tenant RS","type":"confidential","redirect_uris":["http://localhost:9999/callback"],"grant_types":["client_credentials"],"default_scopes":["openid"]}' \
  | jq -er '.client.id')"
tenant_secret="$(admin_json POST "/api/admin/v1/realms/$tenant_id/clients/$tenant_client/rotate-secret" \
  | jq -er '.client_secret')"
tenant_token="$(curl -fsS -d "grant_type=client_credentials&client_id=tenant-rs&client_secret=$tenant_secret&scope=openid" \
  "$base_url/realms/$tenant/protocol/openid-connect/token" | jq -er '.access_token')"
introspect_tenant() {
  curl -fsS -d "token=$tenant_token&client_id=tenant-rs&client_secret=$tenant_secret" \
    "$base_url/realms/$tenant/protocol/openid-connect/token/introspect"
}
introspect_tenant | jq -e '.active == true' >/dev/null || {
  echo "a token could not be introspected while its Realm was running" >&2; exit 1; }

tenant_policy() {
  admin_json GET "/api/admin/v1/realms/$tenant_id/" \
    | jq -c --argjson enabled "$1" '{display_name,issuer_url,enabled:$enabled,approval_enabled,
        access_token_ttl_seconds,refresh_token_ttl_seconds,session_ttl_seconds,idle_timeout_seconds,
        password_min_length,max_login_attempts,lockout_seconds}'
}
admin_json PUT "/api/admin/v1/realms/$tenant_id/" "$(tenant_policy false)" >/dev/null
[ "$(status_of "$base_url/realms/$tenant/.well-known/openid-configuration")" = "404" ] || {
  echo "a suspended Realm still published its discovery document" >&2; exit 1; }
introspect_tenant | jq -e '.active == false' >/dev/null || {
  echo "a suspended Realm told a resource server its token was still active" >&2; exit 1; }
[ "$(status_of -H "Authorization: Bearer $tenant_token" "$base_url/realms/$tenant/protocol/openid-connect/userinfo")" = "401" ] || {
  echo "a suspended Realm still served userinfo" >&2; exit 1; }

# The Realm the administrator is signed in to is the one suspension cannot be
# applied to, because it would end the request making it and every credential
# that could undo it.
self_disable="$(curl -sS -b "$cookie_jar" -H "X-CSRF-Token: $csrf" -H 'Content-Type: application/json' \
  -X PUT -d "$(curl -fsS -b "$cookie_jar" "$base_url/api/admin/v1/realms/$realm_id/" \
    | jq -c '{display_name,issuer_url,enabled:false,approval_enabled,access_token_ttl_seconds,
        refresh_token_ttl_seconds,session_ttl_seconds,idle_timeout_seconds,password_min_length,
        max_login_attempts,lockout_seconds}')" "$base_url/api/admin/v1/realms/$realm_id/")"
echo "$self_disable" | jq -e '.error == "realm_self_disable"' >/dev/null || {
  echo "suspending one's own Realm was not refused: $self_disable" >&2; exit 1; }
curl -fsS -b "$cookie_jar" "$base_url/api/admin/v1/realms/$realm_id/" | jq -e '.enabled == true' >/dev/null || {
  echo "the refused request suspended the Realm anyway" >&2; exit 1; }

# A name that is already taken is the most ordinary mistake there is, and it
# used to be answered with the constraint that rejected it.
taken="$(curl -sS -b "$cookie_jar" -H "X-CSRF-Token: $csrf" -H 'Content-Type: application/json' \
  -X POST -d "$(jq -nc --arg username "$disabled_user" '{username:$username,password:"another-password-1234",enabled:true}')" \
  "$base_url/api/admin/v1/realms/$realm_id/users")"
echo "$taken" | jq -e '.error == "conflict"' >/dev/null || {
  echo "a taken username was not reported as a conflict: $taken" >&2; exit 1; }
echo "$taken" | jq -er '.message' | grep -Eqv 'SQLSTATE|constraint|violates' || {
  echo "a taken username answered with database text: $taken" >&2; exit 1; }

echo "ReSSO smoke test passed"
