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
client_identifier="smoke-$suffix"
client_payload="$(jq -nc --arg client "$client_identifier" '{client_id:$client,name:"Smoke test",type:"public",redirect_uris:["http://localhost:9999/callback"],post_logout_redirect_uris:["http://localhost:9999/logout"],web_origins:["http://localhost:9999"],grant_types:["authorization_code","refresh_token"],default_scopes:["openid","profile","email"],require_pkce:true,backchannel_logout_uri:""}')"
curl -fsS -b "$cookie_jar" -H "X-CSRF-Token: $csrf" -H 'Content-Type: application/json' -d "$client_payload" "$base_url/api/admin/v1/realms/$realm_id/clients" | jq -e '.client.client_id != null' >/dev/null

verifier='dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
challenge='E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'
curl -fsS -b "$cookie_jar" -D "$work_dir/headers" -o /dev/null --get \
  --data-urlencode "client_id=$client_identifier" \
  --data-urlencode 'redirect_uri=http://localhost:9999/callback' \
  --data-urlencode 'response_type=code' \
  --data-urlencode 'scope=openid profile email' \
  --data-urlencode 'state=smoke-state' \
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

curl -fsS -H "Authorization: Bearer $access_token" "$base_url/realms/master/protocol/openid-connect/userinfo" | jq -e '.preferred_username != null' >/dev/null
refreshed="$(curl -fsS -X POST --data-urlencode 'grant_type=refresh_token' --data-urlencode "client_id=$client_identifier" --data-urlencode "refresh_token=$refresh_token" "$base_url/realms/master/protocol/openid-connect/token")"
rotated_refresh="$(echo "$refreshed" | jq -er '.refresh_token')"
echo "$refreshed" | jq -e '.access_token != null' >/dev/null
reuse_status="$(curl -sS -o "$work_dir/reuse.json" -w '%{http_code}' -X POST --data-urlencode 'grant_type=refresh_token' --data-urlencode "client_id=$client_identifier" --data-urlencode "refresh_token=$refresh_token" "$base_url/realms/master/protocol/openid-connect/token")"
[ "$reuse_status" = 400 ] || { echo "refresh token reuse was not rejected" >&2; exit 1; }
family_status="$(curl -sS -o "$work_dir/family.json" -w '%{http_code}' -X POST --data-urlencode 'grant_type=refresh_token' --data-urlencode "client_id=$client_identifier" --data-urlencode "refresh_token=$rotated_refresh" "$base_url/realms/master/protocol/openid-connect/token")"
[ "$family_status" = 400 ] || { echo "refresh token family was not revoked after reuse" >&2; exit 1; }

api_key_payload='{"name":"Smoke MCP","scopes":["mcp:read","api:read"],"expires_days":1}'
api_key_response="$(curl -sS -b "$cookie_jar" -H "X-CSRF-Token: $csrf" -H 'Content-Type: application/json' -d "$api_key_payload" "$base_url/api/v1/me/api-keys")"
api_key="$(echo "$api_key_response" | jq -er '.secret')" || {
  echo "$api_key_response" | jq '{error,message,trace_id}' >&2
  exit 1
}
mcp_request='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"smoke","version":"1"}}}'
curl -fsS -H "Authorization: Bearer $api_key" -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' -d "$mcp_request" "$base_url/mcp" | jq -e '.result.serverInfo.name == "ReSSO"' >/dev/null

echo "ReSSO smoke test passed"
