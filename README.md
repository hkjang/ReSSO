# ReSSO

ReSSO는 Go와 React로 만든 오프라인 운영용 Keycloak-compatible OIDC SSO 서비스입니다. 기존 애플리케이션은 Keycloak Realm issuer 주소를 ReSSO Realm issuer로 바꾸는 방식으로 연동할 수 있습니다.

현재 구현 범위:

- Keycloak URL 형태의 OIDC Discovery, Authorization, Token, UserInfo, JWKS, Logout, Introspection, Revocation
- Authorization Code + PKCE S256, Refresh Token rotation/reuse detection, Client Credentials
- Keycloak 호환 주요 Claim: `azp`, `sid`, `preferred_username`, `realm_access`, `resource_access`
- Realm, 사용자, Client, Role, SSO Session, 서명 키와 감사 이벤트 관리
- Realm Role·Client Role 할당/회수와 Realm 범위 관리자 위임
- 등록된 Web Origin 기반 OIDC CORS 및 Scope 기반 Claim 최소화
- Realm별 LDAP/Active Directory User Federation, 연결·인증 테스트, 전체/JIT/주기 동기화
- 서비스 관리자와 개인화 화면 분리
- 개인 API 키 생성·폐기·회전 및 MCP Streamable HTTP endpoint
- Realm별 선택적 팀장 검토·승인 프로세스
- 관리자용 구조화 서버 로그 조회, Trace ID, 민감 필드 마스킹
- React/MUI 정적 자산을 Go 바이너리에 포함한 단일 오프라인 Docker 이미지

## 환경변수

PostgreSQL과 최초 관리자 값이 필요하며, 키 보호 설정은 분리형 Keyring 또는 기존 단일 키 중 하나를 선택합니다. Reverse Proxy를 사용하는 경우 신뢰할 Proxy CIDR을 선택적으로 지정합니다.

| 이름 | 설명 |
|---|---|
| `POSTGRES_DSN` | PostgreSQL 연결 문자열. 운영에서는 `sslmode=require` 이상을 권장합니다. |
| `BOOTSTRAP_ADMIN` | 최초 `master` Realm 서비스 관리자 아이디 |
| `BOOTSTRAP_ADMIN_PASSWORD` | 최초 관리자 비밀번호, 최소 12자 |
| `DATA_ENCRYPTION_KEYS` | 권장. 암호화 Keyring. `key-id:encoded-key`를 쉼표로 구분하며 첫 키가 신규 Signing Private Key·LDAP Credential 암호화에 사용됩니다. |
| `DIGEST_KEYS` | 권장. Session·Token·API Key HMAC Keyring. 형식은 위와 같고 첫 키가 신규 Digest에 사용됩니다. |
| `ENCRYPTION_KEY` | v0.2.0 호환 단일 32바이트 키. 분리형 Keyring이 없으면 양쪽 용도로 사용하며, Keyring과 함께 설정하면 Upgrade용 읽기 키로 자동 추가됩니다. |
| `TRUSTED_PROXY_CIDRS` | 선택. 쉼표로 구분한 Reverse Proxy CIDR. 설정된 Proxy에서 온 `X-Forwarded-For`와 `X-Forwarded-Proto`만 신뢰합니다. |

`BOOTSTRAP_ADMIN_PASSWORD`는 최초 계정 생성에만 사용됩니다. 컨테이너 재시작이나 값 변경으로 기존 비밀번호가 재설정되지 않습니다.

서로 다른 키를 생성하는 예:

```bash
printf 'DATA_ENCRYPTION_KEYS=data-2026-08:%s\n' "$(openssl rand -base64 32)"
printf 'DIGEST_KEYS=digest-2026-08:%s\n' "$(openssl rand -base64 32)"
```

두 Keyring은 각각 최소 하나의 32바이트 키가 필요합니다. 기존 `ENCRYPTION_KEY` 단일 키 모드는 v0.2.0 암호문 형식을 유지하므로 모든 인스턴스를 먼저 새 버전으로 안전하게 올릴 수 있습니다. 이후 기존 키를 `legacy` 읽기 키로 유지하며 분리형 Keyring을 활성화하세요. 암호문에는 Data Encryption Key ID가 저장되므로 ID는 키 재료와 함께 불변 식별자로 관리하고, 같은 키 재료라도 ID를 바꾸거나 다른 키에 재사용하지 마세요. `crypto rewrap`은 Signing Private Key와 LDAP Bind Credential만 활성 Data Encryption Key로 다시 암호화합니다. 암호화 키는 rewrap과 진단을 마친 뒤 제거할 수 있지만, Digest Key는 재작성할 수 없으므로 해당 키로 만든 Session·Token·API Key가 모두 만료되거나 회전될 때까지 유지해야 합니다.

## 실행

PostgreSQL 데이터베이스를 먼저 준비한 후:

```bash
cp .env.example .env
# .env의 필수 설정과 키를 실제 운영값으로 변경
docker compose -f compose.offline.yaml up -d
```

브라우저에서 `http://localhost:8080`으로 접속합니다. 운영에서는 TLS를 종료하는 Reverse Proxy 뒤에 배치하고 Realm의 Issuer URL을 외부 HTTPS 주소로 설정하세요. 이때 `TRUSTED_PROXY_CIDRS`를 실제 Proxy 네트워크로 제한해야 Secure Cookie와 원본 Client IP가 올바르게 처리됩니다.

기본 `master` Realm issuer는 최초 기동 시 `http://localhost:8080/realms/master`입니다. 운영 배포 직후 관리자 화면의 Realm 설정에서 실제 외부 URL로 변경해야 합니다.

## 운영 유지보수 CLI

다음 명령은 HTTP 서버를 시작하지 않고 PostgreSQL에 직접 연결합니다. 진단과 복구에는 `POSTGRES_DSN` 및 현재 Keyring이 필요하지만 Bootstrap 관리자 환경변수는 필요하지 않습니다.

```bash
docker compose -f compose.maintenance.yaml --profile maintenance run --rm resso-maintenance admin diagnose
docker compose -f compose.maintenance.yaml --profile maintenance run --rm resso-maintenance crypto rewrap

read -rsp 'New recovery password: ' RESSO_RECOVERY_PASSWORD; echo
printf '%s\n' "$RESSO_RECOVERY_PASSWORD" | docker compose -f compose.maintenance.yaml --profile maintenance run --rm -T resso-maintenance \
  admin recover --username recovery-admin --password-stdin
unset RESSO_RECOVERY_PASSWORD
```

`admin recover`는 `master` Realm의 로컬 관리자를 생성하거나 비밀번호·잠금·권한을 복구하고 기존 Session, Refresh Token, 개인 API Key를 폐기합니다. LDAP 계정을 로컬 계정으로 변환하지 않습니다. 자세한 Keyring 전환 순서는 [운영 가이드](docs/operations.md)를 참고하세요.

## OIDC 연동

Discovery URL:

```text
https://sso.company.com/realms/{realm}/.well-known/openid-configuration
```

주요 Endpoint:

```text
/realms/{realm}/protocol/openid-connect/auth
/realms/{realm}/protocol/openid-connect/token
/realms/{realm}/protocol/openid-connect/userinfo
/realms/{realm}/protocol/openid-connect/certs
/realms/{realm}/protocol/openid-connect/logout
/realms/{realm}/protocol/openid-connect/token/introspect
/realms/{realm}/protocol/openid-connect/revoke
```

Public Client는 PKCE S256이 강제됩니다. Redirect URI와 Post Logout Redirect URI는 등록값과 정확히 일치해야 합니다.
브라우저 SPA는 Client에 등록한 정확한 Web Origin에서만 Token·UserInfo endpoint의 CORS 응답을 받을 수 있습니다. `profile`, `email`, `roles` Claim은 요청 Scope에 포함된 경우에만 제공됩니다.

## MCP와 REST API

- OpenAPI: `/api/openapi.json`
- MCP Streamable HTTP: `POST /mcp`
- OAuth Protected Resource Metadata: `/.well-known/oauth-protected-resource`

개인 설정 → 개인 API 키에서 `mcp:read` 범위의 키를 만든 후 다음처럼 연결합니다. `api:read`는 개인 REST GET API, 관리자는 추가 `admin:read`로 권한 범위 내 관리 GET API를 호출할 수 있습니다. 변경 API는 CSRF가 적용된 브라우저 세션만 허용합니다.

```json
{
  "mcpServers": {
    "resso": {
      "url": "https://sso.company.com/mcp",
      "headers": {
        "Authorization": "Bearer rk_xxxxx.yyyyy"
      }
    }
  }
}
```

MCP 도구는 기본적으로 읽기 전용이며 Secret이나 Private Key를 반환하지 않습니다.

## 오프라인 이미지 반입

GitHub Release에서 `resso-vX.Y.Z.tar.gz`를 내려받아 오프라인망으로 옮깁니다.
공식 오프라인 아카이브는 `linux/amd64` 전용입니다. ARM64 환경에서는 동일 태그의 소스에서 대상 플랫폼용 이미지를 별도로 빌드해야 합니다.

```bash
sha256sum resso-vX.Y.Z.tar.gz
./scripts/offline-load.sh resso-vX.Y.Z.tar.gz
docker image inspect resso:vX.Y.Z
```

릴리즈 태그 `vX.Y.Z`를 GitHub에 push하면 CI가 다음 하나의 실행 산출물을 Release에 첨부합니다.

```text
Docker image:  resso:vX.Y.Z
Archive:       resso-vX.Y.Z.tar.gz
```

로컬에서 동일한 아카이브를 만들려면:

```bash
./scripts/release-image.sh v0.2.1
```

## 개발 및 검증

```bash
go test ./...
go vet ./...
cd web
npm ci
npm run test
npm run build
```

실제 PostgreSQL과 실행 중인 ReSSO를 대상으로 OIDC, Refresh, UserInfo, 개인 API Key와 MCP까지 확인:

```bash
./scripts/smoke-test.sh http://127.0.0.1:8080 admin 'your-password'
```

Smoke test는 PKCE, Scope 기반 Claim, Refresh Token 재사용 탐지, Web Origin CORS, Realm/Client Role, Realm 관리자 격리, 개인 API Key REST와 MCP를 함께 검증합니다.

## 운영 보안

- `POSTGRES_DSN`, Bootstrap Password와 모든 Keyring 값을 로그에 남기지 마세요.
- TLS를 강제하고 PostgreSQL TLS도 활성화하세요.
- Data Encryption·Digest Keyring과 PostgreSQL 백업을 서로 분리 보관하세요.
- 개인 API Key와 Client Secret은 생성 직후 한 번만 표시됩니다.
- 관리자 화면의 감사 이벤트와 서버 로그를 정기적으로 검토하세요.
- Signing Key 회전 후 이전 키는 기존 Token 검증을 위해 일정 시간 JWKS에 유지됩니다.
- LDAP Bind Credential도 Data Encryption Keyring으로 암호화되며 API·MCP·감사로그에 평문으로 반환하지 않습니다.
- 현재 릴리즈는 Kerberos/SPNEGO, MFA/TOTP, SAML, WebAuthn, 외부 Identity Broker를 포함하지 않습니다. 해당 기능이 필요한 조직은 별도 보안 검토와 단계적 확장이 필요합니다.

자세한 운영 절차는 [docs/operations.md](docs/operations.md), [LDAP User Federation 가이드](docs/user-federation.md), 호환 범위는 [docs/compatibility.md](docs/compatibility.md)를 참고하세요.
