# ReSSO

ReSSO는 Go와 React로 만든 오프라인 운영용 Keycloak-compatible OIDC SSO 서비스입니다. 기존 애플리케이션은 Keycloak Realm issuer 주소를 ReSSO Realm issuer로 바꾸는 방식으로 연동할 수 있습니다.

현재 구현 범위:

- Keycloak URL 형태의 OIDC Discovery, Authorization, Token, UserInfo, JWKS, Logout, Introspection, Revocation
- Authorization Code + PKCE S256, Refresh Token rotation/reuse detection, Client Credentials
- Keycloak 호환 주요 Claim: `azp`, `sid`, `preferred_username`, `realm_access`, `resource_access`
- Realm, 사용자, Client, Role, SSO Session, 서명 키와 감사 이벤트 관리
- 서비스 관리자와 개인화 화면 분리
- 개인 API 키 생성·폐기·회전 및 MCP Streamable HTTP endpoint
- Realm별 선택적 팀장 검토·승인 프로세스
- 관리자용 구조화 서버 로그 조회, Trace ID, 민감 필드 마스킹
- React/MUI 정적 자산을 Go 바이너리에 포함한 단일 오프라인 Docker 이미지

## 필수 환경변수

ReSSO 프로세스가 읽는 환경변수는 아래 네 개뿐입니다.

| 이름 | 설명 |
|---|---|
| `POSTGRES_DSN` | PostgreSQL 연결 문자열. 운영에서는 `sslmode=require` 이상을 권장합니다. |
| `BOOTSTRAP_ADMIN` | 최초 `master` Realm 서비스 관리자 아이디 |
| `BOOTSTRAP_ADMIN_PASSWORD` | 최초 관리자 비밀번호, 최소 12자 |
| `ENCRYPTION_KEY` | Signing Private Key와 비밀값 보호용 32바이트 키의 Base64 또는 64자리 Hex 인코딩 |

`BOOTSTRAP_ADMIN_PASSWORD`는 최초 계정 생성에만 사용됩니다. 컨테이너 재시작이나 값 변경으로 기존 비밀번호가 재설정되지 않습니다.

키 생성 예:

```bash
openssl rand -base64 32
```

`ENCRYPTION_KEY`를 잃으면 저장된 Signing Private Key를 복호화할 수 없습니다. 데이터베이스와 별도로 안전하게 백업하세요.

## 실행

PostgreSQL 데이터베이스를 먼저 준비한 후:

```bash
cp .env.example .env
# .env의 네 값을 실제 운영값으로 변경
docker compose -f compose.offline.yaml up -d
```

브라우저에서 `http://localhost:8080`으로 접속합니다. 운영에서는 TLS를 종료하는 Reverse Proxy 뒤에 배치하고 Realm의 Issuer URL을 외부 HTTPS 주소로 설정하세요.

기본 `master` Realm issuer는 최초 기동 시 `http://localhost:8080/realms/master`입니다. 운영 배포 직후 관리자 화면의 Realm 설정에서 실제 외부 URL로 변경해야 합니다.

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

## MCP와 REST API

- OpenAPI: `/api/openapi.json`
- MCP Streamable HTTP: `POST /mcp`
- OAuth Protected Resource Metadata: `/.well-known/oauth-protected-resource`

개인 설정 → 개인 API 키에서 `mcp:read` 범위의 키를 만든 후 다음처럼 연결합니다.

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
./scripts/release-image.sh v0.1.0
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

## 운영 보안

- `POSTGRES_DSN`, Bootstrap Password, `ENCRYPTION_KEY`를 로그에 남기지 마세요.
- TLS를 강제하고 PostgreSQL TLS도 활성화하세요.
- `ENCRYPTION_KEY`와 PostgreSQL 백업을 분리 보관하세요.
- 개인 API Key와 Client Secret은 생성 직후 한 번만 표시됩니다.
- 관리자 화면의 감사 이벤트와 서버 로그를 정기적으로 검토하세요.
- Signing Key 회전 후 이전 키는 기존 Token 검증을 위해 일정 시간 JWKS에 유지됩니다.
- 현재 릴리즈는 LDAP/AD, MFA/TOTP, SAML, WebAuthn, 외부 Identity Broker를 포함하지 않습니다. 해당 기능이 필요한 조직은 별도 보안 검토와 단계적 확장이 필요합니다.

자세한 운영 절차는 [docs/operations.md](docs/operations.md), 호환 범위는 [docs/compatibility.md](docs/compatibility.md)를 참고하세요.
