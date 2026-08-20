# LDAP User Federation 가이드

ReSSO의 User Federation은 Realm별로 여러 LDAP/Active Directory 공급자를 등록하고 우선순위 순서로 사용자를 인증합니다. 로컬 계정은 기존 방식으로 인증되며, LDAP에 연결된 사용자는 로컬 비밀번호로 우회하지 않습니다.

## 권장 구성 순서

1. 관리 → User Federation에서 Realm을 선택합니다.
2. `Other / OpenLDAP` 또는 `Active Directory` 프리셋을 선택합니다.
3. Connection URL, Bind DN/Credential, Users DN을 입력합니다.
4. 조직 CA를 PEM으로 넣고 LDAPS 또는 StartTLS를 사용합니다.
5. 연결 테스트 후 전용 시험 사용자의 인증 테스트를 수행합니다.
6. 수동 전체 동기화 결과와 사용자 화면의 `LDAP` 소스를 확인합니다.
7. 필요할 때만 자동 동기화 주기와 누락 사용자 `DISABLE` 정책을 켭니다.

Bind Credential은 `ENCRYPTION_KEY`를 이용한 AES-256-GCM envelope로 PostgreSQL에 저장됩니다. 조회 API는 Secret을 반환하지 않고 설정 여부만 제공합니다.

## 주요 설정

| 설정 | 의미 |
|---|---|
| Priority | 작은 숫자의 공급자부터 JIT 로그인 사용자를 검색합니다. |
| Connection URL | `ldap://host:389` 또는 `ldaps://host:636` 형식입니다. URL 자격증명과 Query는 허용하지 않습니다. |
| StartTLS | `ldap://` 연결을 TLS로 승격합니다. `ldaps://`와 동시에 사용하지 않습니다. |
| Users DN | 사용자 검색 Base DN입니다. |
| Username/RDN/UUID attribute | 로그인 ID, DN 구성 속성, 변경되지 않는 외부 식별자입니다. AD는 보통 `sAMAccountName`, `cn`, `objectGUID`입니다. |
| User object classes/filter | 객체 클래스는 AND 조건으로, 추가 필터는 RFC 4515 필터로 결합됩니다. 로그인 입력은 Escape 후 결합됩니다. |
| Import users | 전체/주기 동기화를 허용합니다. 끄면 전체 동기화는 거부되고 JIT shadow 등록만 사용할 수 있습니다. |
| Sync registrations | 아직 가져오지 않은 LDAP 사용자를 첫 로그인 때 ReSSO shadow 사용자로 등록합니다. |
| Missing user action | `KEEP`은 유지하고 `DISABLE`은 성공한 전체 동기화에서 사라진 사용자를 비활성화하고 세션을 종료합니다. 일부 사용자 동기화가 실패하면 안전을 위해 비활성화를 실행하지 않습니다. |
| Batch size | LDAP paged search 크기입니다. 50~5000 범위입니다. |
| Sync period | 0은 끔, 그 외에는 300~604800초입니다. |

ReSSO의 shadow 사용자는 SSO Session, Role, Audit의 안정적인 관계형 참조를 위한 최소 로컬 레코드입니다. 비밀번호는 저장하지 않으며 실제 인증은 매번 원본 LDAP Bind로 수행합니다.

## Edit mode

| 모드 | 동작 |
|---|---|
| `READ_ONLY` | 프로필과 비밀번호 변경을 거부하고 원본 디렉터리 변경을 안내합니다. |
| `WRITABLE` | email/displayName 변경을 LDAP Modify로 전달합니다. OpenLDAP은 Password Modify extended operation, AD는 TLS 연결에서 `unicodePwd` 변경을 사용합니다. |
| `UNSYNCED` | 프로필의 로컬 변경을 허용하고 이후 동기화에서 덮어쓰지 않습니다. 인증은 계속 LDAP에서 수행하며 비밀번호는 원본에서 변경합니다. |

AD 비밀번호 변경은 반드시 LDAPS 또는 StartTLS가 필요합니다. 디렉터리 ACL이 서비스 계정의 사용자/비밀번호 변경을 허용해야 합니다.

## Group → Realm Role

사용자 엔트리의 `memberOf` 값을 직접 Realm Role로 매핑합니다. 한 줄에 다음 형식으로 입력합니다.

```text
CN=Admins,OU=Groups,DC=company,DC=local => realm-admin
Developers => developer
```

전체 Group DN 또는 첫 RDN의 CN으로 일치시킬 수 있습니다. 대상 Realm Role은 먼저 생성되어 있어야 합니다. ReSSO가 추가한 Federation Role만 추적해 제거하므로 관리자가 직접 할당한 동일 Role을 동기화가 임의로 제거하지 않습니다.

## 장애 및 보안 동작

- 연결된 LDAP 사용자는 공급자 비활성화 또는 LDAP 장애 시 인증에 실패하며 로컬 비밀번호로 fallback하지 않습니다.
- 잘못된 LDAP 비밀번호도 Realm 잠금 정책의 실패 횟수에 포함됩니다.
- 연결·인증 테스트, 설정 변경, 동기화는 감사 이벤트에 기록되지만 비밀번호는 기록하지 않습니다.
- LDAP 작업은 TLS 1.2 이상, 인증서 검증, 연결/작업 제한시간을 사용합니다.
- `DISABLE`은 LDAP 조회 전체가 성공하고 사용자별 실패가 0건일 때만 적용됩니다.
- 공급자 삭제는 연결 사용자가 있으면 기본 거부됩니다. 명시적 연결 해제를 선택하면 사용자를 비활성화하고 세션과 Federation Role을 정리한 뒤 비활성 Local 계정으로 보존합니다.

현재 버전은 direct `memberOf`만 처리합니다. 중첩 Group 탐색, Kerberos/SPNEGO, Changed Users Sync, LDAP 연결 Pool은 후속 확장 범위입니다.
