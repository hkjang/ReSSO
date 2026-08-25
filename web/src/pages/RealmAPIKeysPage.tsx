import { useSearchParams } from 'react-router-dom'
import { Alert, Chip, Stack, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, ToggleButton, ToggleButtonGroup, Typography } from '@mui/material'
import { useQuery } from '@tanstack/react-query'
import { api } from '../lib/api'
import { useRealms, useRealmSelection } from '../lib/realms'
import { formatDate } from '../lib/format'
import { RealmPicker } from '../components/RealmPicker'
import { ContentCard, PageHeader, StatusChip } from '../components/Page'
import { EmptyState, ErrorAlert, PageLoading } from '../components/Feedback'

interface RealmAPIKey {
  id: string
  name: string
  prefix: string
  scopes: string[]
  created_at: string
  expires_at?: string
  last_used_at?: string
  revoked_at?: string
  active: boolean
  inactive_reason?: string
  user_id: string
  username: string
}

// The dashboard reports how many keys stop working within the week; this is
// the screen it links to. Whether it opened filtered has to come from the URL
// so that link can arrive here already narrowed, the same way the locked
// accounts do.
// The server says which condition stopped the key, decided by the clock that
// wrote the timestamps. Working it out here from expires_at would use this
// browser's clock, and would call a disabled account's key expired — which
// sends someone to renew a key that would not work if they did.
const inactiveLabel = (reason?: string) => {
  switch (reason) {
    case 'revoked': return '폐기'
    case 'expired': return '만료'
    case 'account_disabled': return '계정 비활성'
    case 'realm_suspended': return 'Realm 정지'
    default: return '사용 불가'
  }
}

export function RealmAPIKeysPage() {
  const realms = useRealms()
  const selection = useRealmSelection(realms.data?.items)
  const [params, setParams] = useSearchParams()
  const expiringOnly = params.get('expiring') === 'true'
  const setExpiringOnly = (value: boolean) => {
    const next = new URLSearchParams(params)
    if (value) next.set('expiring', 'true')
    else next.delete('expiring')
    setParams(next, { replace: true })
  }
  const keys = useQuery({
    queryKey: ['realm-api-keys', selection.realmID, expiringOnly],
    queryFn: () => api<{ items: RealmAPIKey[] }>(
      `/api/admin/v1/realms/${selection.realmID}/api-keys${expiringOnly ? '?expiring=true' : ''}`),
    enabled: Boolean(selection.realmID),
  })

  if (realms.isLoading) return <PageLoading />
  if (realms.error) return <ErrorAlert error={realms.error} onRetry={() => void realms.refetch()} />
  return <>
    <PageHeader title="API 키" description="이 Realm의 구성원이 발급한 개인 API 키입니다. Secret은 저장되지 않으므로 여기에도 표시되지 않습니다." />
    <Alert severity="info" sx={{ mb: 2 }}>키가 만료되면 그 키를 쓰는 연동은 예고 없이 멈춥니다. 만료가 가까운 키는 소유자에게 회전을 요청하세요.</Alert>
    <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.5} sx={{ mb: 2 }}>
      <RealmPicker realms={realms.data?.items ?? []} value={selection.realmID} onChange={selection.setRealmID} />
      <ToggleButtonGroup exclusive size="small" value={expiringOnly ? 'expiring' : 'all'} aria-label="만료 필터"
        onChange={(_, value: string | null) => value && setExpiringOnly(value === 'expiring')} sx={{ alignSelf: 'center' }}>
        <ToggleButton value="all">전체</ToggleButton>
        <ToggleButton value="expiring">7일 내 만료</ToggleButton>
      </ToggleButtonGroup>
    </Stack>
    <ContentCard noPadding>
      {keys.isLoading ? <PageLoading />
        : keys.error ? <ErrorAlert error={keys.error} onRetry={() => void keys.refetch()} />
          : !keys.data?.items.length
            ? <EmptyState title={expiringOnly ? '7일 내 만료되는 키가 없습니다' : '발급된 개인 API 키가 없습니다'} />
            : <TableContainer><Table aria-label="Realm 개인 API 키 목록">
              <TableHead><TableRow>
                <TableCell>소유자</TableCell><TableCell>이름</TableCell><TableCell>Prefix</TableCell>
                <TableCell>Scope</TableCell><TableCell>마지막 사용</TableCell><TableCell>만료</TableCell><TableCell>상태</TableCell>
              </TableRow></TableHead>
              <TableBody>{keys.data.items.map((key) => <TableRow key={key.id}>
                <TableCell><Typography fontWeight={650}>{key.username}</Typography></TableCell>
                <TableCell>{key.name}</TableCell>
                <TableCell className="mono">{key.prefix}</TableCell>
                <TableCell>{key.scopes.map((scope) => <Chip key={scope} label={scope} size="small" sx={{ mr: .5, mb: .5 }} />)}</TableCell>
                <TableCell>{formatDate(key.last_used_at)}</TableCell>
                <TableCell>{formatDate(key.expires_at)}</TableCell>
                <TableCell><StatusChip active={key.active} activeLabel="활성" inactiveLabel={inactiveLabel(key.inactive_reason)} /></TableCell>
              </TableRow>)}</TableBody>
            </Table></TableContainer>}
    </ContentCard>
  </>
}
