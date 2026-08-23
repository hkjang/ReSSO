import { useState, type FormEvent } from 'react'
import { useParams } from 'react-router-dom'
import { Box, Button, Dialog, DialogActions, DialogContent, DialogTitle, FormControlLabel, Stack, Switch, TextField, Typography } from '@mui/material'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { api, jsonBody } from '../lib/api'
import { useAuth } from '../lib/auth-context'
import { useRealms } from '../lib/realms'
import type { Realm } from '../types'
import { PageHeader, ContentCard, StatusChip } from '../components/Page'
import { useToast } from '../components/toast-context'
import { DetailDrawer } from '../components/DetailDrawer'
import { EmptyState, ErrorAlert, PageLoading } from '../components/Feedback'

const newRealm = { name: '', display_name: '', issuer_url: '' }

export function RealmsPage() {
	const { me } = useAuth()
  const { notify } = useToast()
  const params = useParams()
  const queryClient = useQueryClient()
  const realms = useRealms()
  const [createOpen, setCreateOpen] = useState(false)
  const [createForm, setCreateForm] = useState(newRealm)
  const [selected, setSelected] = useState<Realm | null>(null)
  const [form, setForm] = useState<Realm | null>(null)
  // Opening /admin/realms/:realmId selects that Realm once its list has
  // loaded. Both of these adjust state during render instead of in an effect,
  // which is React's documented pattern for deriving from asynchronous data.
  const routeTarget = realms.data?.items.find((realm) => realm.id === params.realmId)
  const [loadedRoute, setLoadedRoute] = useState<string | undefined>(routeTarget?.id)
  if (routeTarget && loadedRoute !== routeTarget.id) {
    setLoadedRoute(routeTarget.id)
    setSelected(routeTarget)
  }
  const formVersion = selected ? `${selected.id}:${selected.updated_at}` : ''
  const [loadedForm, setLoadedForm] = useState(formVersion)
  if (loadedForm !== formVersion) {
    setLoadedForm(formVersion)
    setForm(selected ? { ...selected } : null)
  }
  const create = useMutation({
    mutationFn: () => api<Realm>('/api/admin/v1/realms', { method: 'POST', ...jsonBody(createForm) }),
    onSuccess: async () => { setCreateOpen(false); setCreateForm(newRealm); await queryClient.invalidateQueries({ queryKey: ['realms'] }) },
  })
  const update = useMutation({
    mutationFn: () => api<Realm>(`/api/admin/v1/realms/${form!.id}`, { method: 'PUT', ...jsonBody({
      display_name: form!.display_name, issuer_url: form!.issuer_url, enabled: form!.enabled,
      approval_enabled: form!.approval_enabled, access_token_ttl_seconds: Number(form!.access_token_ttl_seconds),
      refresh_token_ttl_seconds: Number(form!.refresh_token_ttl_seconds), session_ttl_seconds: Number(form!.session_ttl_seconds),
      password_min_length: Number(form!.password_min_length), max_login_attempts: Number(form!.max_login_attempts),
      lockout_seconds: Number(form!.lockout_seconds), idle_timeout_seconds: Number(form!.idle_timeout_seconds),
    }) }),
    onSuccess: async (saved) => { setSelected(saved); notify('Realm 설정을 저장했습니다.'); await queryClient.invalidateQueries({ queryKey: ['realms'] }) },
  })
  if (realms.isLoading) return <PageLoading />
  if (realms.error) return <ErrorAlert error={realms.error} />
  const submitCreate = (event: FormEvent) => { event.preventDefault(); create.mutate() }
  return (
    <>
      <PageHeader title="Realm" description="사용자, Client, 역할과 서명 키가 격리되는 인증 영역입니다." action={me?.permissions.platform_admin ? { label: 'Realm 만들기', onClick: () => setCreateOpen(true) } : undefined} badge={`${realms.data?.items.length ?? 0}`} />
      <ContentCard noPadding>
        {!realms.data?.items.length ? <EmptyState title="Realm이 없습니다" /> : <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', md: 'repeat(2, minmax(0, 1fr))', xl: 'repeat(3, minmax(0, 1fr))' } }}>
          {realms.data.items.map((realm) => <Box component="button" key={realm.id} onClick={() => setSelected(realm)} sx={{ appearance: 'none', border: 0, borderRight: '1px solid', borderBottom: '1px solid', borderColor: 'divider', bgcolor: '#fff', textAlign: 'left', p: 2.5, cursor: 'pointer', '&:hover': { bgcolor: '#f9fafb' } }}>
            <Stack direction="row" justifyContent="space-between" alignItems="flex-start"><Box sx={{ minWidth: 0 }}><Typography fontWeight={720} fontSize={17}>{realm.display_name}</Typography><Typography className="mono" variant="body2" color="text.secondary">{realm.name}</Typography></Box><StatusChip active={realm.enabled} /></Stack>
            <Typography variant="body2" className="mono" noWrap sx={{ mt: 2, color: 'primary.main' }}>{realm.issuer_url}</Typography>
            <Stack direction="row" spacing={1} sx={{ mt: 2 }}><StatusChip active={realm.approval_enabled} activeLabel="승인 사용" inactiveLabel="승인 없음" /></Stack>
          </Box>)}
        </Box>}
      </ContentCard>
      <Dialog open={createOpen} onClose={() => setCreateOpen(false)} maxWidth="sm">
        <Box component="form" onSubmit={submitCreate}>
          <DialogTitle>새 Realm</DialogTitle>
          <DialogContent><Stack spacing={2.2} sx={{ pt: 1 }}>
            {create.error && <ErrorAlert error={create.error} />}
            <TextField label="Realm 이름" required value={createForm.name} onChange={(e) => setCreateForm({ ...createForm, name: e.target.value.toLowerCase() })} helperText="소문자, 숫자, 하이픈만 사용합니다. 생성 후 변경할 수 없습니다." inputProps={{ pattern: '[a-z0-9][a-z0-9-]*', maxLength: 63 }} />
            <TextField label="표시 이름" required value={createForm.display_name} onChange={(e) => setCreateForm({ ...createForm, display_name: e.target.value })} />
            <TextField label="Issuer URL" required type="url" value={createForm.issuer_url} onChange={(e) => setCreateForm({ ...createForm, issuer_url: e.target.value })} placeholder="https://sso.company.com/realms/example" helperText="Discovery와 Token의 iss Claim에 사용되는 외부 공개 URL입니다." />
          </Stack></DialogContent>
          <DialogActions><Button onClick={() => setCreateOpen(false)}>취소</Button><Button type="submit" variant="contained" disabled={create.isPending || !createForm.name || !createForm.display_name || !createForm.issuer_url}>만들기</Button></DialogActions>
        </Box>
      </Dialog>
      <DetailDrawer open={Boolean(selected)} onClose={() => setSelected(null)} title={selected?.display_name ?? ''} subtitle={selected?.name}>
        {form && <Stack component="form" spacing={2.2} onSubmit={(e) => { e.preventDefault(); update.mutate() }}>
          {update.error && <ErrorAlert error={update.error} />}
          <TextField label="표시 이름" required value={form.display_name} onChange={(e) => setForm({ ...form, display_name: e.target.value })} />
          <TextField label="Issuer URL" type="url" required value={form.issuer_url} onChange={(e) => setForm({ ...form, issuer_url: e.target.value })} />
          <FormControlLabel control={<Switch checked={form.enabled} onChange={(e) => setForm({ ...form, enabled: e.target.checked })} />} label="Realm 활성" />
          <Box sx={{ p: 2, bgcolor: '#f9fafb', borderRadius: 1.5, border: '1px solid', borderColor: 'divider' }}>
            <FormControlLabel control={<Switch checked={form.approval_enabled} onChange={(e) => setForm({ ...form, approval_enabled: e.target.checked })} />} label="팀장 검토·승인 프로세스 사용" />
            <Typography variant="body2" color="text.secondary">끄면 사용자 화면과 관리자 메뉴에서 요청·승인·반려 과정이 제외됩니다.</Typography>
          </Box>
          <Typography variant="h3">Token · Session 수명</Typography>
          <TextField label="Access Token (초)" type="number" value={form.access_token_ttl_seconds} onChange={(e) => setForm({ ...form, access_token_ttl_seconds: Number(e.target.value) })} inputProps={{ min: 60, max: 3600 }} helperText="60초에서 3600초 사이" />
          <TextField label="Refresh Token (초)" type="number" value={form.refresh_token_ttl_seconds} onChange={(e) => setForm({ ...form, refresh_token_ttl_seconds: Number(e.target.value) })} inputProps={{ min: 300, max: 2592000 }} helperText="최초 발급 시점부터의 총 수명입니다. 회전해도 연장되지 않으므로, 이 시간이 지나면 RP는 인가 과정을 다시 거칩니다." />
          <TextField label="SSO Session (초)" type="number" value={form.session_ttl_seconds} onChange={(e) => setForm({ ...form, session_ttl_seconds: Number(e.target.value) })} inputProps={{ min: 300, max: 2592000 }} helperText="로그인 후 활동과 무관하게 세션이 유지되는 최대 시간" />
          <TextField label="유휴 만료 (초)" type="number" value={form.idle_timeout_seconds} onChange={(e) => setForm({ ...form, idle_timeout_seconds: Number(e.target.value) })} inputProps={{ min: 0, max: 2592000 }} helperText={form.idle_timeout_seconds === 0 ? '0은 사용 안 함. 설정하면 이 시간 동안 사용되지 않은 세션이 만료됩니다.' : `약 ${Math.round(form.idle_timeout_seconds / 60)}분 동안 사용되지 않으면 만료됩니다. 300초 이상, SSO Session 이하로 설정하세요.`} />
          <Typography variant="h3">비밀번호 · 잠금 정책</Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mt: -1 }}>이 Realm의 모든 사용자에게 적용되며, 개인 설정의 비밀번호 변경 화면에도 그대로 안내됩니다.</Typography>
          <TextField label="비밀번호 최소 길이" type="number" value={form.password_min_length} onChange={(e) => setForm({ ...form, password_min_length: Number(e.target.value) })} inputProps={{ min: 8, max: 128 }} helperText="8자에서 128자 사이" />
          <TextField label="잠금까지 허용할 연속 실패 횟수" type="number" value={form.max_login_attempts} onChange={(e) => setForm({ ...form, max_login_attempts: Number(e.target.value) })} inputProps={{ min: 3, max: 50 }} helperText="3회에서 50회 사이" />
          <TextField label="잠금 유지 시간 (초)" type="number" value={form.lockout_seconds} onChange={(e) => setForm({ ...form, lockout_seconds: Number(e.target.value) })} inputProps={{ min: 30, max: 86400 }} helperText={`30초에서 24시간 사이 · 현재 약 ${Math.round((form.lockout_seconds || 0) / 60)}분`} />
          <Button type="submit" variant="contained" disabled={update.isPending}>설정 저장</Button>
        </Stack>}
      </DetailDrawer>
    </>
  )
}
