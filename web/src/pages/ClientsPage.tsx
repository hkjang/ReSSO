import { useState, type FormEvent } from 'react'
import { useSearchParams } from 'react-router-dom'
import SearchRoundedIcon from '@mui/icons-material/SearchRounded'
import { Alert, Box, Button, Dialog, DialogActions, DialogContent, DialogTitle, FormControlLabel, InputAdornment, MenuItem, Stack, Switch, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, TextField, Typography } from '@mui/material'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, jsonBody } from '../lib/api'
import { useRealms, useRealmSelection } from '../lib/realms'
import { rowActivation } from '../lib/rowActivation'
import type { Client, ClientRole } from '../types'
import { RealmPicker } from '../components/RealmPicker'
import { PageHeader, ContentCard, StatusChip } from '../components/Page'
import { DetailDrawer } from '../components/DetailDrawer'
import { EmptyState, ErrorAlert, PageLoading } from '../components/Feedback'
import { useToast } from '../components/toast-context'
import { CopyButton } from '../components/CopyField'
import { SortableCell } from '../components/SortableTable'
import { sortRows, type SortState } from '../lib/sort'

const lines = (value: string) => value.split('\n').map((item) => item.trim()).filter(Boolean)
const joinLines = (value: string[] | undefined) => (value ?? []).join('\n')
const blankClient = { client_id: '', name: '', type: 'public' as const, redirect_uris: '', post_logout_redirect_uris: '', web_origins: '', grant_types: ['authorization_code', 'refresh_token'], default_scopes: 'openid profile email roles', require_pkce: true, backchannel_logout_uri: '' }

export function ClientsPage() {
  const queryClient = useQueryClient()
  const { notify } = useToast()
  const realms = useRealms()
  const selection = useRealmSelection(realms.data?.items)
  const [createOpen, setCreateOpen] = useState(false)
  const [createForm, setCreateForm] = useState(blankClient)
  const [selected, setSelected] = useState<Client | null>(null)
  const [edit, setEdit] = useState<(Client & { redirectText: string; logoutText: string; originsText: string; scopesText: string }) | null>(null)
  // Handed over by the command palette so the selected client is already
  // filtered. Read from the router on every change, not once at mount: the
  // palette opens over this screen too, and landing on the route the browser is
  // already on remounts nothing, so a term read once applies to the first
  // hand-over only and every later one leaves the list showing the old filter.
  const [searchParams] = useSearchParams()
  const handedOverTerm = searchParams.get('q') ?? ''
  const [search, setSearch] = useState(handedOverTerm)
  // Adjusted during render rather than in an effect, so the list never shows a
  // frame still filtered by the previous term.
  const [appliedTerm, setAppliedTerm] = useState(handedOverTerm)
  if (appliedTerm !== handedOverTerm) {
    setAppliedTerm(handedOverTerm)
    setSearch(handedOverTerm)
  }
  const [sort, setSort] = useState<SortState<'name' | 'client_id' | 'type'>>({ column: 'name', descending: false })
  const [oneTimeSecret, setOneTimeSecret] = useState('')
  // Rotating a secret takes effect immediately and breaks every deployment
  // still holding the old one, so it is confirmed rather than fired on click.
  const [rotateConfirm, setRotateConfirm] = useState(false)
  const [roleName, setRoleName] = useState('')
  const [roleDescription, setRoleDescription] = useState('')
  const clients = useQuery({ queryKey: ['clients', selection.realmID], queryFn: () => api<{ items: Client[] }>(`/api/admin/v1/realms/${selection.realmID}/clients`), enabled: Boolean(selection.realmID) })
  // Derived during render rather than in an effect; the version is part of the
  // identity so a save, which returns the normalized record, refreshes the form.
  const editVersion = selected ? `${selected.id}:${selected.updated_at}` : ''
  const [loadedEdit, setLoadedEdit] = useState(editVersion)
  if (loadedEdit !== editVersion) {
    setLoadedEdit(editVersion)
    setEdit(selected ? { ...selected, redirectText: joinLines(selected.redirect_uris), logoutText: joinLines(selected.post_logout_redirect_uris), originsText: joinLines(selected.web_origins), scopesText: selected.default_scopes.join(' ') } : null)
  }
  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['clients', selection.realmID] })
  const create = useMutation({
    mutationFn: () => api<{ client: Client; client_secret?: string }>(`/api/admin/v1/realms/${selection.realmID}/clients`, { method: 'POST', ...jsonBody({ ...createForm, redirect_uris: lines(createForm.redirect_uris), post_logout_redirect_uris: lines(createForm.post_logout_redirect_uris), web_origins: lines(createForm.web_origins), default_scopes: createForm.default_scopes.split(/\s+/).filter(Boolean) }) }),
    onSuccess: async (result) => { setCreateOpen(false); setCreateForm(blankClient); if (result.client_secret) setOneTimeSecret(result.client_secret); await invalidate() },
  })
  const update = useMutation({
    mutationFn: () => api<Client>(`/api/admin/v1/realms/${selection.realmID}/clients/${edit!.id}`, { method: 'PUT', ...jsonBody({ name: edit!.name, redirect_uris: lines(edit!.redirectText), post_logout_redirect_uris: lines(edit!.logoutText), web_origins: lines(edit!.originsText), grant_types: edit!.grant_types, default_scopes: edit!.scopesText.split(/\s+/).filter(Boolean), require_pkce: edit!.require_pkce, enabled: edit!.enabled, access_token_ttl_seconds: Number(edit!.access_token_ttl_seconds), refresh_token_ttl_seconds: Number(edit!.refresh_token_ttl_seconds), backchannel_logout_uri: edit!.backchannel_logout_uri ?? '' }) }),
    onSuccess: async (saved) => { setSelected(saved); await invalidate() },
  })
  const rotate = useMutation({ mutationFn: () => api<{ client_secret: string }>(`/api/admin/v1/realms/${selection.realmID}/clients/${selected!.id}/rotate-secret`, { method: 'POST' }), onSuccess: (result) => { setRotateConfirm(false); setOneTimeSecret(result.client_secret) } })
  const clientRoles = useQuery({ queryKey: ['client-roles', selection.realmID, selected?.id], queryFn: () => api<{ items: ClientRole[] }>(`/api/admin/v1/realms/${selection.realmID}/clients/${selected!.id}/roles`), enabled: Boolean(selection.realmID && selected?.id) })
  const createRole = useMutation({
    mutationFn: () => api<ClientRole>(`/api/admin/v1/realms/${selection.realmID}/clients/${selected!.id}/roles`, { method: 'POST', ...jsonBody({ name: roleName, description: roleDescription }) }),
    onSuccess: async () => { setRoleName(''); setRoleDescription(''); await queryClient.invalidateQueries({ queryKey: ['client-roles', selection.realmID, selected?.id] }) },
  })
  // A deletion that fails leaves the row where it was and, without this, said
  // nothing — which reads as a click that did not register, so the next thing
  // an administrator does is click again. Every other mutation on this page
  // shows its error.
  const deleteRole = useMutation({
    mutationFn: (role: ClientRole) => api<void>(`/api/admin/v1/realms/${selection.realmID}/clients/${selected!.id}/roles/${role.id}`, { method: 'DELETE' }),
    onSuccess: async () => queryClient.invalidateQueries({ queryKey: ['client-roles', selection.realmID, selected?.id] }),
    onError: (error: Error) => notify(error.message, 'error'),
  })
  const term = search.trim().toLowerCase()
  const visibleClients = sortRows(
    (clients.data?.items ?? []).filter((client) =>
      !term || client.client_id.toLowerCase().includes(term) || client.name.toLowerCase().includes(term)),
    sort.descending,
    (client) => sort.column === 'client_id' ? client.client_id : sort.column === 'type' ? client.type : client.name)
  if (realms.isLoading) return <PageLoading />
  return (
    <>
      <PageHeader title="OIDC Client" description="업무 애플리케이션의 Redirect URI, Grant와 Token 정책을 관리합니다." action={{ label: 'Client 등록', onClick: () => setCreateOpen(true) }} />
      <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.5} sx={{ mb: 2 }}>
        <RealmPicker realms={realms.data?.items ?? []} value={selection.realmID} onChange={selection.setRealmID} />
        <TextField value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Client ID, 이름 검색" sx={{ maxWidth: 360 }}
          inputProps={{ 'aria-label': 'Client 검색' }}
          InputProps={{ startAdornment: <InputAdornment position="start"><SearchRoundedIcon /></InputAdornment> }} />
      </Stack>
      <ContentCard noPadding>{clients.isLoading ? <PageLoading /> : clients.error ? <Box sx={{ p: 2 }}><ErrorAlert error={clients.error} onRetry={() => void clients.refetch()} /></Box> : !clients.data?.items.length ? <EmptyState title="등록된 Client가 없습니다" /> : !visibleClients.length ? <EmptyState title="검색 조건에 맞는 Client가 없습니다" description="Client ID 또는 표시 이름의 일부로 검색합니다." /> : <TableContainer sx={{ maxHeight: 'calc(100vh - 245px)' }}><Table stickyHeader aria-label="OIDC Client 목록"><TableHead><TableRow><SortableCell column="name" sort={sort} onSort={setSort}>Client</SortableCell><SortableCell column="type" sort={sort} onSort={setSort}>유형</SortableCell><TableCell>PKCE</TableCell><TableCell>Grant</TableCell><TableCell>상태</TableCell></TableRow></TableHead><TableBody>{visibleClients.map((client) => <TableRow hover key={client.id} {...rowActivation(() => setSelected(client))} sx={{ cursor: 'pointer' }}><TableCell><Typography fontWeight={680}>{client.name}</Typography><Typography variant="caption" className="mono" color="text.secondary">{client.client_id}</Typography></TableCell><TableCell>{client.type}</TableCell><TableCell><StatusChip active={client.require_pkce} activeLabel="S256" inactiveLabel="선택" /></TableCell><TableCell>{client.grant_types.join(', ')}</TableCell><TableCell><StatusChip active={client.enabled} /></TableCell></TableRow>)}</TableBody></Table></TableContainer>}</ContentCard>
      <Dialog open={createOpen} onClose={() => setCreateOpen(false)} maxWidth="md"><Box component="form" onSubmit={(e: FormEvent) => { e.preventDefault(); create.mutate() }}><DialogTitle>OIDC Client 등록</DialogTitle><DialogContent><Stack spacing={2} sx={{ pt: 1 }}>{create.error && <ErrorAlert error={create.error} />}<Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}><TextField label="Client ID" required value={createForm.client_id} onChange={(e) => setCreateForm({ ...createForm, client_id: e.target.value })} /><TextField label="표시 이름" required value={createForm.name} onChange={(e) => setCreateForm({ ...createForm, name: e.target.value })} /></Stack><TextField select label="Client 유형" value={createForm.type} onChange={(e) => setCreateForm({ ...createForm, type: e.target.value as 'public' })}><MenuItem value="public">public — SPA/Mobile</MenuItem><MenuItem value="confidential">confidential — Server</MenuItem></TextField><TextField label="Redirect URI" required multiline minRows={3} value={createForm.redirect_uris} onChange={(e) => setCreateForm({ ...createForm, redirect_uris: e.target.value })} helperText="한 줄에 하나씩 정확한 HTTPS callback URI를 입력합니다. localhost만 HTTP가 허용됩니다." /><TextField label="Post Logout Redirect URI" multiline minRows={2} value={createForm.post_logout_redirect_uris} onChange={(e) => setCreateForm({ ...createForm, post_logout_redirect_uris: e.target.value })} /><TextField label="Web Origin" multiline minRows={2} value={createForm.web_origins} onChange={(e) => setCreateForm({ ...createForm, web_origins: e.target.value })} /><TextField label="허용 Scope" value={createForm.default_scopes} onChange={(e) => setCreateForm({ ...createForm, default_scopes: e.target.value })} helperText="공백으로 구분합니다." /><FormControlLabel control={<Switch checked={createForm.require_pkce} onChange={(e) => setCreateForm({ ...createForm, require_pkce: e.target.checked })} />} label="PKCE S256 요구" /></Stack></DialogContent><DialogActions><Button onClick={() => setCreateOpen(false)}>취소</Button><Button type="submit" variant="contained" disabled={create.isPending || !createForm.client_id || !createForm.redirect_uris}>등록</Button></DialogActions></Box></Dialog>
      <DetailDrawer open={Boolean(selected)} onClose={() => setSelected(null)} title={selected?.name ?? ''} subtitle={selected?.client_id} width={620}>{edit && <Stack component="form" spacing={2.2} onSubmit={(e) => { e.preventDefault(); update.mutate() }}>{update.error && <ErrorAlert error={update.error} />}{update.isSuccess && <Alert severity="success">Client 설정을 저장했습니다.</Alert>}<Stack direction="row" spacing={2}><TextField label="Client ID" disabled value={edit.client_id} /><TextField label="유형" disabled value={edit.type} /></Stack><TextField label="표시 이름" value={edit.name} onChange={(e) => setEdit({ ...edit, name: e.target.value })} /><TextField label="Redirect URI" multiline minRows={4} value={edit.redirectText} onChange={(e) => setEdit({ ...edit, redirectText: e.target.value })} /><TextField label="Post Logout Redirect URI" multiline minRows={3} value={edit.logoutText} onChange={(e) => setEdit({ ...edit, logoutText: e.target.value })} /><TextField label="Web Origin" multiline minRows={2} value={edit.originsText} onChange={(e) => setEdit({ ...edit, originsText: e.target.value })} helperText="등록된 Origin만 OIDC endpoint의 CORS 요청을 허용합니다." /><TextField label="허용 Scope" value={edit.scopesText} onChange={(e) => setEdit({ ...edit, scopesText: e.target.value })} /><FormControlLabel control={<Switch checked={edit.require_pkce || edit.type === 'public'} disabled={edit.type === 'public'} onChange={(e) => setEdit({ ...edit, require_pkce: e.target.checked })} />} label={edit.type === 'public' ? 'PKCE S256 요구 (Public Client는 해제할 수 없습니다)' : 'PKCE S256 요구'} /><FormControlLabel control={<Switch checked={edit.enabled} onChange={(e) => setEdit({ ...edit, enabled: e.target.checked })} />} label="Client 활성" /><Stack direction="row" spacing={2}><TextField label="Access Token (초)" type="number" value={edit.access_token_ttl_seconds} onChange={(e) => setEdit({ ...edit, access_token_ttl_seconds: Number(e.target.value) })} /><TextField label="Refresh Token (초)" type="number" value={edit.refresh_token_ttl_seconds} onChange={(e) => setEdit({ ...edit, refresh_token_ttl_seconds: Number(e.target.value) })} /></Stack><TextField label="Back-channel Logout URI" type="url" value={edit.backchannel_logout_uri ?? ''} onChange={(e) => setEdit({ ...edit, backchannel_logout_uri: e.target.value })} /><Button type="submit" variant="contained" disabled={update.isPending}>설정 저장</Button>{edit.type === 'confidential' && <Button color="warning" variant="outlined" onClick={() => setRotateConfirm(true)} disabled={rotate.isPending}>Client Secret 회전</Button>}<Box sx={{ borderTop: '1px solid', borderColor: 'divider', pt: 3, mt: 1 }}><Typography variant="h3">Client Role</Typography><Typography variant="body2" color="text.secondary" sx={{ mt: .5, mb: 2 }}>사용자에게 할당하면 resource_access Claim에 포함됩니다.</Typography>{clientRoles.error && <ErrorAlert error={clientRoles.error} />}{createRole.error && <ErrorAlert error={createRole.error} />}<Stack spacing={1}>{clientRoles.data?.items.map((role) => <Stack key={role.id} direction="row" alignItems="center" spacing={1} sx={{ p: 1.2, border: '1px solid', borderColor: 'divider', borderRadius: 1 }}><Box sx={{ flex: 1 }}><Typography className="mono" fontWeight={650}>{role.name}</Typography><Typography variant="caption" color="text.secondary">{role.description || '설명 없음'}</Typography></Box><Button type="button" size="small" color="error" onClick={() => deleteRole.mutate(role)} disabled={deleteRole.isPending}>삭제</Button></Stack>)}</Stack><Stack direction={{ xs: 'column', sm: 'row' }} spacing={1} sx={{ mt: 2 }}><TextField size="small" label="Role 이름" value={roleName} onChange={(e) => setRoleName(e.target.value)} /><TextField size="small" label="설명" value={roleDescription} onChange={(e) => setRoleDescription(e.target.value)} /><Button type="button" variant="outlined" onClick={() => createRole.mutate()} disabled={!roleName.trim() || createRole.isPending}>추가</Button></Stack></Box></Stack>}</DetailDrawer>
      <Dialog open={rotateConfirm} onClose={() => setRotateConfirm(false)} maxWidth="xs">
        <DialogTitle>Client Secret을 회전할까요?</DialogTitle>
        <DialogContent>
          <Alert severity="warning" sx={{ mb: 2 }}>이전 Secret은 즉시 사용할 수 없습니다.</Alert>
          <Typography variant="body2"><strong className="mono">{selected?.client_id}</strong>를 사용하는 모든 배포에 새 Secret을 반영하기 전까지 해당 애플리케이션의 Token 발급이 실패합니다. 배포 창을 확보한 뒤 진행하세요.</Typography>
          {rotate.error && <Box sx={{ mt: 2 }}><ErrorAlert error={rotate.error} /></Box>}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setRotateConfirm(false)}>취소</Button>
          <Button color="warning" variant="contained" onClick={() => rotate.mutate()} disabled={rotate.isPending}>회전 실행</Button>
        </DialogActions>
      </Dialog>
      <Dialog open={Boolean(oneTimeSecret)} onClose={() => setOneTimeSecret('')} maxWidth="sm"><DialogTitle>Secret을 지금 복사하세요</DialogTitle><DialogContent><Alert severity="warning" sx={{ mb: 2 }}>이 값은 다시 표시되지 않습니다. 안전한 비밀 저장소에 보관하세요.</Alert><Stack direction="row" spacing={1} alignItems="center"><TextField value={oneTimeSecret} fullWidth InputProps={{ readOnly: true }} inputProps={{ className: 'mono', 'aria-label': '발급된 Client Secret' }} /><CopyButton value={oneTimeSecret} label="Secret 복사" size="medium" /></Stack></DialogContent><DialogActions><Button variant="contained" onClick={() => setOneTimeSecret('')}>확인</Button></DialogActions></Dialog>
    </>
  )
}
