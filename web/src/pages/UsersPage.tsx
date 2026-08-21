import { useEffect, useState, type FormEvent } from 'react'
import LockOpenRoundedIcon from '@mui/icons-material/LockOpenRounded'
import SearchRoundedIcon from '@mui/icons-material/SearchRounded'
import { Alert, Box, Button, Checkbox, Chip, Dialog, DialogActions, DialogContent, DialogTitle, FormControlLabel, InputAdornment, MenuItem, Stack, Switch, Table, TableBody, TableCell, TableContainer, TableHead, TablePagination, TableRow, TextField, ToggleButton, ToggleButtonGroup, Tooltip, Typography } from '@mui/material'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, jsonBody } from '../lib/api'
import { useRealms, useRealmSelection } from '../lib/realms'
import type { User, UserRoleMappings } from '../types'
import { formatDate } from '../lib/format'
import { EMAIL_MAX_LENGTH, normalizeEmail } from '../lib/email'
import { RealmPicker } from '../components/RealmPicker'
import { PageHeader, ContentCard, StatusChip } from '../components/Page'
import { DetailDrawer } from '../components/DetailDrawer'
import { EmptyState, ErrorAlert, PageLoading } from '../components/Feedback'
import { CopyButton } from '../components/CopyField'
import { useToast } from '../components/toast-context'

const blankUser = { username: '', email: '', email_verified: false, display_name: '', password: '', enabled: true, manager_id: '' }

type StatusFilter = 'all' | 'locked' | 'disabled'

export function UsersPage() {
  const queryClient = useQueryClient()
  const { notify } = useToast()
  const realms = useRealms()
  const selection = useRealmSelection(realms.data?.items)
  const [searchInput, setSearchInput] = useState('')
  const [search, setSearch] = useState('')
  const [page, setPage] = useState(0)
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all')
  const [rowsPerPage, setRowsPerPage] = useState(50)
  const [createOpen, setCreateOpen] = useState(false)
  const [createForm, setCreateForm] = useState(blankUser)
  const [selected, setSelected] = useState<User | null>(null)
  const [editForm, setEditForm] = useState<User | null>(null)
  const [resetPassword, setResetPassword] = useState('')
  const [realmRoleIDs, setRealmRoleIDs] = useState<string[]>([])
  const [clientRoleIDs, setClientRoleIDs] = useState<string[]>([])
  const users = useQuery({
    queryKey: ['users', selection.realmID, search, page, rowsPerPage],
    queryFn: () => api<{ items: User[]; total: number }>(`/api/admin/v1/realms/${selection.realmID}/users?q=${encodeURIComponent(search)}&limit=${rowsPerPage}&offset=${page * rowsPerPage}`),
    enabled: Boolean(selection.realmID),
  })
  const managers = useQuery({
    queryKey: ['users-managers', selection.realmID],
    queryFn: () => api<{ items: User[] }>(`/api/admin/v1/realms/${selection.realmID}/users?limit=500`),
    enabled: Boolean(selection.realmID),
  })
  const roleMappings = useQuery({
    queryKey: ['user-role-mappings', selection.realmID, selected?.id],
    queryFn: () => api<UserRoleMappings>(`/api/admin/v1/realms/${selection.realmID}/users/${selected!.id}/role-mappings`),
    enabled: Boolean(selection.realmID && selected?.id),
  })
  useEffect(() => {
    const timer = window.setTimeout(() => { setSearch(searchInput.trim()); setPage(0) }, 300)
    return () => window.clearTimeout(timer)
  }, [searchInput])
  // These three derive editor state from data that arrives asynchronously.
  // Adjusting during render instead of in an effect is React's documented
  // pattern for it: the extra render happens before the browser paints, so it
  // cannot cause the visible flash of stale values an effect would.
  const [pagedRealm, setPagedRealm] = useState(selection.realmID)
  if (pagedRealm !== selection.realmID) {
    setPagedRealm(selection.realmID)
    setPage(0)
  }
  // The version is part of the identity so that saving, which returns a
  // normalized record, refreshes the form the same way selecting a row does.
  const editVersion = selected ? `${selected.id}:${selected.updated_at}` : ''
  const [loadedEdit, setLoadedEdit] = useState(editVersion)
  if (loadedEdit !== editVersion) {
    setLoadedEdit(editVersion)
    setEditForm(selected ? { ...selected } : null)
  }
  const [loadedMappings, setLoadedMappings] = useState<UserRoleMappings | undefined>(undefined)
  if (loadedMappings !== roleMappings.data) {
    setLoadedMappings(roleMappings.data)
    setRealmRoleIDs(roleMappings.data?.realm_role_ids ?? [])
    setClientRoleIDs(roleMappings.data?.client_role_ids ?? [])
  }
  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['users', selection.realmID] })
  const create = useMutation({
    mutationFn: () => api<User>(`/api/admin/v1/realms/${selection.realmID}/users`, { method: 'POST', ...jsonBody({ ...createForm, manager_id: createForm.manager_id || undefined }) }),
    onSuccess: async () => { setCreateOpen(false); setCreateForm(blankUser); await invalidate() },
  })
  const update = useMutation({
    mutationFn: () => api<User>(`/api/admin/v1/realms/${selection.realmID}/users/${editForm!.id}`, { method: 'PUT', ...jsonBody({ email: editForm!.email, email_verified: editForm!.email_verified, display_name: editForm!.display_name, enabled: editForm!.enabled, manager_id: editForm!.manager_id || undefined }) }),
    onSuccess: async (saved) => { setSelected(saved); await invalidate() },
  })
  const reset = useMutation({
    mutationFn: () => api<void>(`/api/admin/v1/realms/${selection.realmID}/users/${selected!.id}/password`, { method: 'PUT', ...jsonBody({ new_password: resetPassword }) }),
    onSuccess: () => setResetPassword(''),
  })
  const unlock = useMutation({
    mutationFn: (user: User) => api<User>(`/api/admin/v1/realms/${selection.realmID}/users/${user.id}/unlock`, { method: 'POST' }),
    onSuccess: async (saved) => {
      notify(`${saved.display_name} 계정의 잠금을 해제했습니다.`)
      if (selected?.id === saved.id) setSelected(saved)
      await invalidate()
    },
    onError: () => notify('잠금을 해제하지 못했습니다.', 'error'),
  })
  const saveRoles = useMutation({
    mutationFn: () => api<UserRoleMappings>(`/api/admin/v1/realms/${selection.realmID}/users/${selected!.id}/role-mappings`, {
      method: 'PUT', ...jsonBody({ realm_role_ids: realmRoleIDs, client_role_ids: clientRoleIDs }),
    }),
    onSuccess: async (saved) => {
      setRealmRoleIDs(saved.realm_role_ids)
      setClientRoleIDs(saved.client_role_ids)
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ['user-role-mappings', selection.realmID, selected?.id] }),
        queryClient.invalidateQueries({ queryKey: ['me'] }),
      ])
    },
  })
  const toggle = (values: string[], value: string, setter: (next: string[]) => void) => setter(values.includes(value) ? values.filter((item) => item !== value) : [...values, value])
  const emailMatchesSelected = normalizeEmail(editForm?.email) === normalizeEmail(selected?.email)
  const isLocked = (user: User) => Boolean(user.locked_until && new Date(user.locked_until) > new Date())
  // The filter narrows the page that is already loaded; the server-side query
  // stays a plain paged search so the count in the pager remains truthful.
  const visibleUsers = (users.data?.items ?? []).filter((user) => {
    if (statusFilter === 'locked') return isLocked(user)
    if (statusFilter === 'disabled') return !user.enabled
    return true
  })
  if (realms.isLoading) return <PageLoading />
  if (realms.error) return <ErrorAlert error={realms.error} />
  return (
    <>
      <PageHeader title="사용자" description="Realm별 계정 수명주기, 잠금과 팀장 관계를 관리합니다." action={{ label: '사용자 추가', onClick: () => setCreateOpen(true) }} />
      <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.5} sx={{ mb: 2 }}>
        <RealmPicker realms={realms.data?.items ?? []} value={selection.realmID} onChange={selection.setRealmID} />
        <TextField value={searchInput} onChange={(e) => setSearchInput(e.target.value)} placeholder="아이디, 이메일, 이름 검색" aria-label="사용자 검색" sx={{ maxWidth: 400 }} InputProps={{ startAdornment: <InputAdornment position="start"><SearchRoundedIcon /></InputAdornment> }} />
        <ToggleButtonGroup exclusive size="small" value={statusFilter} onChange={(_, value: StatusFilter | null) => value && setStatusFilter(value)} aria-label="상태 필터" sx={{ alignSelf: { sm: 'center' } }}>
          <ToggleButton value="all">전체</ToggleButton>
          <ToggleButton value="locked">잠김</ToggleButton>
          <ToggleButton value="disabled">비활성</ToggleButton>
        </ToggleButtonGroup>
      </Stack>
      <ContentCard noPadding>
        {users.isLoading ? <PageLoading /> : users.error ? <Box sx={{ p: 2 }}><ErrorAlert error={users.error} /></Box> : !users.data?.items.length ? <EmptyState title="사용자가 없습니다" description="검색 조건을 바꾸거나 새 사용자를 추가하세요." /> : !visibleUsers.length ? <EmptyState title="이 페이지에 해당하는 사용자가 없습니다" description="상태 필터는 현재 페이지에만 적용됩니다. 필터를 해제하거나 다른 페이지를 확인하세요." /> : <>
          <TableContainer sx={{ maxHeight: 'calc(100vh - 315px)' }}><Table stickyHeader aria-label="사용자 목록"><TableHead><TableRow><TableCell>사용자</TableCell><TableCell>이메일</TableCell><TableCell>소스</TableCell><TableCell>상태</TableCell><TableCell>마지막 비밀번호 변경</TableCell><TableCell align="right">작업</TableCell></TableRow></TableHead><TableBody>
            {visibleUsers.map((user) => <TableRow hover key={user.id} onClick={() => setSelected(user)} sx={{ cursor: 'pointer' }} tabIndex={0} onKeyDown={(e) => { if (e.key === 'Enter') setSelected(user) }}><TableCell><Typography fontWeight={680}>{user.display_name}</Typography><Typography variant="caption" color="text.secondary" className="mono">{user.username}</Typography></TableCell><TableCell>{user.email ? <Stack direction="row" spacing={.7} alignItems="center"><span>{user.email}</span>{user.email_verified && <Chip label="확인됨" size="small" color="success" variant="outlined" />}</Stack> : '—'}</TableCell><TableCell>{user.federation_id ? <Chip label="LDAP" size="small" color="secondary" variant="outlined" /> : <Chip label="Local" size="small" variant="outlined" />}</TableCell><TableCell><StatusChip active={user.enabled && !isLocked(user)} activeLabel="정상" inactiveLabel={isLocked(user) ? '잠김' : '비활성'} />{isLocked(user) && <Typography variant="caption" color="text.secondary" display="block">{formatDate(user.locked_until)}까지</Typography>}</TableCell><TableCell>{formatDate(user.password_changed_at)}</TableCell><TableCell align="right" onClick={(event) => event.stopPropagation()}>{isLocked(user) ? <Tooltip title="비밀번호를 바꾸지 않고 잠금만 해제합니다"><span><Button size="small" startIcon={<LockOpenRoundedIcon />} disabled={unlock.isPending} onClick={() => unlock.mutate(user)}>잠금 해제</Button></span></Tooltip> : null}</TableCell></TableRow>)}
          </TableBody></Table></TableContainer>
          <TablePagination component="div" count={users.data.total ?? users.data.items.length} page={page} rowsPerPage={rowsPerPage} rowsPerPageOptions={[25, 50, 100]} onPageChange={(_, next) => setPage(next)} onRowsPerPageChange={(event) => { setRowsPerPage(Number(event.target.value)); setPage(0) }} labelRowsPerPage="페이지당" />
        </>}
      </ContentCard>
      <Dialog open={createOpen} onClose={() => setCreateOpen(false)} maxWidth="sm"><Box component="form" onSubmit={(e: FormEvent) => { e.preventDefault(); create.mutate() }}><DialogTitle>사용자 추가</DialogTitle><DialogContent><Stack spacing={2} sx={{ pt: 1 }}>
        {create.error && <ErrorAlert error={create.error} />}
        <TextField label="아이디" required autoComplete="off" value={createForm.username} onChange={(e) => setCreateForm({ ...createForm, username: e.target.value })} inputProps={{ maxLength: 128 }} />
        <TextField label="표시 이름" required value={createForm.display_name} onChange={(e) => setCreateForm({ ...createForm, display_name: e.target.value })} />
        <TextField label="이메일 (선택)" type="email" value={createForm.email} inputProps={{ maxLength: EMAIL_MAX_LENGTH }} onChange={(e) => { const email = e.target.value; setCreateForm({ ...createForm, email, email_verified: email.trim() ? createForm.email_verified : false }) }} />
        <FormControlLabel control={<Switch checked={createForm.email_verified} disabled={!createForm.email.trim()} onChange={(e) => setCreateForm({ ...createForm, email_verified: e.target.checked })} />} label="관리자가 이메일을 확인함" />
        <TextField label="초기 비밀번호" required type="password" autoComplete="new-password" value={createForm.password} onChange={(e) => setCreateForm({ ...createForm, password: e.target.value })} helperText="Realm 비밀번호 정책의 최소 길이를 충족해야 합니다." />
        <TextField select label="팀장" value={createForm.manager_id} onChange={(e) => setCreateForm({ ...createForm, manager_id: e.target.value })}><MenuItem value="">지정 안 함</MenuItem>{managers.data?.items.map((user) => <MenuItem key={user.id} value={user.id}>{user.display_name} ({user.username})</MenuItem>)}</TextField>
        <FormControlLabel control={<Switch checked={createForm.enabled} onChange={(e) => setCreateForm({ ...createForm, enabled: e.target.checked })} />} label="즉시 활성화" />
      </Stack></DialogContent><DialogActions><Button onClick={() => setCreateOpen(false)}>취소</Button><Button type="submit" variant="contained" disabled={create.isPending || !createForm.username || !createForm.password}>추가</Button></DialogActions></Box></Dialog>
      <DetailDrawer open={Boolean(selected)} onClose={() => setSelected(null)} title={selected?.display_name ?? ''} subtitle={selected?.username}>
        {editForm && <Stack spacing={3}>
          <Stack component="form" spacing={2} onSubmit={(e) => { e.preventDefault(); update.mutate() }}>
            {update.error && <ErrorAlert error={update.error} />}{update.isSuccess && <Alert severity="success">사용자 정보를 저장했습니다.</Alert>}
            <TextField label="아이디" value={editForm.username} disabled helperText="아이디는 변경할 수 없습니다." />
            <Stack direction="row" alignItems="center" spacing={.5}><Typography variant="caption" color="text.secondary" className="mono" sx={{ overflowWrap: 'anywhere' }}>User ID {editForm.id}</Typography><CopyButton value={editForm.id} label="User ID 복사" /></Stack>
            {isLocked(editForm) && <Alert severity="warning" action={<Button size="small" color="inherit" startIcon={<LockOpenRoundedIcon />} disabled={unlock.isPending} onClick={() => unlock.mutate(editForm)}>잠금 해제</Button>}>{formatDate(editForm.locked_until)}까지 잠긴 계정입니다. 비밀번호를 재설정하지 않고 잠금만 해제할 수 있습니다.</Alert>}
            <TextField label="표시 이름" required value={editForm.display_name} onChange={(e) => setEditForm({ ...editForm, display_name: e.target.value })} />
            <TextField label="이메일 (선택)" type="email" value={editForm.email} inputProps={{ maxLength: EMAIL_MAX_LENGTH }} onChange={(e) => { const email = e.target.value; setEditForm({ ...editForm, email, email_verified: normalizeEmail(email) === normalizeEmail(selected?.email) ? Boolean(selected?.email_verified) : false }) }} helperText={emailMatchesSelected ? '이메일을 변경하거나 비우면 확인 상태가 자동으로 해제됩니다.' : '새 이메일을 먼저 저장한 뒤 관리자가 확인 상태로 변경할 수 있습니다.'} />
            <FormControlLabel control={<Switch checked={editForm.email_verified} disabled={!editForm.email.trim() || !emailMatchesSelected} onChange={(e) => setEditForm({ ...editForm, email_verified: e.target.checked })} />} label="관리자가 이메일을 확인함" />
            <TextField select label="팀장" value={editForm.manager_id ?? ''} onChange={(e) => setEditForm({ ...editForm, manager_id: e.target.value || undefined })}><MenuItem value="">지정 안 함</MenuItem>{managers.data?.items.filter((u) => u.id !== editForm.id).map((user) => <MenuItem key={user.id} value={user.id}>{user.display_name} ({user.username})</MenuItem>)}</TextField>
            <FormControlLabel control={<Switch checked={editForm.enabled} onChange={(e) => setEditForm({ ...editForm, enabled: e.target.checked })} />} label="계정 활성" />
            <Button type="submit" variant="contained" disabled={update.isPending}>변경 저장</Button>
          </Stack>
          <Box sx={{ borderTop: '1px solid', borderColor: 'divider', pt: 3 }}>
            <Typography variant="h3">Role 매핑</Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mt: .6, mb: 2 }}>Token의 realm_access와 resource_access에 반영됩니다. LDAP에서 관리하는 Role은 여기서 해제할 수 없습니다.</Typography>
            {roleMappings.isLoading ? <PageLoading label="Role을 불러오는 중" /> : roleMappings.error ? <ErrorAlert error={roleMappings.error} /> : <Stack spacing={2}>
              <Box><Typography variant="body2" fontWeight={700} sx={{ mb: 1 }}>Realm Role</Typography><Stack>
                {roleMappings.data?.available_realm_roles.map((role) => {
                  const federationManaged = roleMappings.data.federation_realm_role_ids.includes(role.id)
                  return <FormControlLabel key={role.id} control={<Checkbox checked={realmRoleIDs.includes(role.id)} disabled={federationManaged} onChange={() => toggle(realmRoleIDs, role.id, setRealmRoleIDs)} />} label={<Box><Typography variant="body2" className="mono">{role.name}</Typography>{role.description && <Typography variant="caption" color="text.secondary">{role.description}{federationManaged ? ' · LDAP 관리' : ''}</Typography>}</Box>} />
                })}
              </Stack></Box>
              <Box><Typography variant="body2" fontWeight={700} sx={{ mb: 1 }}>Client Role</Typography><Stack>
                {!roleMappings.data?.available_client_roles.length ? <Typography variant="body2" color="text.secondary">등록된 Client Role이 없습니다.</Typography> : roleMappings.data.available_client_roles.map((role) => <FormControlLabel key={role.id} control={<Checkbox checked={clientRoleIDs.includes(role.id)} onChange={() => toggle(clientRoleIDs, role.id, setClientRoleIDs)} />} label={<Box><Typography variant="body2" className="mono">{role.client_key}:{role.name}</Typography>{role.description && <Typography variant="caption" color="text.secondary">{role.description}</Typography>}</Box>} />)}
              </Stack></Box>
              {saveRoles.error && <ErrorAlert error={saveRoles.error} />}{saveRoles.isSuccess && <Alert severity="success">Role 매핑을 저장했습니다.</Alert>}
              <Button variant="contained" onClick={() => saveRoles.mutate()} disabled={saveRoles.isPending}>Role 저장</Button>
            </Stack>}
          </Box>
          <Box sx={{ borderTop: '1px solid', borderColor: 'divider', pt: 3 }}><Typography variant="h3">비밀번호 재설정</Typography><Typography variant="body2" color="text.secondary" sx={{ mt: .6, mb: 2 }}>{editForm.federation_id ? 'LDAP WRITABLE 공급자만 ReSSO에서 비밀번호를 변경할 수 있습니다. 성공하면 모든 로그인 세션이 종료됩니다.' : '재설정하면 이 사용자의 모든 로그인 세션이 종료됩니다.'}</Typography>{editForm.federation_id && <Alert severity="info" sx={{ mb: 2 }}>이 계정의 인증 원본은 LDAP입니다. READ_ONLY 또는 UNSYNCED라면 원본 디렉터리에서 변경하세요.</Alert>}{reset.error && <ErrorAlert error={reset.error} />}{reset.isSuccess && <Alert severity="success" sx={{ mb: 2 }}>비밀번호를 재설정하고 세션을 종료했습니다.</Alert>}<Stack direction={{ xs: 'column', sm: 'row' }} spacing={1}><TextField label="새 비밀번호" type="password" autoComplete="new-password" value={resetPassword} onChange={(e) => setResetPassword(e.target.value)} /><Button color="warning" variant="outlined" onClick={() => reset.mutate()} disabled={reset.isPending || resetPassword.length < 8} sx={{ whiteSpace: 'nowrap' }}>재설정</Button></Stack></Box>
        </Stack>}
      </DetailDrawer>
    </>
  )
}
