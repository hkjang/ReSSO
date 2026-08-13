import { useEffect, useState, type FormEvent } from 'react'
import SearchRoundedIcon from '@mui/icons-material/SearchRounded'
import { Alert, Box, Button, Dialog, DialogActions, DialogContent, DialogTitle, FormControlLabel, InputAdornment, MenuItem, Stack, Switch, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, TextField, Typography } from '@mui/material'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, jsonBody } from '../lib/api'
import { useRealms, useRealmSelection } from '../lib/realms'
import type { User } from '../types'
import { formatDate } from '../lib/format'
import { RealmPicker } from '../components/RealmPicker'
import { PageHeader, ContentCard, StatusChip } from '../components/Page'
import { DetailDrawer } from '../components/DetailDrawer'
import { EmptyState, ErrorAlert, PageLoading } from '../components/Feedback'

const blankUser = { username: '', email: '', display_name: '', password: '', enabled: true, manager_id: '' }

export function UsersPage() {
  const queryClient = useQueryClient()
  const realms = useRealms()
  const selection = useRealmSelection(realms.data?.items)
  const [search, setSearch] = useState('')
  const [createOpen, setCreateOpen] = useState(false)
  const [createForm, setCreateForm] = useState(blankUser)
  const [selected, setSelected] = useState<User | null>(null)
  const [editForm, setEditForm] = useState<User | null>(null)
  const [resetPassword, setResetPassword] = useState('')
  const users = useQuery({
    queryKey: ['users', selection.realmID, search],
    queryFn: () => api<{ items: User[] }>(`/api/admin/v1/realms/${selection.realmID}/users?q=${encodeURIComponent(search)}`),
    enabled: Boolean(selection.realmID),
  })
  useEffect(() => setEditForm(selected ? { ...selected } : null), [selected])
  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['users', selection.realmID] })
  const create = useMutation({
    mutationFn: () => api<User>(`/api/admin/v1/realms/${selection.realmID}/users`, { method: 'POST', ...jsonBody({ ...createForm, manager_id: createForm.manager_id || undefined }) }),
    onSuccess: async () => { setCreateOpen(false); setCreateForm(blankUser); await invalidate() },
  })
  const update = useMutation({
    mutationFn: () => api<User>(`/api/admin/v1/realms/${selection.realmID}/users/${editForm!.id}`, { method: 'PUT', ...jsonBody({ email: editForm!.email, display_name: editForm!.display_name, enabled: editForm!.enabled, manager_id: editForm!.manager_id || undefined }) }),
    onSuccess: async (saved) => { setSelected(saved); await invalidate() },
  })
  const reset = useMutation({
    mutationFn: () => api<void>(`/api/admin/v1/realms/${selection.realmID}/users/${selected!.id}/password`, { method: 'PUT', ...jsonBody({ new_password: resetPassword }) }),
    onSuccess: () => setResetPassword(''),
  })
  if (realms.isLoading) return <PageLoading />
  if (realms.error) return <ErrorAlert error={realms.error} />
  return (
    <>
      <PageHeader title="사용자" description="Realm별 계정 수명주기, 잠금과 팀장 관계를 관리합니다." action={{ label: '사용자 추가', onClick: () => setCreateOpen(true) }} />
      <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.5} sx={{ mb: 2 }}>
        <RealmPicker realms={realms.data?.items ?? []} value={selection.realmID} onChange={selection.setRealmID} />
        <TextField value={search} onChange={(e) => setSearch(e.target.value)} placeholder="아이디, 이메일, 이름 검색" aria-label="사용자 검색" sx={{ maxWidth: 400 }} InputProps={{ startAdornment: <InputAdornment position="start"><SearchRoundedIcon /></InputAdornment> }} />
      </Stack>
      <ContentCard noPadding>
        {users.isLoading ? <PageLoading /> : users.error ? <Box sx={{ p: 2 }}><ErrorAlert error={users.error} /></Box> : !users.data?.items.length ? <EmptyState title="사용자가 없습니다" description="검색 조건을 바꾸거나 새 사용자를 추가하세요." /> :
          <TableContainer sx={{ maxHeight: 'calc(100vh - 255px)' }}><Table stickyHeader aria-label="사용자 목록"><TableHead><TableRow><TableCell>사용자</TableCell><TableCell>이메일</TableCell><TableCell>상태</TableCell><TableCell>마지막 비밀번호 변경</TableCell></TableRow></TableHead><TableBody>
            {users.data.items.map((user) => <TableRow hover key={user.id} onClick={() => setSelected(user)} sx={{ cursor: 'pointer' }} tabIndex={0} onKeyDown={(e) => { if (e.key === 'Enter') setSelected(user) }}><TableCell><Typography fontWeight={680}>{user.display_name}</Typography><Typography variant="caption" color="text.secondary" className="mono">{user.username}</Typography></TableCell><TableCell>{user.email}</TableCell><TableCell><StatusChip active={user.enabled && !user.locked_until} activeLabel="정상" inactiveLabel={user.locked_until ? '잠김' : '비활성'} /></TableCell><TableCell>{formatDate(user.password_changed_at)}</TableCell></TableRow>)}
          </TableBody></Table></TableContainer>}
      </ContentCard>
      <Dialog open={createOpen} onClose={() => setCreateOpen(false)} maxWidth="sm"><Box component="form" onSubmit={(e: FormEvent) => { e.preventDefault(); create.mutate() }}><DialogTitle>사용자 추가</DialogTitle><DialogContent><Stack spacing={2} sx={{ pt: 1 }}>
        {create.error && <ErrorAlert error={create.error} />}
        <TextField label="아이디" required autoComplete="off" value={createForm.username} onChange={(e) => setCreateForm({ ...createForm, username: e.target.value })} inputProps={{ maxLength: 128 }} />
        <TextField label="표시 이름" required value={createForm.display_name} onChange={(e) => setCreateForm({ ...createForm, display_name: e.target.value })} />
        <TextField label="이메일" required type="email" value={createForm.email} onChange={(e) => setCreateForm({ ...createForm, email: e.target.value })} />
        <TextField label="초기 비밀번호" required type="password" autoComplete="new-password" value={createForm.password} onChange={(e) => setCreateForm({ ...createForm, password: e.target.value })} helperText="Realm 비밀번호 정책의 최소 길이를 충족해야 합니다." />
        <TextField select label="팀장" value={createForm.manager_id} onChange={(e) => setCreateForm({ ...createForm, manager_id: e.target.value })}><MenuItem value="">지정 안 함</MenuItem>{users.data?.items.map((user) => <MenuItem key={user.id} value={user.id}>{user.display_name} ({user.username})</MenuItem>)}</TextField>
        <FormControlLabel control={<Switch checked={createForm.enabled} onChange={(e) => setCreateForm({ ...createForm, enabled: e.target.checked })} />} label="즉시 활성화" />
      </Stack></DialogContent><DialogActions><Button onClick={() => setCreateOpen(false)}>취소</Button><Button type="submit" variant="contained" disabled={create.isPending || !createForm.username || !createForm.password}>추가</Button></DialogActions></Box></Dialog>
      <DetailDrawer open={Boolean(selected)} onClose={() => setSelected(null)} title={selected?.display_name ?? ''} subtitle={selected?.username}>
        {editForm && <Stack spacing={3}>
          <Stack component="form" spacing={2} onSubmit={(e) => { e.preventDefault(); update.mutate() }}>
            {update.error && <ErrorAlert error={update.error} />}{update.isSuccess && <Alert severity="success">사용자 정보를 저장했습니다.</Alert>}
            <TextField label="아이디" value={editForm.username} disabled helperText="아이디는 변경할 수 없습니다." />
            <TextField label="표시 이름" required value={editForm.display_name} onChange={(e) => setEditForm({ ...editForm, display_name: e.target.value })} />
            <TextField label="이메일" required type="email" value={editForm.email} onChange={(e) => setEditForm({ ...editForm, email: e.target.value })} />
            <TextField select label="팀장" value={editForm.manager_id ?? ''} onChange={(e) => setEditForm({ ...editForm, manager_id: e.target.value || undefined })}><MenuItem value="">지정 안 함</MenuItem>{users.data?.items.filter((u) => u.id !== editForm.id).map((user) => <MenuItem key={user.id} value={user.id}>{user.display_name} ({user.username})</MenuItem>)}</TextField>
            <FormControlLabel control={<Switch checked={editForm.enabled} onChange={(e) => setEditForm({ ...editForm, enabled: e.target.checked })} />} label="계정 활성" />
            <Button type="submit" variant="contained" disabled={update.isPending}>변경 저장</Button>
          </Stack>
          <Box sx={{ borderTop: '1px solid', borderColor: 'divider', pt: 3 }}><Typography variant="h3">비밀번호 재설정</Typography><Typography variant="body2" color="text.secondary" sx={{ mt: .6, mb: 2 }}>재설정하면 이 사용자의 모든 로그인 세션이 종료됩니다.</Typography>{reset.error && <ErrorAlert error={reset.error} />}{reset.isSuccess && <Alert severity="success" sx={{ mb: 2 }}>비밀번호를 재설정하고 세션을 종료했습니다.</Alert>}<Stack direction={{ xs: 'column', sm: 'row' }} spacing={1}><TextField label="새 비밀번호" type="password" autoComplete="new-password" value={resetPassword} onChange={(e) => setResetPassword(e.target.value)} /><Button color="warning" variant="outlined" onClick={() => reset.mutate()} disabled={reset.isPending || resetPassword.length < 8} sx={{ whiteSpace: 'nowrap' }}>재설정</Button></Stack></Box>
        </Stack>}
      </DetailDrawer>
    </>
  )
}
