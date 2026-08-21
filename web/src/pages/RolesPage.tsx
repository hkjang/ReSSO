import { useState, type FormEvent } from 'react'
import { Alert, Box, Button, Chip, Dialog, DialogActions, DialogContent, DialogTitle, Stack, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, TextField, Typography } from '@mui/material'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, jsonBody } from '../lib/api'
import { useRealms, useRealmSelection } from '../lib/realms'
import type { Role } from '../types'
import { formatDate } from '../lib/format'
import { rowActivation } from '../lib/rowActivation'
import { RealmPicker } from '../components/RealmPicker'
import { ContentCard, PageHeader } from '../components/Page'
import { EmptyState, ErrorAlert, PageLoading } from '../components/Feedback'
import { useToast } from '../components/toast-context'
import { SortableCell } from '../components/SortableTable'
import { sortRows, type SortState } from '../lib/sort'

export function RolesPage() {
  const queryClient = useQueryClient()
  const { notify } = useToast()
  const realms = useRealms()
  const selection = useRealmSelection(realms.data?.items)
  const [open, setOpen] = useState(false)
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [selected, setSelected] = useState<Role | null>(null)
  const [editDescription, setEditDescription] = useState('')
  const [confirmDelete, setConfirmDelete] = useState(false)
  const [sort, setSort] = useState<SortState<'name' | 'assigned_users'>>({ column: 'name', descending: false })
  const roles = useQuery({ queryKey: ['roles', selection.realmID], queryFn: () => api<{ items: Role[] }>(`/api/admin/v1/realms/${selection.realmID}/roles`), enabled: Boolean(selection.realmID) })
  const create = useMutation({ mutationFn: () => api<Role>(`/api/admin/v1/realms/${selection.realmID}/roles`, { method: 'POST', ...jsonBody({ name, description }) }), onSuccess: async () => { setOpen(false); setName(''); setDescription(''); await queryClient.invalidateQueries({ queryKey: ['roles', selection.realmID] }) } })
  const update = useMutation({ mutationFn: () => api<Role>(`/api/admin/v1/realms/${selection.realmID}/roles/${selected!.id}`, { method: 'PUT', ...jsonBody({ description: editDescription }) }), onSuccess: async (saved) => { setSelected(saved); setEditDescription(saved.description); await queryClient.invalidateQueries({ queryKey: ['roles', selection.realmID] }) } })
  const remove = useMutation({ mutationFn: () => api<void>(`/api/admin/v1/realms/${selection.realmID}/roles/${selected!.id}`, { method: 'DELETE' }), onSuccess: async () => { setConfirmDelete(false); notify(`Role ${selected?.name}을(를) 삭제했습니다.`); setSelected(null); await queryClient.invalidateQueries({ queryKey: ['roles', selection.realmID] }) } })
  const visibleRoles = sortRows(roles.data?.items ?? [], sort.descending,
    (role) => sort.column === 'assigned_users' ? role.assigned_users : role.name)
  if (realms.isLoading) return <PageLoading />
  return <><PageHeader title="Role" description="Realm Role을 정의하고 Token의 realm_access.roles Claim으로 제공합니다." action={{ label: 'Role 만들기', onClick: () => setOpen(true) }} /><Box sx={{ mb: 2 }}><RealmPicker realms={realms.data?.items ?? []} value={selection.realmID} onChange={selection.setRealmID} /></Box><ContentCard noPadding>{roles.isLoading ? <PageLoading /> : roles.error ? <Box sx={{ p: 2 }}><ErrorAlert error={roles.error} onRetry={() => void roles.refetch()} /></Box> : !roles.data?.items.length ? <EmptyState title="Role이 없습니다" /> : <TableContainer><Table><TableHead><TableRow><SortableCell column="name" sort={sort} onSort={setSort}>Role</SortableCell><TableCell>설명</TableCell><SortableCell column="assigned_users" sort={sort} onSort={setSort} align="right">할당된 사용자</SortableCell><TableCell>생성일</TableCell></TableRow></TableHead><TableBody>{visibleRoles.map((role) => <TableRow hover key={role.id} {...rowActivation(() => { setSelected(role); setEditDescription(role.description) })} sx={{ cursor: 'pointer' }}><TableCell><Stack direction="row" spacing={1} alignItems="center"><Typography fontWeight={680} className="mono">{role.name}</Typography>{role.builtin && <Chip size="small" label="기본" variant="outlined" />}</Stack></TableCell><TableCell>{role.description || '—'}</TableCell><TableCell align="right">{role.assigned_users.toLocaleString()}</TableCell><TableCell>{formatDate(role.created_at)}</TableCell></TableRow>)}</TableBody></Table></TableContainer>}</ContentCard><Dialog open={open} onClose={() => setOpen(false)} maxWidth="sm"><Stack component="form" onSubmit={(e: FormEvent) => { e.preventDefault(); create.mutate() }}><DialogTitle>Role 만들기</DialogTitle><DialogContent><Stack spacing={2} sx={{ pt: 1 }}>{create.error && <ErrorAlert error={create.error} />}<TextField label="Role 이름" required value={name} onChange={(e) => setName(e.target.value)} /><TextField label="설명" multiline minRows={3} value={description} onChange={(e) => setDescription(e.target.value)} /></Stack></DialogContent><DialogActions><Button onClick={() => setOpen(false)}>취소</Button><Button type="submit" variant="contained" disabled={!name || create.isPending}>만들기</Button></DialogActions></Stack></Dialog><Dialog open={Boolean(selected)} onClose={() => setSelected(null)} maxWidth="sm"><DialogTitle>Role 관리 · {selected?.name}</DialogTitle><DialogContent><Stack spacing={2} sx={{ pt: 1 }}>{update.error && <ErrorAlert error={update.error} />}{remove.error && <ErrorAlert error={remove.error} />}<TextField label="Role 이름" value={selected?.name ?? ''} disabled /><TextField label="설명" multiline minRows={3} value={editDescription} onChange={(e) => setEditDescription(e.target.value)} />{selected?.builtin ? <Typography variant="body2" color="text.secondary">기본 Role은 삭제할 수 없습니다.</Typography> : <Typography variant="body2" color="text.secondary">현재 {selected?.assigned_users.toLocaleString() ?? 0}명에게 할당되어 있습니다.</Typography>}</Stack></DialogContent><DialogActions><Button color="error" onClick={() => setConfirmDelete(true)} disabled={remove.isPending || Boolean(selected?.builtin)}>삭제</Button><Box sx={{ flex: 1 }} /><Button onClick={() => setSelected(null)}>닫기</Button><Button variant="contained" onClick={() => update.mutate()} disabled={update.isPending}>저장</Button></DialogActions></Dialog><Dialog open={confirmDelete} onClose={() => setConfirmDelete(false)} maxWidth="xs"><DialogTitle>Role을 삭제할까요?</DialogTitle><DialogContent><Alert severity="warning" sx={{ mb: 2 }}>되돌릴 수 없습니다.</Alert><Typography variant="body2"><strong className="mono">{selected?.name}</strong>을(를) 삭제하면 {selected?.assigned_users ? <>현재 보유한 <strong>{selected.assigned_users.toLocaleString()}명</strong>에게서 즉시 회수되고, </> : null}이후 발급되는 Token의 <span className="mono">realm_access.roles</span>에서 제외됩니다. 이 Role로 접근을 통제하는 애플리케이션이 있는지 먼저 확인하세요.</Typography>{remove.error && <Box sx={{ mt: 2 }}><ErrorAlert error={remove.error} /></Box>}</DialogContent><DialogActions><Button onClick={() => setConfirmDelete(false)}>취소</Button><Button color="error" variant="contained" onClick={() => remove.mutate()} disabled={remove.isPending}>삭제</Button></DialogActions></Dialog></>
}
