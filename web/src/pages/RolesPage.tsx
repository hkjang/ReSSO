import { useState, type FormEvent } from 'react'
import { Box, Button, Dialog, DialogActions, DialogContent, DialogTitle, Stack, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, TextField, Typography } from '@mui/material'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, jsonBody } from '../lib/api'
import { useRealms, useRealmSelection } from '../lib/realms'
import type { Role } from '../types'
import { formatDate } from '../lib/format'
import { RealmPicker } from '../components/RealmPicker'
import { ContentCard, PageHeader } from '../components/Page'
import { EmptyState, ErrorAlert, PageLoading } from '../components/Feedback'

export function RolesPage() {
  const queryClient = useQueryClient()
  const realms = useRealms()
  const selection = useRealmSelection(realms.data?.items)
  const [open, setOpen] = useState(false)
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [selected, setSelected] = useState<Role | null>(null)
  const [editDescription, setEditDescription] = useState('')
  const roles = useQuery({ queryKey: ['roles', selection.realmID], queryFn: () => api<{ items: Role[] }>(`/api/admin/v1/realms/${selection.realmID}/roles`), enabled: Boolean(selection.realmID) })
  const create = useMutation({ mutationFn: () => api<Role>(`/api/admin/v1/realms/${selection.realmID}/roles`, { method: 'POST', ...jsonBody({ name, description }) }), onSuccess: async () => { setOpen(false); setName(''); setDescription(''); await queryClient.invalidateQueries({ queryKey: ['roles', selection.realmID] }) } })
  const update = useMutation({ mutationFn: () => api<Role>(`/api/admin/v1/realms/${selection.realmID}/roles/${selected!.id}`, { method: 'PUT', ...jsonBody({ description: editDescription }) }), onSuccess: async (saved) => { setSelected(saved); setEditDescription(saved.description); await queryClient.invalidateQueries({ queryKey: ['roles', selection.realmID] }) } })
  const remove = useMutation({ mutationFn: () => api<void>(`/api/admin/v1/realms/${selection.realmID}/roles/${selected!.id}`, { method: 'DELETE' }), onSuccess: async () => { setSelected(null); await queryClient.invalidateQueries({ queryKey: ['roles', selection.realmID] }) } })
  if (realms.isLoading) return <PageLoading />
  return <><PageHeader title="Role" description="Realm Role을 정의하고 Token의 realm_access.roles Claim으로 제공합니다." action={{ label: 'Role 만들기', onClick: () => setOpen(true) }} /><Box sx={{ mb: 2 }}><RealmPicker realms={realms.data?.items ?? []} value={selection.realmID} onChange={selection.setRealmID} /></Box><ContentCard noPadding>{roles.isLoading ? <PageLoading /> : roles.error ? <Box sx={{ p: 2 }}><ErrorAlert error={roles.error} /></Box> : !roles.data?.items.length ? <EmptyState title="Role이 없습니다" /> : <TableContainer><Table><TableHead><TableRow><TableCell>Role</TableCell><TableCell>설명</TableCell><TableCell>생성일</TableCell></TableRow></TableHead><TableBody>{roles.data.items.map((role) => <TableRow hover key={role.id} onClick={() => { setSelected(role); setEditDescription(role.description) }} sx={{ cursor: 'pointer' }}><TableCell><Typography fontWeight={680} className="mono">{role.name}</Typography></TableCell><TableCell>{role.description || '—'}</TableCell><TableCell>{formatDate(role.created_at)}</TableCell></TableRow>)}</TableBody></Table></TableContainer>}</ContentCard><Dialog open={open} onClose={() => setOpen(false)} maxWidth="sm"><Stack component="form" onSubmit={(e: FormEvent) => { e.preventDefault(); create.mutate() }}><DialogTitle>Role 만들기</DialogTitle><DialogContent><Stack spacing={2} sx={{ pt: 1 }}>{create.error && <ErrorAlert error={create.error} />}<TextField label="Role 이름" required value={name} onChange={(e) => setName(e.target.value)} /><TextField label="설명" multiline minRows={3} value={description} onChange={(e) => setDescription(e.target.value)} /></Stack></DialogContent><DialogActions><Button onClick={() => setOpen(false)}>취소</Button><Button type="submit" variant="contained" disabled={!name || create.isPending}>만들기</Button></DialogActions></Stack></Dialog><Dialog open={Boolean(selected)} onClose={() => setSelected(null)} maxWidth="sm"><DialogTitle>Role 관리 · {selected?.name}</DialogTitle><DialogContent><Stack spacing={2} sx={{ pt: 1 }}>{update.error && <ErrorAlert error={update.error} />}{remove.error && <ErrorAlert error={remove.error} />}<TextField label="Role 이름" value={selected?.name ?? ''} disabled /><TextField label="설명" multiline minRows={3} value={editDescription} onChange={(e) => setEditDescription(e.target.value)} />{['user', 'realm-admin', 'offline_access'].includes(selected?.name ?? '') && <Typography variant="body2" color="text.secondary">기본 Role은 삭제할 수 없습니다.</Typography>}</Stack></DialogContent><DialogActions><Button color="error" onClick={() => remove.mutate()} disabled={remove.isPending || ['user', 'realm-admin', 'offline_access'].includes(selected?.name ?? '')}>삭제</Button><Box sx={{ flex: 1 }} /><Button onClick={() => setSelected(null)}>닫기</Button><Button variant="contained" onClick={() => update.mutate()} disabled={update.isPending}>저장</Button></DialogActions></Dialog></>
}
