import { useState } from 'react'
import LogoutRoundedIcon from '@mui/icons-material/LogoutRounded'
import { Box, Button, Dialog, DialogActions, DialogContent, DialogTitle, IconButton, Stack, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Tooltip, Typography } from '@mui/material'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'
import { useRealms, useRealmSelection } from '../lib/realms'
import type { Session } from '../types'
import { formatDate, shortId } from '../lib/format'
import { RealmPicker } from '../components/RealmPicker'
import { ContentCard, PageHeader, StatusChip } from '../components/Page'
import { EmptyState, ErrorAlert, PageLoading } from '../components/Feedback'

export function SessionsPage() {
  const queryClient = useQueryClient()
  const realms = useRealms()
  const selection = useRealmSelection(realms.data?.items)
  const [target, setTarget] = useState<Session | null>(null)
  const sessions = useQuery({ queryKey: ['sessions', selection.realmID], queryFn: () => api<{ items: Session[] }>(`/api/admin/v1/realms/${selection.realmID}/sessions?limit=500`), enabled: Boolean(selection.realmID), refetchInterval: 20_000 })
  const revoke = useMutation({ mutationFn: () => api<void>(`/api/admin/v1/realms/${selection.realmID}/sessions/${target!.id}`, { method: 'DELETE' }), onSuccess: async () => { setTarget(null); await queryClient.invalidateQueries({ queryKey: ['sessions', selection.realmID] }) } })
  if (realms.isLoading) return <PageLoading />
  return <><PageHeader title="SSO 세션" description="사용자가 로그인한 브라우저와 활동 상태를 확인하고 강제로 종료합니다." /><Box sx={{ mb: 2 }}><RealmPicker realms={realms.data?.items ?? []} value={selection.realmID} onChange={selection.setRealmID} /></Box><ContentCard noPadding>{sessions.isLoading ? <PageLoading /> : sessions.error ? <Box sx={{ p: 2 }}><ErrorAlert error={sessions.error} /></Box> : !sessions.data?.items.length ? <EmptyState title="세션이 없습니다" /> : <TableContainer sx={{ maxHeight: 'calc(100vh - 245px)' }}><Table stickyHeader><TableHead><TableRow><TableCell>사용자</TableCell><TableCell>Session ID</TableCell><TableCell>IP</TableCell><TableCell>마지막 접근</TableCell><TableCell>만료</TableCell><TableCell>상태</TableCell><TableCell align="right">작업</TableCell></TableRow></TableHead><TableBody>{sessions.data.items.map((session) => { const active = !session.revoked_at && new Date(session.expires_at) > new Date(); return <TableRow key={session.id}><TableCell><Typography fontWeight={650}>{session.username}</Typography><Typography variant="caption" color="text.secondary" noWrap sx={{ maxWidth: 260, display: 'block' }}>{session.user_agent}</Typography></TableCell><TableCell className="mono">{shortId(session.id)}</TableCell><TableCell className="mono">{session.ip_address}</TableCell><TableCell>{formatDate(session.last_access)}</TableCell><TableCell>{formatDate(session.expires_at)}</TableCell><TableCell><StatusChip active={active} activeLabel="활성" inactiveLabel={session.revoked_at ? '종료' : '만료'} /></TableCell><TableCell align="right"><Tooltip title="강제 로그아웃"><span><IconButton disabled={!active} color="error" onClick={() => setTarget(session)}><LogoutRoundedIcon /></IconButton></span></Tooltip></TableCell></TableRow> })}</TableBody></Table></TableContainer>}</ContentCard><Dialog open={Boolean(target)} onClose={() => setTarget(null)} maxWidth="xs"><DialogTitle>세션을 종료할까요?</DialogTitle><DialogContent><Typography>{target?.username} 사용자의 이 SSO 세션과 연결된 Refresh Token을 즉시 폐기합니다.</Typography>{revoke.error && <Box sx={{ mt: 2 }}><ErrorAlert error={revoke.error} /></Box>}</DialogContent><DialogActions><Button onClick={() => setTarget(null)}>취소</Button><Button color="error" variant="contained" onClick={() => revoke.mutate()} disabled={revoke.isPending}>강제 로그아웃</Button></DialogActions></Dialog></>
}
