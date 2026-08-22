import { useState } from 'react'
import AutorenewRoundedIcon from '@mui/icons-material/AutorenewRounded'
import { Alert, Box, Button, Chip, Dialog, DialogActions, DialogContent, DialogTitle, Stack, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Typography } from '@mui/material'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'
import { useRealms, useRealmSelection } from '../lib/realms'
import type { SigningKey } from '../types'
import { formatDate } from '../lib/format'
import { RealmPicker } from '../components/RealmPicker'
import { ContentCard, PageHeader } from '../components/Page'
import { EmptyState, ErrorAlert, PageLoading } from '../components/Feedback'

// Signing keys never rotate on their own, so the page has to say when one has
// aged. The threshold comes from the response rather than a copy kept here,
// because the dashboard counts aged keys with the server's number and two
// screens disagreeing about the same key is worse than either being silent.
const ADVISORY_FALLBACK = 180

function ageInDays(createdAt: string): number {
  return Math.floor((Date.now() - new Date(createdAt).getTime()) / 86_400_000)
}

function KeyAge({ createdAt, advisoryDays }: { createdAt: string; advisoryDays: number }) {
  const days = ageInDays(createdAt)
  return <Typography variant="body2" color={days > advisoryDays ? 'warning.main' : 'text.primary'}>{days.toLocaleString()}일</Typography>
}

export function KeysPage() {
  const queryClient = useQueryClient()
  const realms = useRealms()
  const selection = useRealmSelection(realms.data?.items)
  const [confirmOpen, setConfirmOpen] = useState(false)
  const keys = useQuery({ queryKey: ['signing-keys', selection.realmID], queryFn: () => api<{ items: SigningKey[]; advisory_days: number }>(`/api/admin/v1/realms/${selection.realmID}/keys`), enabled: Boolean(selection.realmID) })
  const rotate = useMutation({ mutationFn: () => api<SigningKey>(`/api/admin/v1/realms/${selection.realmID}/keys/rotate`, { method: 'POST' }), onSuccess: async () => { setConfirmOpen(false); await queryClient.invalidateQueries({ queryKey: ['signing-keys', selection.realmID] }) } })
  const advisoryDays = keys.data?.advisory_days ?? ADVISORY_FALLBACK
  const activeKey = keys.data?.items.find((key) => key.status === 'ACTIVE')
  const agingKey = activeKey ? ageInDays(activeKey.created_at) > advisoryDays : false
  if (realms.isLoading) return <PageLoading />
  return <><PageHeader title="서명 키" description="Realm JWT 서명 키를 회전합니다. 이전 공개키는 기존 Access Token 만료 동안 JWKS에 유지됩니다." action={{ label: '서명 키 회전', onClick: () => setConfirmOpen(true) }} /><Stack direction={{ xs: 'column', md: 'row' }} spacing={2} sx={{ mb: 2 }}><RealmPicker realms={realms.data?.items ?? []} value={selection.realmID} onChange={selection.setRealmID} /><Alert severity={agingKey ? 'warning' : 'info'} sx={{ flex: 1 }}>{agingKey
      ? <>이 Realm의 서명 키를 {advisoryDays}일 넘게 사용하고 있습니다. 회전을 검토하세요. 회전해도 이전 공개키는 기존 Token 검증을 위해 일정 시간 JWKS에 유지되므로 서비스는 중단되지 않습니다.</>
      : <>Private Key는 Data Encryption Keyring으로 AES-256-GCM 암호화되어 PostgreSQL에 저장됩니다. 서명 키는 자동으로 회전되지 않으므로 {advisoryDays}일을 기준으로 검토하세요.</>}</Alert></Stack><ContentCard noPadding>{keys.isLoading ? <PageLoading /> : keys.error ? <Box sx={{ p: 2 }}><ErrorAlert error={keys.error} onRetry={() => void keys.refetch()} /></Box> : !keys.data?.items.length ? <EmptyState title="서명 키가 없습니다" /> : <TableContainer><Table><TableHead><TableRow><TableCell>Key ID (kid)</TableCell><TableCell>Algorithm</TableCell><TableCell>상태</TableCell><TableCell>생성일</TableCell><TableCell align="right">사용 기간</TableCell><TableCell>이전 키 유지 시각</TableCell></TableRow></TableHead><TableBody>{keys.data.items.map((key) => <TableRow key={key.id}><TableCell className="mono">{key.kid}</TableCell><TableCell>{key.algorithm}</TableCell><TableCell><Chip size="small" label={key.status} color={key.status === 'ACTIVE' ? 'success' : 'default'} /></TableCell><TableCell>{formatDate(key.created_at)}</TableCell><TableCell align="right">{key.status === 'ACTIVE' ? <KeyAge createdAt={key.created_at} advisoryDays={advisoryDays} /> : '—'}</TableCell><TableCell>{formatDate(key.retire_at)}</TableCell></TableRow>)}</TableBody></Table></TableContainer>}</ContentCard><Dialog open={confirmOpen} onClose={() => setConfirmOpen(false)} maxWidth="xs"><DialogTitle>Signing Key 회전</DialogTitle><DialogContent><Typography>새 RS256 키를 ACTIVE로 전환하고 현재 키를 PASSIVE로 유지합니다. 발급 중인 요청은 중단되지 않습니다.</Typography>{rotate.error && <Box sx={{ mt: 2 }}><ErrorAlert error={rotate.error} /></Box>}</DialogContent><DialogActions><Button onClick={() => setConfirmOpen(false)}>취소</Button><Button variant="contained" startIcon={<AutorenewRoundedIcon />} onClick={() => rotate.mutate()} disabled={rotate.isPending}>회전 실행</Button></DialogActions></Dialog></>
}
