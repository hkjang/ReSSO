import { useState, type FormEvent, type ReactNode } from 'react'
import DeleteOutlineRoundedIcon from '@mui/icons-material/DeleteOutlineRounded'
import LanRoundedIcon from '@mui/icons-material/LanRounded'
import PlayArrowRoundedIcon from '@mui/icons-material/PlayArrowRounded'
import SyncRoundedIcon from '@mui/icons-material/SyncRounded'
import {
  Alert, Box, Button, Chip, Dialog, DialogActions, DialogContent, DialogTitle, Divider,
  FormControlLabel, Grid, MenuItem, Stack, Switch, Table, TableBody, TableCell, TableContainer,
  TableHead, TableRow, TextField, Typography,
} from '@mui/material'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ContentCard, PageHeader, StatusChip } from '../components/Page'
import { DetailDrawer } from '../components/DetailDrawer'
import { EmptyState, ErrorAlert, PageLoading } from '../components/Feedback'
import { RealmPicker } from '../components/RealmPicker'
import { api, jsonBody } from '../lib/api'
import { formatDate } from '../lib/format'
import { useRealms, useRealmSelection } from '../lib/realms'
import type { LDAPFederation } from '../types'

type FederationForm = {
  name: string
  vendor: 'OTHER' | 'AD'
  priority: number
  enabled: boolean
  connection_url: string
  start_tls: boolean
  ca_certificate: string
  bind_dn: string
  bind_credential: string
  clear_bind_credential: boolean
  users_dn: string
  username_ldap_attribute: string
  rdn_ldap_attribute: string
  uuid_ldap_attribute: string
  user_object_classes: string
  user_ldap_filter: string
  search_scope: 'ONE_LEVEL' | 'SUBTREE'
  email_ldap_attribute: string
  first_name_ldap_attribute: string
  last_name_ldap_attribute: string
  display_name_ldap_attribute: string
  member_of_ldap_attribute: string
  group_role_mappings: string
  import_enabled: boolean
  sync_registrations: boolean
  missing_user_action: 'KEEP' | 'DISABLE'
  edit_mode: 'READ_ONLY' | 'WRITABLE' | 'UNSYNCED'
  batch_size: number
  sync_period_seconds: number
}

const presets: Record<'OTHER' | 'AD', FederationForm> = {
  OTHER: {
    name: 'Corporate LDAP', vendor: 'OTHER', priority: 0, enabled: true,
    connection_url: 'ldaps://ldap.company.local:636', start_tls: false, ca_certificate: '',
    bind_dn: 'cn=resso,ou=service,dc=company,dc=local', bind_credential: '', clear_bind_credential: false,
    users_dn: 'ou=people,dc=company,dc=local', username_ldap_attribute: 'uid', rdn_ldap_attribute: 'uid',
    uuid_ldap_attribute: 'entryUUID', user_object_classes: 'inetOrgPerson', user_ldap_filter: '', search_scope: 'SUBTREE',
    email_ldap_attribute: 'mail', first_name_ldap_attribute: 'givenName', last_name_ldap_attribute: 'sn',
    display_name_ldap_attribute: 'cn', member_of_ldap_attribute: 'memberOf', group_role_mappings: '',
    import_enabled: true, sync_registrations: true, missing_user_action: 'KEEP', edit_mode: 'READ_ONLY',
    batch_size: 500, sync_period_seconds: 0,
  },
  AD: {
    name: 'Corporate Active Directory', vendor: 'AD', priority: 0, enabled: true,
    connection_url: 'ldaps://ad.company.local:636', start_tls: false, ca_certificate: '',
    bind_dn: 'CN=ReSSO,OU=Service Accounts,DC=company,DC=local', bind_credential: '', clear_bind_credential: false,
    users_dn: 'OU=Users,DC=company,DC=local', username_ldap_attribute: 'sAMAccountName', rdn_ldap_attribute: 'cn',
    uuid_ldap_attribute: 'objectGUID', user_object_classes: 'person, organizationalPerson, user',
    user_ldap_filter: '(!(userAccountControl:1.2.840.113556.1.4.803:=2))', search_scope: 'SUBTREE',
    email_ldap_attribute: 'mail', first_name_ldap_attribute: 'givenName', last_name_ldap_attribute: 'sn',
    display_name_ldap_attribute: 'displayName', member_of_ldap_attribute: 'memberOf', group_role_mappings: '',
    import_enabled: true, sync_registrations: true, missing_user_action: 'KEEP', edit_mode: 'READ_ONLY',
    batch_size: 500, sync_period_seconds: 0,
  },
}

function toForm(item: LDAPFederation): FederationForm {
  return {
    name: item.name, vendor: item.vendor, priority: item.priority, enabled: item.enabled,
    connection_url: item.connection_url, start_tls: item.start_tls, ca_certificate: item.ca_certificate ?? '',
    bind_dn: item.bind_dn, bind_credential: '', clear_bind_credential: false, users_dn: item.users_dn,
    username_ldap_attribute: item.username_ldap_attribute, rdn_ldap_attribute: item.rdn_ldap_attribute,
    uuid_ldap_attribute: item.uuid_ldap_attribute,
    user_object_classes: item.user_object_classes.join(', '),
    user_ldap_filter: item.user_ldap_filter, search_scope: item.search_scope,
    email_ldap_attribute: item.email_ldap_attribute, first_name_ldap_attribute: item.first_name_ldap_attribute,
    last_name_ldap_attribute: item.last_name_ldap_attribute, display_name_ldap_attribute: item.display_name_ldap_attribute,
    member_of_ldap_attribute: item.member_of_ldap_attribute,
    group_role_mappings: Object.entries(item.group_role_mappings).map(([group, role]) => `${group} => ${role}`).join('\n'),
    import_enabled: item.import_enabled, sync_registrations: item.sync_registrations,
    missing_user_action: item.missing_user_action, edit_mode: item.edit_mode,
    batch_size: item.batch_size, sync_period_seconds: item.sync_period_seconds,
  }
}

function mappings(value: string): Record<string, string> {
  return Object.fromEntries(value.split('\n').map((line) => line.trim()).filter(Boolean).map((line) => {
    const separator = line.lastIndexOf('=>')
    return separator < 0 ? [line, ''] : [line.slice(0, separator).trim(), line.slice(separator + 2).trim()]
  }).filter(([, role]) => Boolean(role)))
}

function requestBody(form: FederationForm, editing: boolean) {
  const body: Record<string, unknown> = {
    ...form,
    user_object_classes: form.user_object_classes.split(/[\n,]/).map((value) => value.trim()).filter(Boolean),
    group_role_mappings: mappings(form.group_role_mappings),
  }
  if (editing && !form.bind_credential) delete body.bind_credential
  return body
}

export function UserFederationPage() {
  const queryClient = useQueryClient()
  const realms = useRealms()
  const selection = useRealmSelection(realms.data?.items)
  const [drawerOpen, setDrawerOpen] = useState(false)
  const [editing, setEditing] = useState<LDAPFederation | null>(null)
  const [form, setForm] = useState<FederationForm>({ ...presets.OTHER })
  const [deleteOpen, setDeleteOpen] = useState(false)
  const [unlinkUsers, setUnlinkUsers] = useState(false)
  const [testUsername, setTestUsername] = useState('')
  const [testPassword, setTestPassword] = useState('')
  const providers = useQuery({
    queryKey: ['ldap-federations', selection.realmID],
    queryFn: () => api<{ items: LDAPFederation[] }>(`/api/admin/v1/realms/${selection.realmID}/user-federations`),
    enabled: Boolean(selection.realmID),
  })
  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['ldap-federations', selection.realmID] })
  const save = useMutation({
    mutationFn: () => api<LDAPFederation>(editing
      ? `/api/admin/v1/realms/${selection.realmID}/user-federations/${editing.id}`
      : `/api/admin/v1/realms/${selection.realmID}/user-federations`, {
      method: editing ? 'PUT' : 'POST', ...jsonBody(requestBody(form, Boolean(editing))),
    }),
    onSuccess: async (saved) => { setEditing(saved); setForm(toForm(saved)); await invalidate() },
  })
  const testConnection = useMutation({
    mutationFn: () => api<{ connected: boolean; duration_ms: number }>(`/api/admin/v1/realms/${selection.realmID}/user-federations/${editing!.id}/test-connection`, { method: 'POST' }),
  })
  const sync = useMutation({
    mutationFn: () => api<{ read: number; added: number; updated: number; failed: number; disabled: number }>(`/api/admin/v1/realms/${selection.realmID}/user-federations/${editing!.id}/sync`, { method: 'POST' }),
    onSuccess: invalidate,
  })
  const testAuth = useMutation({
    mutationFn: () => api<{ authenticated: boolean; user: { username: string; dn: string; display_name: string } }>(`/api/admin/v1/realms/${selection.realmID}/user-federations/${editing!.id}/test-authentication`, { method: 'POST', ...jsonBody({ username: testUsername, password: testPassword }) }),
    onSettled: () => setTestPassword(''),
  })
  const remove = useMutation({
    mutationFn: () => api<void>(`/api/admin/v1/realms/${selection.realmID}/user-federations/${editing!.id}${unlinkUsers ? '?unlink_users=true' : ''}`, { method: 'DELETE' }),
    onSuccess: async () => { setDeleteOpen(false); setUnlinkUsers(false); setDrawerOpen(false); setEditing(null); await invalidate() },
  })
  const openCreate = () => { setEditing(null); setForm({ ...presets.OTHER }); setDrawerOpen(true) }
  const openEdit = (item: LDAPFederation) => { setEditing(item); setForm(toForm(item)); setDrawerOpen(true); setTestUsername(''); setTestPassword('') }
  const applyPreset = (vendor: 'OTHER' | 'AD') => setForm({ ...presets[vendor], name: form.name || presets[vendor].name, priority: form.priority, enabled: form.enabled })
  const canSave = Boolean(form.name.trim() && form.connection_url.trim() && form.users_dn.trim()
    && form.username_ldap_attribute.trim() && form.uuid_ldap_attribute.trim() && form.user_object_classes.trim()
    && (editing || !form.bind_dn || form.bind_credential))

  if (realms.isLoading) return <PageLoading />
  if (realms.error) return <ErrorAlert error={realms.error} />
  return <>
    <PageHeader title="User Federation" description="Realm 사용자 계정을 LDAP 또는 Active Directory와 연결하고 로그인·동기화 정책을 중앙 관리합니다."
      action={{ label: 'LDAP 공급자 추가', onClick: openCreate }} />
    <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.5} sx={{ mb: 2 }}>
      <RealmPicker realms={realms.data?.items ?? []} value={selection.realmID} onChange={selection.setRealmID} />
      <Alert severity="info" sx={{ flex: 1, py: 0 }}>낮은 우선순위 숫자의 공급자부터 로그인 사용자를 검색합니다. 운영 전 연결 및 인증 테스트를 실행하세요.</Alert>
    </Stack>
    <ContentCard noPadding>
      {providers.isLoading ? <PageLoading /> : providers.error ? <Box sx={{ p: 2 }}><ErrorAlert error={providers.error} /></Box>
        : !providers.data?.items.length ? <EmptyState title="LDAP 공급자가 없습니다" description="Active Directory 또는 표준 LDAP 연결을 추가하세요." />
          : <TableContainer sx={{ maxHeight: 'calc(100vh - 265px)' }}><Table stickyHeader aria-label="LDAP User Federation 목록"><TableHead><TableRow>
            <TableCell>공급자</TableCell><TableCell>연결</TableCell><TableCell>편집 모드</TableCell><TableCell>마지막 동기화</TableCell><TableCell>상태</TableCell>
          </TableRow></TableHead><TableBody>{providers.data.items.map((item) => <TableRow hover key={item.id} onClick={() => openEdit(item)} tabIndex={0}
            onKeyDown={(event) => { if (event.key === 'Enter') openEdit(item) }} sx={{ cursor: 'pointer' }}>
            <TableCell><Stack direction="row" spacing={1.2} alignItems="center"><LanRoundedIcon color="action" /><Box><Typography fontWeight={700}>{item.name}</Typography><Typography variant="caption" color="text.secondary">{item.vendor === 'AD' ? 'Active Directory' : 'LDAP'} · 우선순위 {item.priority}</Typography></Box></Stack></TableCell>
            <TableCell><Typography className="mono" variant="body2" sx={{ maxWidth: 360, overflow: 'hidden', textOverflow: 'ellipsis' }}>{item.connection_url}</Typography></TableCell>
            <TableCell><Chip size="small" variant="outlined" label={item.edit_mode} /></TableCell>
            <TableCell>{item.last_sync_at ? <><Typography variant="body2">{formatDate(item.last_sync_at)}</Typography><Typography variant="caption" color="text.secondary">추가 {item.last_sync_added} · 갱신 {item.last_sync_updated} · 실패 {item.last_sync_failed}</Typography></> : '실행 전'}</TableCell>
            <TableCell><StatusChip active={item.enabled && item.last_sync_status !== 'FAILURE'} activeLabel={item.last_sync_status === 'RUNNING' ? '동기화 중' : '활성'} inactiveLabel={!item.enabled ? '비활성' : '동기화 실패'} /></TableCell>
          </TableRow>)}</TableBody></Table></TableContainer>}
    </ContentCard>

    <DetailDrawer open={drawerOpen} onClose={() => setDrawerOpen(false)} width={760}
      title={editing ? editing.name : 'LDAP 공급자 추가'} subtitle={editing ? `${editing.vendor} · ${editing.connection_url}` : 'Keycloak 호환 LDAP User Federation 설정'}>
      <Box component="form" onSubmit={(event: FormEvent) => { event.preventDefault(); save.mutate() }}>
        <Stack spacing={3}>
          {save.error && <ErrorAlert error={save.error} />}{save.isSuccess && <Alert severity="success">설정을 저장했습니다.</Alert>}
          <Section title="기본 설정" description="공급자 식별과 로그인 검색 순서를 지정합니다.">
            <Grid container spacing={2}><Grid size={{ xs: 12, sm: 7 }}><TextField label="Console 표시 이름" required autoFocus={!editing} value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} inputProps={{ maxLength: 120 }} /></Grid>
              <Grid size={{ xs: 12, sm: 5 }}><TextField select label="Vendor" value={form.vendor} onChange={(e) => applyPreset(e.target.value as 'OTHER' | 'AD')}><MenuItem value="OTHER">Other / OpenLDAP</MenuItem><MenuItem value="AD">Active Directory</MenuItem></TextField></Grid>
              <Grid size={{ xs: 12, sm: 6 }}><TextField label="Priority" type="number" value={form.priority} onChange={(e) => setForm({ ...form, priority: Number(e.target.value) })} inputProps={{ min: 0, max: 1000 }} helperText="낮은 숫자를 먼저 조회합니다." /></Grid>
              <Grid size={{ xs: 12, sm: 6 }}><FormControlLabel control={<Switch checked={form.enabled} onChange={(e) => setForm({ ...form, enabled: e.target.checked })} />} label="공급자 활성" /></Grid></Grid>
          </Section>
          <Section title="연결 및 서비스 계정" description="운영 환경에서는 LDAPS 또는 StartTLS와 내부 CA 인증서를 사용하세요.">
            <Stack spacing={2}><TextField label="Connection URL" required value={form.connection_url} onChange={(e) => setForm({ ...form, connection_url: e.target.value })} placeholder="ldaps://ldap.company.local:636" className="mono" />
              <FormControlLabel control={<Switch checked={form.start_tls} onChange={(e) => setForm({ ...form, start_tls: e.target.checked })} disabled={form.connection_url.startsWith('ldaps://')} />} label="StartTLS 사용 (ldap:// 전용)" />
              <TextField label="Bind DN" value={form.bind_dn} onChange={(e) => setForm({ ...form, bind_dn: e.target.value })} placeholder="cn=resso,ou=service,dc=company,dc=local" />
              <TextField label={editing?.bind_credential_set ? 'Bind Credential (변경 시에만 입력)' : 'Bind Credential'} required={!editing && Boolean(form.bind_dn)} type="password" autoComplete="new-password" value={form.bind_credential} onChange={(e) => setForm({ ...form, bind_credential: e.target.value, clear_bind_credential: false })} helperText="저장 시 ENCRYPTION_KEY로 암호화되며 다시 표시되지 않습니다." />
              {editing?.bind_credential_set && <FormControlLabel control={<Switch checked={form.clear_bind_credential} onChange={(e) => setForm({ ...form, clear_bind_credential: e.target.checked, bind_credential: '' })} />} label="저장된 Bind Credential 제거" />}
              <TextField label="추가 CA 인증서 (PEM)" multiline minRows={3} maxRows={8} value={form.ca_certificate} onChange={(e) => setForm({ ...form, ca_certificate: e.target.value })} placeholder="-----BEGIN CERTIFICATE-----" />
            </Stack>
          </Section>
          <Section title="사용자 검색" description="Base DN, 객체 클래스와 추가 필터를 결합해 사용자를 조회합니다.">
            <Grid container spacing={2}><Grid size={12}><TextField label="Users DN" required value={form.users_dn} onChange={(e) => setForm({ ...form, users_dn: e.target.value })} /></Grid>
              <Grid size={{ xs: 12, sm: 4 }}><TextField label="Username attribute" required value={form.username_ldap_attribute} onChange={(e) => setForm({ ...form, username_ldap_attribute: e.target.value })} /></Grid>
              <Grid size={{ xs: 12, sm: 4 }}><TextField label="RDN attribute" required value={form.rdn_ldap_attribute} onChange={(e) => setForm({ ...form, rdn_ldap_attribute: e.target.value })} /></Grid>
              <Grid size={{ xs: 12, sm: 4 }}><TextField label="UUID attribute" required value={form.uuid_ldap_attribute} onChange={(e) => setForm({ ...form, uuid_ldap_attribute: e.target.value })} /></Grid>
              <Grid size={{ xs: 12, sm: 7 }}><TextField label="User object classes" required value={form.user_object_classes} onChange={(e) => setForm({ ...form, user_object_classes: e.target.value })} helperText="쉼표로 구분합니다." /></Grid>
              <Grid size={{ xs: 12, sm: 5 }}><TextField select label="Search scope" value={form.search_scope} onChange={(e) => setForm({ ...form, search_scope: e.target.value as FederationForm['search_scope'] })}><MenuItem value="SUBTREE">Subtree</MenuItem><MenuItem value="ONE_LEVEL">One level</MenuItem></TextField></Grid>
              <Grid size={12}><TextField label="User LDAP filter" value={form.user_ldap_filter} onChange={(e) => setForm({ ...form, user_ldap_filter: e.target.value })} placeholder="(department=IT)" helperText="RFC 4515 LDAP 필터 형식을 사용하며 로그인 아이디는 별도로 안전하게 결합됩니다." /></Grid></Grid>
          </Section>
          <Section title="속성 및 Role 매핑" description="LDAP 사용자 속성과 memberOf 그룹을 ReSSO 프로필·Realm Role에 매핑합니다.">
            <Grid container spacing={2}>{([
              ['Email', 'email_ldap_attribute'], ['First name', 'first_name_ldap_attribute'], ['Last name', 'last_name_ldap_attribute'],
              ['Display name', 'display_name_ldap_attribute'], ['Member of', 'member_of_ldap_attribute'],
            ] as const).map(([label, key]) => <Grid key={key} size={{ xs: 12, sm: 6 }}><TextField label={`${label} attribute`} value={form[key]} onChange={(e) => setForm({ ...form, [key]: e.target.value })} /></Grid>)}
              <Grid size={12}><TextField label="LDAP group → Realm Role" multiline minRows={3} maxRows={8} value={form.group_role_mappings} onChange={(e) => setForm({ ...form, group_role_mappings: e.target.value })} placeholder={'CN=Admins,OU=Groups,DC=company,DC=local => realm-admin\nDevelopers => developer'} helperText="한 줄에 ‘그룹 DN 또는 CN => 기존 Realm Role’을 입력합니다." /></Grid></Grid>
          </Section>
          <Section title="동기화 및 편집 정책" description="로그인 시 등록, 주기 동기화와 원본 디렉터리 변경 정책을 제어합니다.">
            <Grid container spacing={2}><Grid size={{ xs: 12, sm: 6 }}><TextField select label="Edit mode" value={form.edit_mode} onChange={(e) => setForm({ ...form, edit_mode: e.target.value as FederationForm['edit_mode'] })}><MenuItem value="READ_ONLY">READ_ONLY</MenuItem><MenuItem value="WRITABLE">WRITABLE</MenuItem><MenuItem value="UNSYNCED">UNSYNCED</MenuItem></TextField></Grid>
              <Grid size={{ xs: 12, sm: 6 }}><TextField select label="동기화에서 사라진 사용자" value={form.missing_user_action} onChange={(e) => setForm({ ...form, missing_user_action: e.target.value as FederationForm['missing_user_action'] })}><MenuItem value="KEEP">유지</MenuItem><MenuItem value="DISABLE">비활성화 및 세션 종료</MenuItem></TextField></Grid>
              <Grid size={{ xs: 12, sm: 6 }}><TextField label="Batch size" type="number" value={form.batch_size} onChange={(e) => setForm({ ...form, batch_size: Number(e.target.value) })} inputProps={{ min: 50, max: 5000 }} /></Grid>
              <Grid size={{ xs: 12, sm: 6 }}><TextField label="자동 동기화 주기(초)" type="number" value={form.sync_period_seconds} onChange={(e) => setForm({ ...form, sync_period_seconds: Number(e.target.value) })} inputProps={{ min: 0, step: 300 }} disabled={!form.import_enabled} helperText="0은 자동 동기화를 끕니다. 최소 300초." /></Grid>
              <Grid size={{ xs: 12, sm: 6 }}><FormControlLabel control={<Switch checked={form.import_enabled} onChange={(e) => setForm({ ...form, import_enabled: e.target.checked, sync_period_seconds: e.target.checked ? form.sync_period_seconds : 0 })} />} label="전체/주기 사용자 가져오기" /></Grid>
              <Grid size={{ xs: 12, sm: 6 }}><FormControlLabel control={<Switch checked={form.sync_registrations} onChange={(e) => setForm({ ...form, sync_registrations: e.target.checked })} />} label="첫 로그인 시 사용자 등록" /></Grid></Grid>
          </Section>
          <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1} justifyContent="flex-end"><Button type="submit" variant="contained" disabled={save.isPending || !canSave}>{editing ? '설정 저장' : '공급자 생성'}</Button></Stack>

          {editing && <><Divider /><Section title="연결 검증 및 동기화" description="저장된 설정으로 실제 LDAP 서버에 연결합니다. 인증 테스트 비밀번호는 저장하거나 감사로그에 기록하지 않습니다.">
            <Stack spacing={2}>
              {testConnection.error && <ErrorAlert error={testConnection.error} />}{testConnection.data && <Alert severity="success">LDAP 연결 성공 · {testConnection.data.duration_ms}ms</Alert>}
              {sync.error && <ErrorAlert error={sync.error} />}{sync.data && <Alert severity="success">사용자 {sync.data.read}명 조회 · 추가 {sync.data.added} · 갱신 {sync.data.updated} · 비활성 {sync.data.disabled}</Alert>}
              <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1}><Button startIcon={<PlayArrowRoundedIcon />} variant="outlined" onClick={() => testConnection.mutate()} disabled={testConnection.isPending}>연결 테스트</Button><Button startIcon={<SyncRoundedIcon />} variant="outlined" onClick={() => sync.mutate()} disabled={sync.isPending || !editing.import_enabled}>전체 사용자 동기화</Button></Stack>
              {editing.last_sync_error && <Alert severity="warning">최근 동기화 오류: {editing.last_sync_error}</Alert>}
              <Divider /><Typography variant="h3">사용자 인증 테스트</Typography>
              {testAuth.error && <ErrorAlert error={testAuth.error} />}{testAuth.data && <Alert severity="success">{testAuth.data.user.display_name} ({testAuth.data.user.username}) 인증 성공</Alert>}
              <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1}><TextField label="LDAP 사용자 아이디" value={testUsername} onChange={(e) => setTestUsername(e.target.value)} autoComplete="off" /><TextField label="LDAP 비밀번호" type="password" value={testPassword} onChange={(e) => setTestPassword(e.target.value)} autoComplete="new-password" /><Button variant="outlined" onClick={() => testAuth.mutate()} disabled={testAuth.isPending || !testUsername.trim() || !testPassword} sx={{ whiteSpace: 'nowrap' }}>인증 테스트</Button></Stack>
            </Stack>
          </Section><Divider /><Box><Button color="error" startIcon={<DeleteOutlineRoundedIcon />} onClick={() => { setUnlinkUsers(false); setDeleteOpen(true) }}>공급자 삭제</Button><Typography variant="caption" color="text.secondary" display="block" sx={{ mt: .5 }}>연결된 사용자가 있으면 안전을 위해 삭제가 거부됩니다.</Typography></Box></>}
        </Stack>
      </Box>
    </DetailDrawer>
    <Dialog open={deleteOpen} onClose={() => { setDeleteOpen(false); setUnlinkUsers(false) }} maxWidth="xs"><DialogTitle>LDAP 공급자를 삭제할까요?</DialogTitle><DialogContent><Typography color="text.secondary">이 작업은 되돌릴 수 없습니다. 기본적으로 연결 사용자가 있으면 삭제가 거부됩니다.</Typography><FormControlLabel sx={{ mt: 2 }} control={<Switch checked={unlinkUsers} onChange={(e) => setUnlinkUsers(e.target.checked)} />} label="연결 사용자를 비활성화하고 세션 종료 후 연결 해제" />{unlinkUsers && <Alert severity="warning" sx={{ mt: 1 }}>사용자는 비활성 Local 계정으로 남습니다. 다시 사용하려면 관리자가 비밀번호를 재설정하고 활성화해야 합니다.</Alert>}{remove.error && <Box sx={{ mt: 2 }}><ErrorAlert error={remove.error} /></Box>}</DialogContent><DialogActions><Button onClick={() => { setDeleteOpen(false); setUnlinkUsers(false) }}>취소</Button><Button color="error" variant="contained" onClick={() => remove.mutate()} disabled={remove.isPending}>삭제</Button></DialogActions></Dialog>
  </>
}

function Section({ title, description, children }: { title: string; description: string; children: ReactNode }) {
  return <Box><Typography variant="h3">{title}</Typography><Typography variant="body2" color="text.secondary" sx={{ mt: .5, mb: 2 }}>{description}</Typography>{children}</Box>
}
