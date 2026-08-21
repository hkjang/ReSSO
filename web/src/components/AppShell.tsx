import { useEffect, useMemo, useState } from 'react'
import { Link as RouterLink, Outlet, useLocation, useNavigate } from 'react-router-dom'
import AccountCircleRoundedIcon from '@mui/icons-material/AccountCircleRounded'
import AdminPanelSettingsRoundedIcon from '@mui/icons-material/AdminPanelSettingsRounded'
import ApprovalRoundedIcon from '@mui/icons-material/ApprovalRounded'
import ArticleRoundedIcon from '@mui/icons-material/ArticleRounded'
import BadgeRoundedIcon from '@mui/icons-material/BadgeRounded'
import DashboardRoundedIcon from '@mui/icons-material/DashboardRounded'
import DnsRoundedIcon from '@mui/icons-material/DnsRounded'
import GroupsRoundedIcon from '@mui/icons-material/GroupsRounded'
import KeyRoundedIcon from '@mui/icons-material/KeyRounded'
import KeyboardCommandKeyRoundedIcon from '@mui/icons-material/KeyboardCommandKeyRounded'
import LanRoundedIcon from '@mui/icons-material/LanRounded'
import LogoutRoundedIcon from '@mui/icons-material/LogoutRounded'
import MenuRoundedIcon from '@mui/icons-material/MenuRounded'
import PolicyRoundedIcon from '@mui/icons-material/PolicyRounded'
import SearchRoundedIcon from '@mui/icons-material/SearchRounded'
import SecurityRoundedIcon from '@mui/icons-material/SecurityRounded'
import SettingsRoundedIcon from '@mui/icons-material/SettingsRounded'
import VpnKeyRoundedIcon from '@mui/icons-material/VpnKeyRounded'
import { Avatar, Box, Button, Chip, Dialog, DialogContent, Divider, Drawer, IconButton, InputAdornment, List, ListItemButton, ListItemIcon, ListItemText, Menu, MenuItem, Stack, TextField, Tooltip, Typography, useMediaQuery } from '@mui/material'
import { useQuery } from '@tanstack/react-query'
import { useTheme } from '@mui/material/styles'
import { api } from '../lib/api'
import { useAuth } from '../lib/auth'
import type { Realm } from '../types'

const drawerWidth = 264

interface NavItem { label: string; path: string; icon: typeof DashboardRoundedIcon; keywords?: string }

const adminItems: NavItem[] = [
  { label: '대시보드', path: '/admin', icon: DashboardRoundedIcon, keywords: '현황 홈' },
  { label: 'Realm', path: '/admin/realms', icon: DnsRoundedIcon, keywords: '테넌트 영역' },
  { label: '사용자', path: '/admin/users', icon: GroupsRoundedIcon, keywords: '계정 조직' },
  { label: 'User Federation', path: '/admin/user-federation', icon: LanRoundedIcon, keywords: 'LDAP AD 디렉터리 페더레이션' },
  { label: 'Client', path: '/admin/clients', icon: VpnKeyRoundedIcon, keywords: 'OIDC OAuth 애플리케이션' },
  { label: 'Role', path: '/admin/roles', icon: BadgeRoundedIcon, keywords: '권한 RBAC' },
  { label: '세션', path: '/admin/sessions', icon: SecurityRoundedIcon, keywords: '로그인 강제 로그아웃' },
  { label: '서명 키', path: '/admin/keys', icon: KeyRoundedIcon, keywords: 'JWKS rotation' },
  { label: '승인함', path: '/admin/approvals', icon: ApprovalRoundedIcon, keywords: '검토 승인 반려' },
  { label: '감사 이벤트', path: '/admin/audit', icon: PolicyRoundedIcon, keywords: '보안 audit' },
  { label: '서버 로그', path: '/admin/logs', icon: ArticleRoundedIcon, keywords: '운영 오류 trace' },
  { label: 'API · MCP', path: '/admin/integrations', icon: SettingsRoundedIcon, keywords: 'OpenAPI 도구 연동' },
]

const personalItems: NavItem[] = [
  { label: '내 프로필', path: '/personal', icon: AccountCircleRoundedIcon, keywords: '개인 정보' },
  { label: '로그인 보안', path: '/personal/security', icon: SecurityRoundedIcon, keywords: '비밀번호' },
  { label: '개인 API 키', path: '/personal/api-keys', icon: KeyRoundedIcon, keywords: 'MCP token 회전' },
  { label: '내 세션', path: '/personal/sessions', icon: DnsRoundedIcon, keywords: '접속 기기 로그아웃' },
  { label: '내 요청', path: '/personal/requests', icon: ApprovalRoundedIcon, keywords: '팀장 승인 역할' },
]

export function AppShell() {
  const { me, meta, logout } = useAuth()
  const location = useLocation()
  const navigate = useNavigate()
  const theme = useTheme()
  const desktop = useMediaQuery(theme.breakpoints.up('lg'))
  const [mobileOpen, setMobileOpen] = useState(false)
  const [profileAnchor, setProfileAnchor] = useState<HTMLElement | null>(null)
  const [paletteOpen, setPaletteOpen] = useState(false)
  const isAdmin = location.pathname.startsWith('/admin')
  const realms = useQuery({
    queryKey: ['realms'],
    queryFn: () => api<{ items: Realm[] }>('/api/admin/v1/realms'),
    enabled: Boolean(me?.permissions.admin),
    staleTime: 30_000,
  })
  const approvalEnabled = realms.data?.items.some((realm) => realm.approval_enabled) ?? false
  const capability = useQuery({
    queryKey: ['approval-capability'],
    queryFn: () => api<{ enabled: boolean }>('/api/v1/me/approval-capability'),
    enabled: Boolean(me),
    staleTime: 30_000,
  })
  const navItems = useMemo(() => {
    if (isAdmin) return adminItems.filter((item) => {
      if (item.path === '/admin/logs' && !me?.permissions.platform_admin) return false
      return item.path !== '/admin/approvals' || approvalEnabled
    })
    return personalItems.filter((item) => item.path !== '/personal/requests' || capability.data?.enabled)
  }, [isAdmin, approvalEnabled, capability.data?.enabled, me?.permissions.platform_admin])
  useEffect(() => {
    const keydown = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault()
        setPaletteOpen(true)
      }
    }
    window.addEventListener('keydown', keydown)
    return () => window.removeEventListener('keydown', keydown)
  }, [])

  const switchContext = () => navigate(isAdmin ? '/personal' : '/admin')
  const drawer = (
    <Stack sx={{ width: drawerWidth, height: '100%', bgcolor: '#101828', color: '#d0d5dd', overflow: 'hidden' }}>
      <Stack direction="row" alignItems="center" spacing={1.2} sx={{ px: 2.5, height: 68, flex: '0 0 auto' }}>
        <Box sx={{ width: 34, height: 34, borderRadius: 1.4, bgcolor: '#2f6fed', color: '#fff', display: 'grid', placeItems: 'center', fontWeight: 850 }}>R</Box>
        <Box><Typography color="#fff" fontWeight={800} lineHeight={1.15}>ReSSO</Typography><Typography variant="caption" color="#98a2b3">Identity control plane</Typography></Box>
      </Stack>
      <Box sx={{ px: 1.5, pb: 1.5 }}>
        <Button fullWidth variant="outlined" startIcon={isAdmin ? <AdminPanelSettingsRoundedIcon /> : <AccountCircleRoundedIcon />} onClick={switchContext}
          sx={{ justifyContent: 'flex-start', color: '#e4e7ec', borderColor: '#344054', bgcolor: '#1d2939', '&:hover': { bgcolor: '#344054', borderColor: '#475467' } }}>
          {isAdmin ? '서비스 관리' : '개인 설정'}
        </Button>
      </Box>
      <Divider sx={{ borderColor: '#263244' }} />
      <List component="nav" aria-label={isAdmin ? '서비스 관리 메뉴' : '개인 설정 메뉴'} sx={{ flex: '1 1 auto', minHeight: 0, overflowY: 'auto', overscrollBehavior: 'contain', px: 1.25, py: 1.5 }}>
        {navItems.map((item) => {
          const selected = item.path === '/admin' || item.path === '/personal' ? location.pathname === item.path : location.pathname.startsWith(item.path)
          const Icon = item.icon
          return (
            <ListItemButton key={item.path} component={RouterLink} to={item.path} selected={selected} onClick={() => setMobileOpen(false)}
              sx={{ borderRadius: 1.2, mb: .4, color: '#d0d5dd', '& .MuiListItemIcon-root': { color: '#98a2b3' }, '&.Mui-selected': { bgcolor: '#253b68', color: '#fff', '& .MuiListItemIcon-root': { color: '#9fbaff' } }, '&.Mui-selected:hover': { bgcolor: '#2c477c' }, '&:hover': { bgcolor: '#1d2939' } }}>
              <ListItemIcon sx={{ minWidth: 38 }}><Icon fontSize="small" /></ListItemIcon>
              <ListItemText primary={item.label} primaryTypographyProps={{ fontSize: 14, fontWeight: selected ? 700 : 520 }} />
            </ListItemButton>
          )
        })}
      </List>
      <Box sx={{ p: 1.5, flex: '0 0 auto' }}>
        <Button fullWidth variant="text" startIcon={<KeyboardCommandKeyRoundedIcon />} onClick={() => setPaletteOpen(true)} sx={{ justifyContent: 'flex-start', color: '#98a2b3' }}>
          빠른 이동 <Chip label="Ctrl K" size="small" sx={{ ml: 'auto', height: 22, bgcolor: '#344054', color: '#d0d5dd' }} />
        </Button>
      </Box>
    </Stack>
  )

  return (
    <Box sx={{ display: 'flex', minHeight: '100vh' }}>
      {desktop ? <Box component="aside" sx={{ position: 'fixed', inset: '0 auto 0 0', zIndex: 1200 }}>{drawer}</Box> : <Drawer open={mobileOpen} onClose={() => setMobileOpen(false)} ModalProps={{ keepMounted: true }}>{drawer}</Drawer>}
      <Box sx={{ flex: 1, minWidth: 0, ml: { lg: `${drawerWidth}px` } }}>
        <Stack component="header" direction="row" alignItems="center" spacing={1.5} sx={{ height: 68, px: { xs: 2, md: 3 }, position: 'sticky', top: 0, zIndex: 1100, bgcolor: 'rgba(255,255,255,.94)', backdropFilter: 'blur(12px)', borderBottom: '1px solid', borderColor: 'divider' }}>
          {!desktop && <IconButton onClick={() => setMobileOpen(true)} aria-label="메뉴 열기"><MenuRoundedIcon /></IconButton>}
          <Button startIcon={<SearchRoundedIcon />} variant="outlined" onClick={() => setPaletteOpen(true)} sx={{ color: 'text.secondary', borderColor: 'divider', justifyContent: 'flex-start', width: { xs: 44, sm: 260 }, px: { xs: 1.2, sm: 1.5 } }}>
            <Box component="span" sx={{ display: { xs: 'none', sm: 'inline' } }}>빠른 이동 및 검색</Box>
          </Button>
          <Box sx={{ flex: 1 }} />
          <Tooltip title="프로필 메뉴"><IconButton onClick={(event) => setProfileAnchor(event.currentTarget)} aria-label="프로필 메뉴"><Avatar sx={{ width: 34, height: 34, bgcolor: 'primary.main', fontSize: 14 }}>{me?.user.display_name?.slice(0, 1) || me?.user.username.slice(0, 1).toUpperCase()}</Avatar></IconButton></Tooltip>
          <Menu anchorEl={profileAnchor} open={Boolean(profileAnchor)} onClose={() => setProfileAnchor(null)} slotProps={{ paper: { sx: { width: 270, mt: 1 } } }}>
            <Box sx={{ px: 2, py: 1.5 }}><Typography fontWeight={700}>{me?.user.display_name}</Typography><Typography variant="body2" color="text.secondary">{me?.user.email || (me?.user.username ? `@${me.user.username}` : '이메일 미등록')}</Typography></Box>
            <Divider />
            <MenuItem onClick={() => { setProfileAnchor(null); navigate('/personal') }}><ListItemIcon><AccountCircleRoundedIcon fontSize="small" /></ListItemIcon>개인 설정</MenuItem>
            {me?.permissions.admin && <MenuItem onClick={() => { setProfileAnchor(null); navigate('/admin') }}><ListItemIcon><AdminPanelSettingsRoundedIcon fontSize="small" /></ListItemIcon>서비스 관리</MenuItem>}
            <Divider />
            <Box sx={{ px: 2, py: 1.2 }}><Typography variant="caption" color="text.secondary">ReSSO {meta?.version}</Typography><Typography variant="caption" color="text.secondary" display="block" className="mono">{meta?.commit !== 'unknown' ? meta?.commit.slice(0, 12) : 'development build'}</Typography></Box>
            <Divider />
            <MenuItem onClick={() => void logout()} sx={{ color: 'error.main' }}><ListItemIcon><LogoutRoundedIcon color="error" fontSize="small" /></ListItemIcon>로그아웃</MenuItem>
          </Menu>
        </Stack>
        <Box component="main" sx={{ p: { xs: 2, sm: 3, xl: 4 }, maxWidth: 1680, mx: 'auto' }}><Outlet /></Box>
      </Box>
      <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} items={navItems} admin={Boolean(me?.permissions.admin)} />
    </Box>
  )
}

function CommandPalette({ open, onClose, items, admin }: { open: boolean; onClose: () => void; items: NavItem[]; admin: boolean }) {
  const [query, setQuery] = useState('')
  const navigate = useNavigate()
  useEffect(() => { if (!open) setQuery('') }, [open])
  const remote = useQuery({
    queryKey: ['quick-search', query],
    queryFn: () => api<{ items: Array<{ kind: string; id: string; label: string; description: string; path: string }> }>(`/api/admin/v1/quick-search?q=${encodeURIComponent(query)}`),
    enabled: open && admin && query.trim().length >= 2,
    staleTime: 10_000,
  })
  const filtered = items.filter((item) => `${item.label} ${item.keywords ?? ''}`.toLowerCase().includes(query.toLowerCase()))
  const go = (path: string) => { onClose(); navigate(path) }
  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth PaperProps={{ sx: { position: 'fixed', top: { xs: 8, sm: 72 }, m: 1, maxHeight: 'min(680px, calc(100vh - 32px))' } }}>
      <TextField autoFocus placeholder="메뉴, 사용자, Client 검색…" value={query} onChange={(e) => setQuery(e.target.value)}
        InputProps={{ startAdornment: <InputAdornment position="start"><SearchRoundedIcon /></InputAdornment> }} sx={{ '& fieldset': { border: 0 }, px: 1, pt: 1 }} />
      <Divider />
      <DialogContent sx={{ p: 1, overflowY: 'auto' }}>
        <Typography variant="overline" color="text.secondary" sx={{ px: 1.5 }}>빠른 이동</Typography>
        <List dense>{filtered.map((item) => { const Icon = item.icon; return <ListItemButton key={item.path} onClick={() => go(item.path)} sx={{ borderRadius: 1 }}><ListItemIcon><Icon /></ListItemIcon><ListItemText primary={item.label} secondary={item.keywords} /></ListItemButton> })}</List>
        {remote.data?.items.length ? <><Divider sx={{ my: 1 }} /><Typography variant="overline" color="text.secondary" sx={{ px: 1.5 }}>검색 결과</Typography><List dense>{remote.data.items.map((item) => <ListItemButton key={`${item.kind}-${item.id}`} onClick={() => go(item.path)} sx={{ borderRadius: 1 }}><ListItemIcon><SearchRoundedIcon /></ListItemIcon><ListItemText primary={item.label} secondary={`${item.kind} · ${item.description}`} /></ListItemButton>)}</List></> : null}
      </DialogContent>
    </Dialog>
  )
}
