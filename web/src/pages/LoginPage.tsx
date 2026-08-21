import { useEffect, useMemo, useState, type FormEvent } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import ArrowForwardRoundedIcon from '@mui/icons-material/ArrowForwardRounded'
import LockRoundedIcon from '@mui/icons-material/LockRounded'
import VisibilityOffRoundedIcon from '@mui/icons-material/VisibilityOffRounded'
import VisibilityRoundedIcon from '@mui/icons-material/VisibilityRounded'
import { Alert, Box, Button, CircularProgress, IconButton, InputAdornment, Link, Paper, Stack, TextField, Typography } from '@mui/material'
import { useMutation, useQuery } from '@tanstack/react-query'
import { api, APIError, jsonBody } from '../lib/api'
import { useAuth } from '../lib/auth-context'

function formatWait(seconds: number): string {
  if (seconds >= 60) {
    const minutes = Math.ceil(seconds / 60)
    return `약 ${minutes}분`
  }
  return `${seconds}초`
}

interface Challenge {
  realm: { name: string; display_name: string }
  client: { client_id: string; name: string }
  expires_at: string
}

export function LoginPage() {
  const location = useLocation()
  const navigate = useNavigate()
  const { meta, refresh } = useAuth()
  const requestToken = useMemo(() => new URLSearchParams(location.search).get('request') ?? '', [location.search])
  const loggedOut = new URLSearchParams(location.search).get('logged_out') === '1'
  const [realmInput, setRealmInput] = useState('master')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  // Repeated failures are counted in the browser so the page can explain the
  // lockout policy without the server having to disclose whether an account
  // exists or is currently locked.
  const [failures, setFailures] = useState(0)
  const [waitSeconds, setWaitSeconds] = useState(0)
  const challenge = useQuery({
    queryKey: ['auth-challenge', requestToken],
    queryFn: () => api<Challenge>(`/api/v1/auth/challenge/${encodeURIComponent(requestToken)}`),
    enabled: Boolean(requestToken),
    retry: false,
  })
  // An authorization request fixes the Realm, so it is derived from the
  // challenge rather than copied into state by an effect.
  const realm = challenge.data?.realm.name ?? realmInput
  const login = useMutation({
    mutationFn: () => api<{ authenticated: boolean; redirect_to: string }>('/api/v1/auth/login', {
      method: 'POST',
      ...jsonBody({ realm, username, password, request: requestToken }),
    }),
    onSuccess: async (result) => {
      setFailures(0)
      if (requestToken) {
        window.location.assign(result.redirect_to)
        return
      }
      await refresh()
      navigate('/', { replace: true })
    },
    onError: (error) => {
      setFailures((count) => count + 1)
      if (error instanceof APIError && error.status === 429) {
        setWaitSeconds(error.retryAfterSeconds ?? 60)
      }
    },
  })
  // Count the wait down so the user can see when to try again rather than
  // guessing, and keep the form disabled until it elapses. One timeout per
  // tick keeps the dependency a plain value.
  useEffect(() => {
    if (waitSeconds <= 0) return
    const timer = window.setTimeout(() => setWaitSeconds(waitSeconds - 1), 1000)
    return () => window.clearTimeout(timer)
  }, [waitSeconds])
  const submit = (event: FormEvent) => {
    event.preventDefault()
    if (username.trim() && password && waitSeconds === 0) login.mutate()
  }
  const rateLimited = waitSeconds > 0
  const errorMessage = login.error instanceof APIError ? login.error.message : login.error ? '로그인하지 못했습니다.' : ''
  const blocked = login.isPending || challenge.isError || rateLimited || !username.trim() || !password

  return (
    <Box sx={{ minHeight: '100vh', display: 'grid', gridTemplateColumns: { xs: '1fr', md: 'minmax(360px, 520px) 1fr' }, bgcolor: '#0b1220' }}>
      <Box sx={{ bgcolor: '#fff', display: 'flex', flexDirection: 'column', px: { xs: 3, sm: 7 }, py: { xs: 3, sm: 5 }, minHeight: '100vh' }}>
        <Stack direction="row" alignItems="center" spacing={1.2}>
          <Box sx={{ width: 36, height: 36, borderRadius: 1.5, bgcolor: 'primary.main', color: '#fff', display: 'grid', placeItems: 'center', fontWeight: 850 }}>R</Box>
          <Typography fontWeight={800} fontSize={21} letterSpacing="-.02em">ReSSO</Typography>
        </Stack>
        <Stack component="main" justifyContent="center" sx={{ flex: 1, width: '100%', maxWidth: 390, mx: 'auto', py: 5 }}>
          <LockRoundedIcon color="primary" sx={{ fontSize: 32, mb: 2 }} />
          <Typography variant="h1" component="h1">안전하게 로그인</Typography>
          <Typography color="text.secondary" sx={{ mt: 1, mb: 3 }}>
            {challenge.data ? `${challenge.data.client.name}에서 ${challenge.data.realm.display_name} 계정 인증을 요청했습니다.` : 'ReSSO 서비스 관리 및 개인 설정에 접속합니다.'}
          </Typography>
          {loggedOut && <Alert severity="success" sx={{ mb: 2 }}>안전하게 로그아웃되었습니다.</Alert>}
          {challenge.isError && <Alert severity="error" sx={{ mb: 2 }}>로그인 요청이 만료되었습니다. 연결한 서비스에서 다시 시작하세요.</Alert>}
          {errorMessage && !rateLimited && <Alert severity="error" sx={{ mb: 2 }}>{errorMessage}</Alert>}
          {rateLimited && (
            <Alert severity="warning" sx={{ mb: 2 }}>
              로그인 시도가 제한되었습니다. <strong>{formatWait(waitSeconds)}</strong> 후에 다시 시도할 수 있습니다.
            </Alert>
          )}
          {failures >= 3 && !rateLimited && (
            <Alert severity="info" sx={{ mb: 2 }}>
              여러 번 실패했습니다. 반복 실패하면 계정이 일정 시간 잠기며, 잠긴 동안에는 올바른 비밀번호로도 로그인할 수 없습니다.
              비밀번호가 확실하지 않으면 잠기기 전에 서비스 관리자에게 문의하세요.
            </Alert>
          )}
          <Box component="form" onSubmit={submit} noValidate>
            <Stack spacing={2}>
              {!requestToken && <TextField label="Realm" name="realm" value={realmInput} onChange={(e) => setRealmInput(e.target.value)} required autoComplete="organization" helperText="기본 관리 Realm은 master입니다." />}
              <TextField label="아이디" name="username" value={username} onChange={(e) => setUsername(e.target.value)} required autoFocus autoComplete="username" inputProps={{ maxLength: 128 }} />
              <TextField
                label="비밀번호" name="password" type={showPassword ? 'text' : 'password'} value={password}
                onChange={(e) => setPassword(e.target.value)} required autoComplete="current-password"
                InputProps={{ endAdornment: <InputAdornment position="end"><IconButton onClick={() => setShowPassword((value) => !value)} edge="end" aria-label={showPassword ? '비밀번호 숨기기' : '비밀번호 표시'}>{showPassword ? <VisibilityOffRoundedIcon /> : <VisibilityRoundedIcon />}</IconButton></InputAdornment> }}
              />
              <Button type="submit" variant="contained" size="large" endIcon={login.isPending ? <CircularProgress color="inherit" size={18} /> : <ArrowForwardRoundedIcon />} disabled={blocked}>
                {login.isPending ? '확인 중…' : rateLimited ? `${formatWait(waitSeconds)} 후 재시도` : '로그인'}
              </Button>
            </Stack>
          </Box>
          <Typography variant="caption" color="text.secondary" sx={{ mt: 3 }}>
            로그인 문제는 서비스 관리자에게 문의하세요. 반복 실패 시 계정이 일시 잠깁니다.
          </Typography>
        </Stack>
        <Stack direction="row" justifyContent="space-between" color="text.secondary">
          <Typography variant="caption">© 2026 ReSSO</Typography>
          <Typography variant="caption">{meta?.version ?? 'version loading…'}</Typography>
        </Stack>
      </Box>
      <Box sx={{ display: { xs: 'none', md: 'flex' }, position: 'relative', overflow: 'hidden', alignItems: 'center', justifyContent: 'center', p: 8,
        background: 'radial-gradient(circle at 25% 20%, rgba(47,111,237,.45), transparent 35%), radial-gradient(circle at 80% 75%, rgba(18,165,148,.3), transparent 30%), #0b1220' }}>
        <Paper elevation={0} sx={{ maxWidth: 620, p: 5, bgcolor: 'rgba(255,255,255,.08)', color: '#fff', border: '1px solid rgba(255,255,255,.12)', backdropFilter: 'blur(16px)' }}>
          <Typography variant="overline" sx={{ color: '#9fbaff', letterSpacing: '.15em', fontWeight: 700 }}>KEYCLOAK-COMPATIBLE OIDC</Typography>
          <Typography sx={{ fontSize: { md: 36, lg: 44 }, lineHeight: 1.15, fontWeight: 780, letterSpacing: '-.035em', mt: 1.5 }}>
            하나의 신뢰 지점에서<br />인증과 접근을 관리하세요.
          </Typography>
          <Typography sx={{ color: '#cdd5e2', fontSize: 17, lineHeight: 1.7, mt: 3 }}>
            Authorization Code + PKCE, SSO 세션, 키 회전과 감사 추적을 오프라인 환경에서 일관되게 운영합니다.
          </Typography>
          <Link href="/realms/master/.well-known/openid-configuration" color="#a9c1ff" underline="hover" sx={{ display: 'inline-block', mt: 3 }}>OIDC Discovery 확인 →</Link>
        </Paper>
      </Box>
    </Box>
  )
}
