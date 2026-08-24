import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { expect, test, vi } from 'vitest'
import { APIKeysPage, PersonalSecurityPage, ProfilePage } from './PersonalPages'
import { ToastProvider } from '../components/Toast'

const auth = vi.hoisted(() => ({
  me: {
    user: {
      id: '00000000-0000-0000-0000-000000000001',
      realm_id: '00000000-0000-0000-0000-000000000002',
      username: 'alice',
      email: 'Alice@Example.COM',
      email_verified: true,
      display_name: 'Alice',
      enabled: true,
      platform_admin: false,
      failed_attempts: 0,
      password_changed_at: '2026-08-21T00:00:00Z',
      created_at: '2026-08-21T00:00:00Z',
      updated_at: '2026-08-21T00:00:00Z',
    },
    roles: [],
    csrf_token: 'test-csrf',
    permissions: { platform_admin: false, realm_admin: false, admin: false },
    password_policy: { min_length: 16, max_login_attempts: 4, lockout_seconds: 1800 },
  },
  refresh: vi.fn(),
}))

vi.mock('../lib/auth-context', () => ({ useAuth: () => auth }))

test('profile treats a legacy mixed-case email as unchanged', () => {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  render(<QueryClientProvider client={queryClient}><ProfilePage /></QueryClientProvider>)

  expect(screen.getByDisplayValue('Alice@Example.COM')).toBeInTheDocument()
  expect(screen.getByText('이메일 확인됨')).toBeInTheDocument()
  expect(screen.getByText('이메일 변경 시 확인 상태가 해제됩니다.')).toBeInTheDocument()
})


function renderSecurity() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  return render(<QueryClientProvider client={queryClient}><PersonalSecurityPage /></QueryClientProvider>)
}

test('the password form states the Realm policy instead of a hardcoded guess', () => {
  renderSecurity()
  // The Realm below requires 16 characters; the form used to allow submitting
  // at 8 and let the server reject it.
  expect(screen.getByText('16자 이상')).toBeInTheDocument()
  expect(screen.getByText(/4회 연속 실패하면 계정이 약 30분 동안 잠깁니다/)).toBeInTheDocument()
})

test('the submit button stays disabled until every Realm requirement is met', async () => {
  const user = userEvent.setup()
  renderSecurity()
  const submit = screen.getByRole('button', { name: '비밀번호 변경' })
  expect(submit).toBeDisabled()

  await user.type(screen.getByLabelText('현재 비밀번호 *', { selector: 'input' }), 'old-password-value')
  // Ten characters clears the old hardcoded minimum but not this Realm's.
  const next = screen.getByLabelText('새 비밀번호 *', { selector: 'input' })
  await user.type(next, '0123456789')
  await user.type(screen.getByLabelText('새 비밀번호 확인 *', { selector: 'input' }), '0123456789')
  expect(submit).toBeDisabled()

  await user.type(next, 'abcdef')
  await user.type(screen.getByLabelText('새 비밀번호 확인 *', { selector: 'input' }), 'abcdef')
  expect(submit).toBeEnabled()
})

// A rotation that fails used to change nothing and say nothing: the dialog
// carrying the new secret simply did not appear, which reads as a click that
// did not register. Every other mutation on the page shows its error.
test('a failed key rotation says so instead of appearing to do nothing', async () => {
  const key = {
    id: '00000000-0000-0000-0000-0000000000aa',
    name: 'agent',
    prefix: 'resso_ab',
    scopes: ['api:read'],
    active: true,
    created_at: '2026-08-21T00:00:00Z',
  }
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    if (url.endsWith('/rotate')) {
      return new Response(JSON.stringify({ error: 'conflict', message: '키를 회전하지 못했습니다.' }),
        { status: 409, headers: { 'Content-Type': 'application/json' } })
    }
    if (url.includes('/api/v1/me/api-keys')) {
      return new Response(JSON.stringify({ items: [key] }),
        { status: 200, headers: { 'Content-Type': 'application/json' } })
    }
    void init
    return new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } })
  })
  vi.stubGlobal('fetch', fetchMock)
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  render(
    <QueryClientProvider client={queryClient}>
      <ToastProvider>
        <APIKeysPage />
      </ToastProvider>
    </QueryClientProvider>,
  )
  const rotateButton = await screen.findByRole('button', { name: 'agent 키 회전' })
  await userEvent.click(rotateButton)
  expect(await screen.findByText('키를 회전하지 못했습니다.')).toBeTruthy()
  vi.unstubAllGlobals()
})
