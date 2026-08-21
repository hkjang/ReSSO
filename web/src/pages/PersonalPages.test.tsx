import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { expect, test, vi } from 'vitest'
import { PersonalSecurityPage, ProfilePage } from './PersonalPages'

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
