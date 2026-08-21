import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import { expect, test, vi } from 'vitest'
import { ProfilePage } from './PersonalPages'

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
  },
  refresh: vi.fn(),
}))

vi.mock('../lib/auth', () => ({ useAuth: () => auth }))

test('profile treats a legacy mixed-case email as unchanged', () => {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  render(<QueryClientProvider client={queryClient}><ProfilePage /></QueryClientProvider>)

  expect(screen.getByDisplayValue('Alice@Example.COM')).toBeInTheDocument()
  expect(screen.getByText('이메일 확인됨')).toBeInTheDocument()
  expect(screen.getByText('이메일 변경 시 확인 상태가 해제됩니다.')).toBeInTheDocument()
})
