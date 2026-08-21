import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, expect, test, vi } from 'vitest'
import { UsersPage } from './UsersPage'

const mocks = vi.hoisted(() => ({ api: vi.fn() }))

vi.mock('../lib/realms', () => ({
  useRealms: () => ({ isLoading: false, error: null, data: { items: [{ id: 'realm-1', name: 'master', display_name: 'Master' }] } }),
  useRealmSelection: () => ({ realmID: 'realm-1', setRealmID: vi.fn() }),
}))

vi.mock('../lib/api', () => ({
  api: (...args: unknown[]) => mocks.api(...args),
  jsonBody: (value: unknown) => ({ body: JSON.stringify(value) }),
}))

const legacyUser = {
  id: '00000000-0000-0000-0000-000000000001',
  realm_id: 'realm-1',
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
}

beforeEach(() => {
  mocks.api.mockReset()
  mocks.api.mockImplementation((path: string) => {
    if (path.includes('/role-mappings')) {
      return Promise.resolve({ available_realm_roles: [], available_client_roles: [], realm_role_ids: [], federation_realm_role_ids: [], client_role_ids: [] })
    }
    if (path.includes('/users')) return Promise.resolve({ items: [legacyUser], total: 1 })
    return Promise.resolve({ items: [] })
  })
})

test('admin can verify unchanged mixed-case email and gets two-step guidance for a replacement', async () => {
  const user = userEvent.setup()
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  render(<QueryClientProvider client={queryClient}><MemoryRouter><UsersPage /></MemoryRouter></QueryClientProvider>)

  await user.click(await screen.findByText('Alice'))
  const email = await screen.findByDisplayValue('Alice@Example.COM')
  const verified = screen.getByRole('switch', { name: '관리자가 이메일을 확인함' })
  expect(verified).toBeEnabled()
  expect(verified).toBeChecked()

  await user.clear(email)
  await user.type(email, 'new@example.com')
  expect(verified).toBeDisabled()
  expect(screen.getByText('새 이메일을 먼저 저장한 뒤 관리자가 확인 상태로 변경할 수 있습니다.')).toBeInTheDocument()
})
