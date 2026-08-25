import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes, useNavigate } from 'react-router-dom'
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

const lockedUser = {
  ...legacyUser,
  id: '00000000-0000-0000-0000-000000000002',
  username: 'bob',
  display_name: 'Bob',
  email: '',
  email_verified: false,
  failed_attempts: 5,
  locked_until: '2099-01-01T00:00:00Z',
  // The server decides whether the lockout is in force; the console no longer
  // works it out from the timestamp, so a fixture has to say so.
  locked: true,
}

function renderUsers() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  return render(<QueryClientProvider client={queryClient}><MemoryRouter><UsersPage /></MemoryRouter></QueryClientProvider>)
}

test('a locked account can be released without resetting its password', async () => {
  const user = userEvent.setup()
  mocks.api.mockImplementation((path: string) => {
    if (path.includes('/unlock')) return Promise.resolve({ ...lockedUser, locked_until: undefined, locked: false, failed_attempts: 0 })
    if (path.includes('/role-mappings')) {
      return Promise.resolve({ available_realm_roles: [], available_client_roles: [], realm_role_ids: [], federation_realm_role_ids: [], client_role_ids: [] })
    }
    if (path.includes('/users')) return Promise.resolve({ items: [lockedUser], total: 1 })
    return Promise.resolve({ items: [] })
  })
  renderUsers()

  expect(await screen.findByText('잠김')).toBeInTheDocument()
  await user.click(await screen.findByRole('button', { name: /잠금 해제/ }))

  const unlockCall = mocks.api.mock.calls.find(([path]) => String(path).includes('/unlock'))
  expect(unlockCall).toBeDefined()
  expect(unlockCall?.[0]).toBe('/api/admin/v1/realms/realm-1/users/00000000-0000-0000-0000-000000000002/unlock')
  expect(unlockCall?.[1]).toMatchObject({ method: 'POST' })
  // Releasing a lockout must not touch the password endpoint.
  expect(mocks.api.mock.calls.some(([path]) => String(path).includes('/password'))).toBe(false)
})

// The filter is applied by the server, to the count as well as to the rows, so
// the pager counts what is shown and a locked account on a later page is still
// reachable. Narrowing only the page that had been fetched could not do that.
test('the status filter narrows the list to locked accounts', async () => {
  const user = userEvent.setup()
  mocks.api.mockImplementation((path: string) => {
    if (path.includes('/role-mappings')) {
      return Promise.resolve({ available_realm_roles: [], available_client_roles: [], realm_role_ids: [], federation_realm_role_ids: [], client_role_ids: [] })
    }
    if (path.includes('/users')) {
      return path.includes('status=locked')
        ? Promise.resolve({ items: [lockedUser], total: 1 })
        : Promise.resolve({ items: [legacyUser, lockedUser], total: 2 })
    }
    return Promise.resolve({ items: [] })
  })
  renderUsers()

  expect(await screen.findByText('Alice')).toBeInTheDocument()
  expect(screen.getByText('Bob')).toBeInTheDocument()

  await user.click(screen.getByRole('button', { name: '잠김' }))

  expect(await screen.findByText('Bob')).toBeInTheDocument()
  expect(screen.queryByText('Alice')).not.toBeInTheDocument()
  // The count the pager reports comes from the same narrowed query.
  expect(screen.getByText(/1-1 of 1|1–1 \/ 1|1–1 of 1/)).toBeInTheDocument()
})

test('saving refreshes the form from the record the server returns', async () => {
  const user = userEvent.setup()
  // The server normalizes the email. The drawer form derives from the selected
  // record including its version, so a save must show the normalized value
  // rather than leaving the text the administrator typed.
  const saved = {
    ...legacyUser,
    email: 'new@example.com',
    email_verified: false,
    updated_at: '2026-08-22T00:00:00Z',
  }
  mocks.api.mockImplementation((path: string, init?: { method?: string }) => {
    if (path.includes('/role-mappings')) {
      return Promise.resolve({ available_realm_roles: [], available_client_roles: [], realm_role_ids: [], federation_realm_role_ids: [], client_role_ids: [] })
    }
    if (init?.method === 'PUT') return Promise.resolve(saved)
    if (path.includes('/users')) return Promise.resolve({ items: [legacyUser], total: 1 })
    return Promise.resolve({ items: [] })
  })
  renderUsers()

  await user.click(await screen.findByText('Alice'))
  const email = await screen.findByDisplayValue('Alice@Example.COM')
  await user.clear(email)
  await user.type(email, 'NEW@Example.com')
  await user.click(screen.getByRole('button', { name: '변경 저장' }))

  expect(await screen.findByDisplayValue('new@example.com')).toBeInTheDocument()
})

// Ending the sessions can fail on its own after the password has already
// changed, which is why the server answers 200 with other_sessions_ended:false
// instead of 204. The screen announced "reset the password and ended the
// sessions" for both — and an administrator resetting an account they believe
// is compromised is the person who most needs to hear that they survived it.
test('a reset that could not end the sessions says so instead of claiming it did', async () => {
  const user = userEvent.setup()
  mocks.api.mockImplementation((path: string, init?: { method?: string }) => {
    if (path.includes('/password') && init?.method === 'PUT') {
      return Promise.resolve({ other_sessions_ended: false, message: '비밀번호는 재설정되었지만 이 계정의 세션을 종료하지 못했습니다.' })
    }
    if (path.includes('/role-mappings')) {
      return Promise.resolve({ available_realm_roles: [], available_client_roles: [], realm_role_ids: [], federation_realm_role_ids: [], client_role_ids: [] })
    }
    if (path.includes('/users')) return Promise.resolve({ items: [legacyUser], total: 1 })
    return Promise.resolve({ items: [] })
  })
  renderUsers()

  await user.click(await screen.findByText('Alice'))
  await user.type(await screen.findByLabelText('새 비밀번호'), 'a-new-password-1234')
  await user.click(screen.getByRole('button', { name: '재설정' }))

  expect(await screen.findByText('비밀번호는 재설정되었지만 이 계정의 세션을 종료하지 못했습니다.')).toBeInTheDocument()
  expect(screen.queryByText('비밀번호를 재설정하고 세션을 종료했습니다.')).not.toBeInTheDocument()
})

// The quick-search palette opens over whatever screen is showing, including
// this one, and hands the matched term over in the URL so the destination
// "opens on the match". Landing on a route the browser is already on does not
// remount anything, so a term read once at mount is read only for the first
// search — the second one leaves the field, the request and the address bar
// disagreeing with each other.
test('a second quick search applies its term to the list already open', async () => {
  const user = userEvent.setup()
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  function HandOver() {
    const navigate = useNavigate()
    return <button onClick={() => navigate('/admin/users?q=bob')}>hand over bob</button>
  }
  render(<QueryClientProvider client={queryClient}>
    <MemoryRouter initialEntries={['/admin/users?q=alice']}>
      <HandOver />
      <Routes><Route path="/admin/users" element={<UsersPage />} /></Routes>
    </MemoryRouter>
  </QueryClientProvider>)

  expect(await screen.findByDisplayValue('alice')).toBeInTheDocument()

  await user.click(screen.getByRole('button', { name: 'hand over bob' }))

  expect(await screen.findByDisplayValue('bob')).toBeInTheDocument()
  await vi.waitFor(() => {
    const asked = mocks.api.mock.calls.map(([path]) => String(path))
    expect(asked.some((path) => path.includes('/users?q=bob'))).toBe(true)
  })
})

// The dashboard reports how many accounts are locked and offers a link to see
// them. It has to arrive filtered, and the request has to carry the filter so
// the server narrows the count as well as the rows — otherwise the pager counts
// accounts the list is not showing and the promised number cannot be reached.
test('arriving from the dashboard asks the server for locked accounts only', async () => {
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
    <MemoryRouter initialEntries={['/admin/users?status=locked']}>
      <Routes><Route path="/admin/users" element={<UsersPage />} /></Routes>
    </MemoryRouter>
  </QueryClientProvider>)

  await vi.waitFor(() => {
    const asked = mocks.api.mock.calls.map(([path]) => String(path))
    expect(asked.some((path) => path.includes('/users?') && path.includes('status=locked'))).toBe(true)
  })
  expect(screen.getByRole('button', { name: '잠김' })).toHaveAttribute('aria-pressed', 'true')
})

// A link written by hand, or one left over from a version that named the filter
// differently, opens the list rather than an error.
test('a status the console does not know opens the unfiltered list', async () => {
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
    <MemoryRouter initialEntries={['/admin/users?status=on-fire']}>
      <Routes><Route path="/admin/users" element={<UsersPage />} /></Routes>
    </MemoryRouter>
  </QueryClientProvider>)

  await vi.waitFor(() => expect(mocks.api).toHaveBeenCalled())
  const asked = mocks.api.mock.calls.map(([path]) => String(path))
  expect(asked.every((path) => !path.includes('status='))).toBe(true)
  expect(await screen.findByText('Alice')).toBeInTheDocument()
})
