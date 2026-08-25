import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { beforeEach, expect, test, vi } from 'vitest'
import { RealmAPIKeysPage } from './RealmAPIKeysPage'

const mocks = vi.hoisted(() => ({ api: vi.fn() }))

vi.mock('../lib/realms', () => ({
  useRealms: () => ({ isLoading: false, error: null, data: { items: [{ id: 'realm-1', name: 'master', display_name: 'Master' }] } }),
  useRealmSelection: () => ({ realmID: 'realm-1', setRealmID: vi.fn() }),
}))

vi.mock('../lib/api', () => ({ api: (...args: unknown[]) => mocks.api(...args) }))

const key = (name: string, username: string) => ({
  id: `id-${name}`, name, prefix: 'resso_ab12', scopes: ['api:read'],
  created_at: '2026-08-01T00:00:00Z', expires_at: '2026-08-28T00:00:00Z',
  last_used_at: null, revoked_at: null, active: true,
  user_id: 'user-1', username,
})

beforeEach(() => {
  mocks.api.mockReset()
  mocks.api.mockImplementation((path: string) =>
    Promise.resolve({ items: String(path).includes('expiring=true')
      ? [key('mcp client', 'integrator')]
      : [key('mcp client', 'integrator'), key('nightly export', 'batch-runner')] }))
})

function renderAt(entry: string) {
  return render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
    <MemoryRouter initialEntries={[entry]}>
      <Routes><Route path="/admin/api-keys" element={<RealmAPIKeysPage />} /></Routes>
    </MemoryRouter>
  </QueryClientProvider>)
}

// The dashboard counts the keys expiring within the week and links here. It has
// to arrive narrowed to those keys, or the number it reported still cannot be
// checked against anything.
test('arriving from the dashboard asks for the expiring keys only', async () => {
  renderAt('/admin/api-keys?expiring=true')

  await vi.waitFor(() => {
    const asked = mocks.api.mock.calls.map(([path]) => String(path))
    expect(asked.some((path) => path.includes('/api-keys?expiring=true'))).toBe(true)
  })
  expect(await screen.findByText('mcp client')).toBeInTheDocument()
  expect(screen.queryByText('nightly export')).not.toBeInTheDocument()
})

// Whose key it is, which is the only thing that lets an administrator act on
// the number: the owner is who has to rotate it.
test('the listing says who holds each key', async () => {
  renderAt('/admin/api-keys')
  expect(await screen.findByText('integrator')).toBeInTheDocument()
  expect(screen.getByText('batch-runner')).toBeInTheDocument()
})

test('the filter can be cleared to see every key in the Realm', async () => {
  const user = userEvent.setup()
  renderAt('/admin/api-keys?expiring=true')
  expect(await screen.findByText('mcp client')).toBeInTheDocument()

  await user.click(screen.getByRole('button', { name: '전체' }))

  expect(await screen.findByText('nightly export')).toBeInTheDocument()
})

// The screen used to work the label out from the fields it had, and called a
// key stopped by a disabled account "만료" — which sends someone to renew a key
// that would not work if they did. The reason comes from the server, decided
// by the clock that wrote the timestamps.
test('a key stopped by a disabled account is not called expired', async () => {
  mocks.api.mockImplementation(() => Promise.resolve({ items: [{
    ...key('mcp client', 'integrator'), active: false, inactive_reason: 'account_disabled',
  }] }))
  renderAt('/admin/api-keys')

  expect(await screen.findByText('계정 비활성')).toBeInTheDocument()
  // 만료 is also a column header, so the chip is the second occurrence when it
  // is there at all; one occurrence means the header alone.
  expect(screen.getAllByText('만료')).toHaveLength(1)
})

test('a revoked key still says revoked and an expired one expired', async () => {
  mocks.api.mockImplementation(() => Promise.resolve({ items: [
    { ...key('a', 'x'), id: 'k1', active: false, inactive_reason: 'revoked' },
    { ...key('b', 'y'), id: 'k2', active: false, inactive_reason: 'expired' },
  ] }))
  renderAt('/admin/api-keys')

  expect(await screen.findByText('폐기')).toBeInTheDocument()
  expect(screen.getAllByText('만료')).toHaveLength(2)
})
