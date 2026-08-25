import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { expect, test, vi } from 'vitest'
import { SessionsPage } from './SessionsPage'
import { ToastProvider } from '../components/Toast'

const mocks = vi.hoisted(() => ({ api: vi.fn() }))

vi.mock('../lib/realms', () => ({
  useRealms: () => ({ isLoading: false, error: null, data: { items: [{ id: 'realm-1', name: 'master', display_name: 'Master' }] } }),
  useRealmSelection: () => ({ realmID: 'realm-1', setRealmID: vi.fn() }),
}))

vi.mock('../lib/api', () => ({
  api: (...args: unknown[]) => mocks.api(...args),
  jsonBody: (value: unknown) => ({ body: JSON.stringify(value) }),
}))

const session = {
  id: '00000000-0000-0000-0000-0000000000f1',
  realm_id: 'realm-1',
  user_id: '00000000-0000-0000-0000-0000000000a1',
  username: 'alice',
  ip_address: '127.0.0.1',
  user_agent: 'Mozilla/5.0',
  auth_method: 'password',
  created_at: '2026-08-24T00:00:00Z',
  last_access: '2026-08-24T00:00:00Z',
  expires_at: '2099-01-01T00:00:00Z',
  revoked_at: null,
  active: true,
}

function renderSessions() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <ToastProvider>
        <SessionsPage />
      </ToastProvider>
    </QueryClientProvider>,
  )
}

// The confirmation dialog promises this revokes the refresh tokens linked to
// the session, and that is exactly the half that can fail on its own once the
// session has ended. Closing the dialog quietly leaves the operator believing
// the promise was kept while a relying party holding one carries on.
test('a force logout that could not revoke the refresh tokens says so', async () => {
  const user = userEvent.setup()
  mocks.api.mockImplementation((path: string, init?: { method?: string }) => {
    if (init?.method === 'DELETE') {
      return Promise.resolve({
        session_ended: true,
        refresh_tokens_revoked: false,
        message: '세션은 종료했지만 이 세션의 Refresh Token을 폐기하지 못했습니다.',
      })
    }
    if (path.includes('/sessions')) return Promise.resolve({ items: [session] })
    return Promise.resolve({ items: [] })
  })
  renderSessions()

  await user.click(await screen.findByRole('button', { name: /세션 강제 로그아웃/ }))
  await user.click(await screen.findByRole('button', { name: '강제 로그아웃' }))

  expect(await screen.findByText('세션은 종료했지만 이 세션의 Refresh Token을 폐기하지 못했습니다.')).toBeInTheDocument()
})

// The screen exists to answer "which sessions does this person have open", and
// the listing is capped at 500. Narrowing the rows that came back answered that
// only for the most recently used ones: a session further down was reported as
// not existing. The term goes to the server so the cap limits what is shown,
// not what can be found.
test('the search goes to the server rather than filtering the page already fetched', async () => {
  const user = userEvent.setup()
  renderSessions()
  await waitFor(() => expect(mocks.api).toHaveBeenCalled())

  await user.type(screen.getByLabelText('세션 검색'), 'quiet-contractor')

  await waitFor(() => {
    const asked = mocks.api.mock.calls.map(([path]) => String(path))
    expect(asked.some((path) => path.includes('/sessions?') && path.includes('q=quiet-contractor'))).toBe(true)
  })
})

// A cut-off list that says nothing looks like the whole list.
test('a listing that hits the cap says so', async () => {
  mocks.api.mockResolvedValue({ items: Array.from({ length: 500 }, (_, index) => ({
    ...session, id: `00000000-0000-0000-0000-${String(index).padStart(12, '0')}`,
  })) })
  renderSessions()

  expect(await screen.findByText(/500건만 표시합니다/)).toBeInTheDocument()
})
