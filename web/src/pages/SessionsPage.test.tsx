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
test('a listing the server reports as cut says so', async () => {
  mocks.api.mockResolvedValue({ items: [session], truncated: true })
  renderSessions()

  expect(await screen.findByText(/500건만 표시합니다/)).toBeInTheDocument()
})

// Counting the rows here said "there is more" for a Realm holding exactly the
// limit. The server knows which it is, and a notice that cries wolf stops
// being read.
test('a listing that is complete says nothing about a cap', async () => {
  mocks.api.mockResolvedValue({ items: [session], truncated: false })
  renderSessions()

  expect(await screen.findByText(session.username)).toBeInTheDocument()
  expect(screen.queryByText(/500건만 표시합니다/)).not.toBeInTheDocument()
})

// The search moved to the server, and with it the rows that come back became
// the whole answer rather than a page to narrow. The screen kept a second empty
// state for "nothing matched" that nothing could reach any more, so a term that
// missed was reported as a Realm with no sessions at all — and an operator who
// believes that goes looking somewhere else entirely.
test('a search that matches nothing says so rather than that there are none', async () => {
  const user = userEvent.setup()
  mocks.api.mockImplementation((path: string) =>
    Promise.resolve({ items: String(path).includes('q=nobody') ? [] : [session], truncated: false }))
  renderSessions()
  expect(await screen.findByText(session.username)).toBeInTheDocument()

  await user.type(screen.getByLabelText('세션 검색'), 'nobody')

  expect(await screen.findByText('검색 조건에 맞는 세션이 없습니다')).toBeInTheDocument()
  expect(screen.queryByText('세션이 없습니다')).not.toBeInTheDocument()
})

const otherSession = { ...session, id: '00000000-0000-0000-0000-0000000000f2', username: 'bob' }
const expiredSession = { ...session, id: '00000000-0000-0000-0000-0000000000f3', username: 'carol', active: false, expires_at: '2020-01-01T00:00:00Z' }

function listing(items: unknown[]) {
  return (path: string, init?: { method?: string }) => {
    if (init?.method === 'DELETE') return Promise.resolve({ session_ended: true, refresh_tokens_revoked: true })
    if (path.includes('/sessions')) return Promise.resolve({ items, truncated: false })
    return Promise.resolve({ items: [] })
  }
}

// 침해된 계정의 세션을 하나씩 대화 상자로 끝내는 것이 원래 동작이었다. 급할 때
// 정확히 필요한 것이 여러 개를 한 번에 끝내는 일이다.
test('여러 세션을 골라 한 번에 종료한다', async () => {
  const user = userEvent.setup()
  mocks.api.mockImplementation(listing([session, otherSession]))
  renderSessions()
  await screen.findByText('alice')
  await user.click(screen.getByRole('checkbox', { name: 'alice 세션 선택' }))
  await user.click(screen.getByRole('checkbox', { name: 'bob 세션 선택' }))
  expect(screen.getByText('2개 선택됨')).toBeInTheDocument()
  // 이 파일의 앞선 테스트가 남긴 호출과 섞이지 않도록, 지금부터의 호출만 센다.
  const deletes = () => mocks.api.mock.calls.filter(([, init]) => (init as { method?: string } | undefined)?.method === 'DELETE')
  const before = deletes().length
  await user.click(screen.getByRole('button', { name: '선택한 세션 강제 로그아웃' }))
  await user.click(screen.getByRole('button', { name: '2개 강제 로그아웃' }))
  await waitFor(() => expect(deletes().length - before).toBe(2))
  expect(deletes().slice(before).map(([path]) => String(path).slice(-2)).sort()).toEqual(['f1', 'f2'])
})

// 열넷 중 셋이 살아남았는데 "완료"라고 말하면, 운영자는 끝나지 않은 세션을
// 끝난 것으로 믿고 화면을 떠난다.
test('일부만 실패하면 몇 개가 남았는지 말한다', async () => {
  const user = userEvent.setup()
  mocks.api.mockImplementation((path: string, init?: { method?: string }) => {
    if (init?.method === 'DELETE') {
      return path.includes('f2') ? Promise.reject(new Error('nope')) : Promise.resolve({ session_ended: true })
    }
    if (path.includes('/sessions')) return Promise.resolve({ items: [session, otherSession], truncated: false })
    return Promise.resolve({ items: [] })
  })
  renderSessions()
  await screen.findByText('alice')
  await user.click(screen.getByRole('checkbox', { name: '표시된 활성 세션 모두 선택' }))
  await user.click(screen.getByRole('button', { name: '선택한 세션 강제 로그아웃' }))
  await user.click(screen.getByRole('button', { name: '2개 강제 로그아웃' }))
  expect(await screen.findByText(/2건 중 1건이 실패/)).toBeInTheDocument()
})

// 이미 끝난 세션까지 고를 수 있으면 열넷을 골라 열하나만 끝나고, 나머지 셋은
// 실패로 보고된다 — 실제로는 끝낼 것이 없었는데도.
test('이미 끝난 세션은 고를 수 없고 전체 선택에도 들지 않는다', async () => {
  const user = userEvent.setup()
  mocks.api.mockImplementation(listing([session, expiredSession]))
  renderSessions()
  await screen.findByText('carol')
  expect(screen.getByRole('checkbox', { name: 'carol 세션 선택' })).toBeDisabled()
  await user.click(screen.getByRole('checkbox', { name: '표시된 활성 세션 모두 선택' }))
  expect(screen.getByText('1개 선택됨')).toBeInTheDocument()
})

// 확인 대화 상자는 무엇이 범위인지 글자로 말해야 한다. 전체 선택이 검색 결과
// 전체나 Realm 전체를 뜻한다고 읽으면 끝내려던 것보다 훨씬 많이 끝난다.
test('확인 대화 상자가 범위를 화면에 보이는 것으로 한정해 말한다', async () => {
  const user = userEvent.setup()
  mocks.api.mockImplementation(listing([session, otherSession]))
  renderSessions()
  await screen.findByText('alice')
  await user.click(screen.getByRole('checkbox', { name: '표시된 활성 세션 모두 선택' }))
  await user.click(screen.getByRole('button', { name: '선택한 세션 강제 로그아웃' }))
  expect(screen.getByText(/지금 화면에 표시된 세션 중 선택한 것만/)).toBeInTheDocument()
})

// 검색어를 바꾸면 고른 행은 화면에서 사라진다. 보이지 않는 식별자에 대고
// 실행하는 것이 아무도 의도하지 않은 세션을 끝내는 경로다.
test('검색어가 바뀌면 선택이 풀린다', async () => {
  const user = userEvent.setup()
  mocks.api.mockImplementation(listing([session, otherSession]))
  renderSessions()
  await screen.findByText('alice')
  await user.click(screen.getByRole('checkbox', { name: 'alice 세션 선택' }))
  expect(screen.getByText('1개 선택됨')).toBeInTheDocument()
  await user.type(screen.getByRole('textbox', { name: '세션 검색' }), 'bob')
  // 새 결과가 돌아온 뒤까지 본다. 다시 불러오는 잠깐 동안 행이 비어 표가
  // 사라지는 것은 선택이 풀린 것과 구별되지 않는다.
  await waitFor(() => expect(mocks.api.mock.calls.some(([path]) => String(path).includes('q=bob'))).toBe(true))
  await screen.findByText('alice')
  expect(screen.queryByText('1개 선택됨')).not.toBeInTheDocument()
})
