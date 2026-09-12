import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import DashboardRoundedIcon from '@mui/icons-material/DashboardRounded'
import LogoutRoundedIcon from '@mui/icons-material/LogoutRounded'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import { CommandPalette } from './CommandPalette'

const mocks = vi.hoisted(() => ({ api: vi.fn() }))
vi.mock('../lib/api', () => ({ api: (...args: unknown[]) => mocks.api(...args) }))

const destinations = [
  { label: '대시보드', path: '/admin', icon: DashboardRoundedIcon, keywords: '현황 홈' },
  { label: '사용자', path: '/admin/users', icon: DashboardRoundedIcon, keywords: '계정 조직' },
  { label: 'Client', path: '/admin/clients', icon: DashboardRoundedIcon, keywords: 'OIDC 애플리케이션' },
]

beforeEach(() => {
  mocks.api.mockResolvedValue({ items: [] })
  window.localStorage.clear()
})
afterEach(() => vi.clearAllMocks())

function renderPalette(overrides: Partial<Parameters<typeof CommandPalette>[0]> = {}) {
  const onNavigate = vi.fn()
  const onClose = vi.fn()
  const run = vi.fn()
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <CommandPalette open onClose={onClose} destinations={destinations}
        commands={[{ label: '로그아웃', description: '이 브라우저의 세션을 종료합니다', icon: LogoutRoundedIcon, run }]}
        admin onNavigate={onNavigate} {...overrides} />
    </QueryClientProvider>,
  )
  return { onNavigate, onClose, run }
}

const field = () => screen.getByRole('combobox', { name: /검색/ })
const activeOption = () => screen.getByRole('option', { selected: true })

// 팔레트의 존재 이유가 키보드다. 단축키로 열어 놓고 마우스를 잡아야 한다면
// 메뉴를 직접 누르는 것과 다르지 않다.
test('방향키로 항목을 옮기고 Enter로 실행한다', async () => {
  const user = userEvent.setup()
  const { onNavigate } = renderPalette()
  expect(activeOption()).toHaveTextContent('대시보드')
  await user.keyboard('{ArrowDown}')
  expect(activeOption()).toHaveTextContent('사용자')
  await user.keyboard('{Enter}')
  expect(onNavigate).toHaveBeenCalledWith('/admin/users')
})

test('위로 올리면 마지막 항목으로 돌아간다', async () => {
  const user = userEvent.setup()
  const { run } = renderPalette()
  await user.keyboard('{ArrowUp}')
  expect(activeOption()).toHaveTextContent('로그아웃')
  await user.keyboard('{Enter}')
  expect(run).toHaveBeenCalled()
})

test('Home과 End가 양 끝으로 보낸다', async () => {
  const user = userEvent.setup()
  renderPalette()
  await user.keyboard('{End}')
  expect(activeOption()).toHaveTextContent('로그아웃')
  await user.keyboard('{Home}')
  expect(activeOption()).toHaveTextContent('대시보드')
})

// 포커스는 입력란에 머물러야 계속 타이핑해서 목록을 좁힐 수 있다. 활성 항목은
// aria-activedescendant로 알린다 — 그러지 않으면 스크린 리더에게는 아무 일도
// 일어나지 않은 것과 같다.
test('포커스는 입력란에 머물고 활성 항목을 aria로 알린다', async () => {
  const user = userEvent.setup()
  renderPalette()
  await user.keyboard('{ArrowDown}')
  expect(field()).toHaveFocus()
  expect(field()).toHaveAttribute('aria-activedescendant', activeOption().id)
})

// 목록이 좁혀지면 남아 있던 위치는 목록 밖을 가리킬 수 있다. 그 상태로 Enter를
// 누르면 아무 일도 일어나지 않는다.
test('입력으로 목록이 줄어도 실행할 항목이 남는다', async () => {
  const user = userEvent.setup()
  const { onNavigate } = renderPalette()
  await user.keyboard('{End}')
  await user.type(field(), '대시')
  expect(activeOption()).toHaveTextContent('대시보드')
  await user.keyboard('{Enter}')
  expect(onNavigate).toHaveBeenCalledWith('/admin')
})

// 아무것도 없는 상자는 "찾는 중"과 "없음"을 구별해 주지 않는다.
test('일치하는 항목이 없으면 그렇게 말한다', async () => {
  const user = userEvent.setup()
  renderPalette()
  await user.type(field(), 'zzzz없는것')
  await waitFor(() => expect(screen.getByText(/해당하는 항목이 없습니다/)).toBeInTheDocument())
  expect(screen.queryAllByRole('option')).toHaveLength(0)
})

test('명령도 이름으로 찾아 실행한다', async () => {
  const user = userEvent.setup()
  const { run } = renderPalette()
  await user.type(field(), '로그아웃')
  await user.keyboard('{Enter}')
  expect(run).toHaveBeenCalled()
})

// 서버 검색 결과는 메뉴 항목과 같은 목록에 들어가야 방향키가 그 위를 지나간다.
test('서버 검색 결과도 같은 목록에서 방향키로 고른다', async () => {
  const user = userEvent.setup()
  mocks.api.mockResolvedValue({ items: [{ kind: 'user', id: 'u1', label: 'alice', description: 'alice@example.com', path: '/admin/users?q=alice' }] })
  const { onNavigate } = renderPalette()
  await user.type(field(), 'alice')
  await waitFor(() => expect(screen.getByText('alice')).toBeInTheDocument())
  await user.keyboard('{End}{Enter}')
  expect(onNavigate).toHaveBeenCalledWith('/admin/users?q=alice')
})

// 매일 같은 두세 화면을 오간다. 아무것도 입력하지 않았을 때 고정된 메뉴 순서를
// 매번 읽고 내려가는 것이 팔레트가 없애야 할 일이다.
test('아무것도 입력하지 않으면 최근 방문한 곳을 먼저 보여준다', async () => {
  window.localStorage.setItem('resso.recent-destinations', JSON.stringify(['/admin/clients']))
  const user = userEvent.setup()
  const { onNavigate } = renderPalette()
  expect(screen.getByText('최근 방문')).toBeInTheDocument()
  expect(activeOption()).toHaveTextContent('Client')
  await user.keyboard('{Enter}')
  expect(onNavigate).toHaveBeenCalledWith('/admin/clients')
})
