import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { expect, test, vi } from 'vitest'
import { AppShell } from './AppShell'

const mocks = vi.hoisted(() => ({ api: vi.fn() }))

vi.mock('../lib/api', () => ({ api: (...args: unknown[]) => mocks.api(...args) }))
vi.mock('../lib/auth-context', () => ({
  useAuth: () => ({
    me: { user: { username: 'alice', display_name: 'Alice', email: 'alice@example.com' }, permissions: { admin: true } },
    meta: { version: 'test', commit: 'unknown' },
    logout: vi.fn(),
  }),
}))

mocks.api.mockResolvedValue({ items: [], enabled: false })

// jsdom에는 matchMedia가 없어 MUI가 좁은 화면으로 판단하고 사이드바를 닫힌 Drawer에
// 넣어버린다. 스킵 링크가 실제로 필요한 쪽은 메뉴 전체가 본문 앞에 펼쳐진 데스크톱
// 레이아웃이므로, 그 화면을 재현한다.
window.matchMedia = ((query: string) => ({
  matches: true, media: query, onchange: null,
  addEventListener: () => {}, removeEventListener: () => {},
  addListener: () => {}, removeListener: () => {}, dispatchEvent: () => false,
})) as unknown as typeof window.matchMedia

function renderShell(initial = '/admin') {
  return render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <MemoryRouter initialEntries={[initial]}>
        <Routes>
          <Route element={<AppShell />}>
            <Route path="/admin" element={<h1>대시보드</h1>} />
            <Route path="/admin/users" element={<h1>사용자</h1>} />
          </Route>
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

// 사이드바 메뉴 전체와 그 앞의 헤더 조작부를 지나야 본문에 닿는다. 스킵 링크가 없으면
// 키보드 사용자는 화면을 옮길 때마다 그 전부를 Tab으로 지나쳐야 본문에 닿는다.
test('첫 Tab이 본문으로 건너뛰는 링크에 닿는다', async () => {
  const user = userEvent.setup()
  renderShell()
  await user.tab()
  const skip = screen.getByRole('link', { name: '본문으로 건너뛰기' })
  expect(skip).toHaveFocus()
})

test('건너뛰기를 누르면 포커스가 본문으로 옮겨간다', async () => {
  const user = userEvent.setup()
  const { container } = renderShell()
  await user.tab()
  await user.keyboard('{Enter}')
  expect(container.querySelector('main')).toHaveFocus()
})

// 라우팅은 화면만 갈아끼우므로, 포커스를 옮기지 않으면 스크린 리더 사용자는
// 방금 누른 메뉴 항목에 그대로 머물고 새 화면이 열린 사실을 알 수 없다.
test('메뉴로 화면을 옮기면 포커스가 새 본문으로 따라간다', async () => {
  const user = userEvent.setup()
  const { container } = renderShell()
  const main = container.querySelector('main')
  expect(main).not.toHaveFocus()

  await user.click(screen.getByRole('link', { name: '사용자' }))

  expect(await screen.findByRole('heading', { name: '사용자' })).toBeInTheDocument()
  expect(container.querySelector('main')).toHaveFocus()
})

// 첫 화면에서 포커스를 빼앗으면 사용자가 요청하지 않은 이동이 된다.
test('처음 열었을 때는 포커스를 빼앗지 않는다', () => {
  const { container } = renderShell()
  expect(container.querySelector('main')).not.toHaveFocus()
})

// MUI는 DialogTitle이 없어도 aria-labelledby를 붙인다. 그래서 제목을 렌더하지 않으면
// 존재하지 않는 id를 가리켜, 속성상으로는 이름이 있어 보이지만 실제로는 이름이 없다.
// 이름을 참조로 확인하지 않고 속성 유무만 세면 이 상태를 놓친다.
test('명령 팔레트는 실제로 해석되는 이름을 가진다', async () => {
  const user = userEvent.setup()
  renderShell()
  await user.keyboard('{Control>}k{/Control}')

  const dialog = await screen.findByRole('dialog')
  const labelledby = dialog.getAttribute('aria-labelledby')
  expect(labelledby).toBeTruthy()
  const label = labelledby && document.getElementById(labelledby)
  expect(label, 'aria-labelledby가 가리키는 요소가 렌더되지 않았다').not.toBeNull()
  expect(label).toHaveTextContent('빠른 이동 및 검색')
})

// placeholder는 접근 가능한 이름이 아니며 입력을 시작하면 사라진다.
test('팔레트 검색 입력은 placeholder가 아닌 이름으로 찾을 수 있다', async () => {
  const user = userEvent.setup()
  renderShell()
  await user.keyboard('{Control>}k{/Control}')

  const search = await screen.findByRole('textbox', { name: '메뉴, 사용자, Client 검색' })
  await user.type(search, '사용')
  expect(search).toHaveAccessibleName('메뉴, 사용자, Client 검색')
})
