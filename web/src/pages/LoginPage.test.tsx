import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { expect, test, vi } from 'vitest'
import { LoginPage } from './LoginPage'

vi.mock('../lib/auth-context', () => ({
  useAuth: () => ({
    meta: { product: 'ReSSO', version: 'v9.9.9-test', commit: 'test', build_time: 'now', go_version: 'go-test' },
    refresh: vi.fn(),
  }),
}))

function renderLogin() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  return render(<QueryClientProvider client={queryClient}><MemoryRouter initialEntries={['/login']}><LoginPage /></MemoryRouter></QueryClientProvider>)
}

test('login form remains usable and exposes the service version', async () => {
  const user = userEvent.setup()
  renderLogin()
  const username = screen.getByRole('textbox', { name: '아이디' })
  const password = screen.getByLabelText(/비밀번호/, { selector: 'input' })
  await user.type(username, 'admin')
  await user.type(password, 'correct horse battery staple')
  expect(username).toHaveValue('admin')
  expect(password).toHaveValue('correct horse battery staple')
  expect(screen.getByText('v9.9.9-test')).toBeInTheDocument()
  expect(screen.getByRole('button', { name: /로그인/ })).toBeEnabled()
})

test('a rate limited login shows how long to wait and blocks the form until then', async () => {
  const user = userEvent.setup()
  // 429 with Retry-After was previously invisible: the page showed the generic
  // failure text and let the user keep hammering a blocked endpoint.
  const fetchMock = vi.fn(async () => new Response(JSON.stringify({ error: 'rate_limited', message: '로그인 요청이 너무 많습니다.' }), {
    status: 429,
    headers: { 'Content-Type': 'application/json', 'Retry-After': '90' },
  }))
  vi.stubGlobal('fetch', fetchMock)

  renderLogin()
  await user.type(screen.getByRole('textbox', { name: '아이디' }), 'admin')
  await user.type(screen.getByLabelText(/비밀번호/, { selector: 'input' }), 'wrong-password')
  await user.click(screen.getByRole('button', { name: /로그인/ }))

  const notice = await screen.findByText(/로그인 시도가 제한되었습니다/)
  expect(notice).toBeInTheDocument()
  expect(notice.textContent).toContain('약 2분')
  expect(screen.getByRole('button', { name: /후 재시도/ })).toBeDisabled()
  vi.unstubAllGlobals()
})

test('repeated failures explain the lockout policy before the account is locked', async () => {
  const user = userEvent.setup()
  const fetchMock = vi.fn(async () => new Response(JSON.stringify({ error: 'invalid_credentials', message: '아이디 또는 비밀번호가 올바르지 않습니다.' }), {
    status: 401,
    headers: { 'Content-Type': 'application/json' },
  }))
  vi.stubGlobal('fetch', fetchMock)

  renderLogin()
  await user.type(screen.getByRole('textbox', { name: '아이디' }), 'admin')
  await user.type(screen.getByLabelText(/비밀번호/, { selector: 'input' }), 'wrong-password')
  for (let attempt = 0; attempt < 3; attempt++) {
    await user.click(screen.getByRole('button', { name: /로그인/ }))
    await screen.findByText('아이디 또는 비밀번호가 올바르지 않습니다.')
  }
  // The server keeps its answer generic; the guidance is produced locally so
  // that no account existence is disclosed.
  expect(await screen.findByText(/반복 실패하면 계정이 일정 시간 잠기며/)).toBeInTheDocument()
  vi.unstubAllGlobals()
})
