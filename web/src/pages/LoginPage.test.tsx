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

function renderLogin(entry = '/login') {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  return render(<QueryClientProvider client={queryClient}><MemoryRouter initialEntries={[entry]}><LoginPage /></MemoryRouter></QueryClientProvider>)
}

const challengeBody = JSON.stringify({
  realm: { name: 'master', display_name: '마스터' },
  client: { client_id: 'portal', name: '사내 포털' },
  expires_at: '2026-01-01T00:00:00Z',
})

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

test('an account the relying party did not ask for is not told its password may lock the account', async () => {
  const user = userEvent.setup()
  // 403 account_mismatch is a login that succeeded: the password was accepted,
  // the session exists, and the service cleared the account's failure count
  // before declining to mint a code for an account the relying party did not
  // name. The page counted it as a failed attempt all the same, so a third one
  // produced "keep failing and the account locks; ask an administrator before
  // it does" — advice to doubt a password that was right, about an account that
  // cannot lock. And the refusal shared its red line with a wrong password, so
  // nothing said the form in front of the person was still the way through.
  const fetchMock = vi.fn(async (input: string) => {
    if (input.startsWith('/api/v1/auth/challenge/')) {
      return new Response(challengeBody, { status: 200, headers: { 'Content-Type': 'application/json' } })
    }
    return new Response(JSON.stringify({
      error: 'account_mismatch',
      message: '이 애플리케이션은 이전에 사용하던 계정으로 다시 로그인하도록 요청했습니다. 방금 로그인한 계정은 그 계정이 아닙니다. 요청한 계정으로 로그인하세요.',
    }), { status: 403, headers: { 'Content-Type': 'application/json' } })
  })
  vi.stubGlobal('fetch', fetchMock)

  renderLogin('/login?request=live-token')
  await screen.findByText(/사내 포털에서 마스터 계정 인증을 요청했습니다/)
  await user.type(screen.getByRole('textbox', { name: '아이디' }), 'someone-else')
  await user.type(screen.getByLabelText(/비밀번호/, { selector: 'input' }), 'their-right-password')
  for (let attempt = 0; attempt < 3; attempt++) {
    await user.click(screen.getByRole('button', { name: /로그인/ }))
    await screen.findByText(/요청한 계정으로 로그인하세요/)
  }

  expect(screen.queryByText(/반복 실패하면 계정이 일정 시간 잠기며/)).not.toBeInTheDocument()
  // The request is left unconsumed on purpose, so the way out is this form —
  // going back to the relying party only lands on the same comparison.
  expect(await screen.findByText(/이 화면에서 요청한 계정으로 다시 로그인하면/)).toBeInTheDocument()
  expect(screen.getByRole('button', { name: /로그인/ })).toBeEnabled()
  vi.unstubAllGlobals()
})

test('a fault on this side is not counted toward the lockout warning either', async () => {
  const user = userEvent.setup()
  // Nothing was recorded against the account: the service did not finish the
  // attempt. Its own message is kept, but the lockout policy has no bearing.
  const fetchMock = vi.fn(async () => new Response(JSON.stringify({
    error: 'internal_error', message: '로그인을 처리하지 못했습니다.', trace_id: 'trace-7',
  }), { status: 500, headers: { 'Content-Type': 'application/json' } }))
  vi.stubGlobal('fetch', fetchMock)

  renderLogin()
  await user.type(screen.getByRole('textbox', { name: '아이디' }), 'admin')
  await user.type(screen.getByLabelText(/비밀번호/, { selector: 'input' }), 'correct horse battery staple')
  for (let attempt = 0; attempt < 3; attempt++) {
    await user.click(screen.getByRole('button', { name: /로그인/ }))
    await screen.findByText('로그인을 처리하지 못했습니다.')
  }

  expect(screen.queryByText(/반복 실패하면 계정이 일정 시간 잠기며/)).not.toBeInTheDocument()
  vi.unstubAllGlobals()
})

test('a locked account is told it is locked, not that its password is wrong', async () => {
  const user = userEvent.setup()
  // The server answers 401 here, not 429, so the countdown that already
  // existed for rate limiting did nothing: someone who had simply been locked
  // out saw "wrong username or password" and went on trying variations.
  const fetchMock = vi.fn(async () => new Response(JSON.stringify({
    error: 'account_locked',
    message: '연속된 로그인 실패로 계정이 잠겼습니다. 약 10분 뒤에 다시 시도하거나 관리자에게 잠금 해제를 요청하세요.',
  }), { status: 401, headers: { 'Content-Type': 'application/json', 'Retry-After': '600' } }))
  vi.stubGlobal('fetch', fetchMock)

  renderLogin()
  await user.type(screen.getByRole('textbox', { name: '아이디' }), 'victim')
  await user.type(screen.getByLabelText(/비밀번호/, { selector: 'input' }), 'the-right-password')
  await user.click(screen.getByRole('button', { name: /로그인/ }))

  const notice = await screen.findByText(/계정이 잠겼습니다/)
  expect(notice.textContent).toContain('약 10분')
  expect(notice.textContent).toContain('잠금 해제')
  expect(screen.getByRole('button', { name: /후 재시도/ })).toBeDisabled()
  vi.unstubAllGlobals()
})

test('a spent login request is the only failure that sends the person back to the service', async () => {
  // 404 is the one answer that means the request token is gone — spent,
  // expired or never issued — and starting over is then the only way out.
  const fetchMock = vi.fn(async () => new Response(JSON.stringify({ error: 'not_found', message: '요청한 항목을 찾을 수 없습니다.' }), {
    status: 404, headers: { 'Content-Type': 'application/json' },
  }))
  vi.stubGlobal('fetch', fetchMock)

  renderLogin('/login?request=spent-token')

  expect(await screen.findByText(/로그인 요청이 만료되었습니다/)).toBeInTheDocument()
  expect(screen.queryByRole('button', { name: '다시 시도' })).not.toBeInTheDocument()
  vi.unstubAllGlobals()
})

test('a fault on this side is not reported as an expired login request', async () => {
  const user = userEvent.setup()
  // The page used to answer every failed challenge with "your login request
  // expired, start again over there". For a store that did not answer, that
  // sent the person off for a fresh request token to meet the same fault
  // again, while the request they held was still intact — and left the form
  // disabled with nothing to press once the fault had cleared.
  const fetchMock = vi.fn()
    .mockResolvedValueOnce(new Response(JSON.stringify({ error: 'internal_error', message: '요청을 처리하지 못했습니다.', trace_id: 'trace-42' }), {
      status: 500, headers: { 'Content-Type': 'application/json' },
    }))
    .mockResolvedValueOnce(new Response(challengeBody, { status: 200, headers: { 'Content-Type': 'application/json' } }))
  vi.stubGlobal('fetch', fetchMock)

  renderLogin('/login?request=live-token')

  const notice = await screen.findByText(/로그인 요청을 확인하지 못했습니다/)
  expect(notice.textContent).toContain('다시 시작하지 말고')
  expect(screen.queryByText(/로그인 요청이 만료되었습니다/)).not.toBeInTheDocument()
  expect(notice.textContent).toContain('trace-42')

  // Retrying is offered because this cause can clear on its own, and once it
  // has, the same request finishes from this form.
  await user.click(screen.getByRole('button', { name: '다시 시도' }))
  expect(await screen.findByText(/사내 포털에서 마스터 계정 인증을 요청했습니다/)).toBeInTheDocument()
  expect(screen.queryByText(/로그인 요청을 확인하지 못했습니다/)).not.toBeInTheDocument()

  await user.type(screen.getByRole('textbox', { name: '아이디' }), 'admin')
  await user.type(screen.getByLabelText(/비밀번호/, { selector: 'input' }), 'correct horse battery staple')
  expect(screen.getByRole('button', { name: /로그인/ })).toBeEnabled()
  vi.unstubAllGlobals()
})
