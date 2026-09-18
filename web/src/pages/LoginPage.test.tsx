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

test('a login that succeeded without its code is sent back to the service, not the form', async () => {
  const user = userEvent.setup()
  // 500 authorization_code_failed is a login that finished: the session exists
  // and its cookies are in the browser; only the code was not written. It
  // shared internal_error with the 500s that mean "this service did not
  // finish, try here again", so the page showed the same red line for two
  // opposite instructions — and retrying here cannot work: the request was
  // consumed, so the same credential meets expired_request.
  const fetchMock = vi.fn(async (input: string) => {
    if (input.startsWith('/api/v1/auth/challenge/')) {
      return new Response(challengeBody, { status: 200, headers: { 'Content-Type': 'application/json' } })
    }
    return new Response(JSON.stringify({
      error: 'authorization_code_failed',
      message: '로그인은 되었지만 인가 코드를 생성하지 못했습니다. 애플리케이션에서 다시 시도하세요.',
      trace_id: 'trace-99',
    }), { status: 500, headers: { 'Content-Type': 'application/json' } })
  })
  vi.stubGlobal('fetch', fetchMock)

  renderLogin('/login?request=live-token')
  await screen.findByText(/사내 포털에서 마스터 계정 인증을 요청했습니다/)
  await user.type(screen.getByRole('textbox', { name: '아이디' }), 'admin')
  await user.type(screen.getByLabelText(/비밀번호/, { selector: 'input' }), 'correct horse battery staple')
  await user.click(screen.getByRole('button', { name: /로그인/ }))

  const notice = await screen.findByText(/연결한 서비스로 돌아가 다시 시작하세요/)
  expect(notice.textContent).toContain('비밀번호를 다시 묻지 않습니다')
  expect(notice.textContent).toContain('이 화면에서 다시 로그인하지 마세요')
  expect(screen.getByText(/trace-99/)).toBeInTheDocument()
  expect(screen.getByRole('button', { name: /로그인/ })).toBeDisabled()
  expect(screen.queryByText(/반복 실패하면 계정이 일정 시간 잠기며/)).not.toBeInTheDocument()
  vi.unstubAllGlobals()
})

test.each([
  { status: 409, error: 'request_already_used', message: '로그인 요청이 이미 처리되었습니다.' },
  { status: 400, error: 'expired_request', message: '로그인 요청이 만료되었거나 이미 사용되었습니다.' },
])('a spent login request ($status $error) says where to go instead of only that it was spent', async ({ status, error, message }) => {
  const user = userEvent.setup()
  // Both said the request was gone and nothing more, and left the form
  // enabled — so the person tried the same form again and met the same
  // answer. The challenge's 404 already sends them back for this reason.
  const fetchMock = vi.fn(async (input: string) => {
    if (input.startsWith('/api/v1/auth/challenge/')) {
      return new Response(challengeBody, { status: 200, headers: { 'Content-Type': 'application/json' } })
    }
    return new Response(JSON.stringify({ error, message }), { status, headers: { 'Content-Type': 'application/json' } })
  })
  vi.stubGlobal('fetch', fetchMock)

  renderLogin('/login?request=live-token')
  await screen.findByText(/사내 포털에서 마스터 계정 인증을 요청했습니다/)
  await user.type(screen.getByRole('textbox', { name: '아이디' }), 'admin')
  await user.type(screen.getByLabelText(/비밀번호/, { selector: 'input' }), 'correct horse battery staple')
  await user.click(screen.getByRole('button', { name: /로그인/ }))

  expect(await screen.findByText(/연결한 서비스로 돌아가 다시 시작하세요/)).toBeInTheDocument()
  expect(screen.getByText(message)).toBeInTheDocument()
  expect(screen.getByRole('button', { name: /로그인/ })).toBeDisabled()
  vi.unstubAllGlobals()
})

test('a fault this service did not finish keeps the form as the way to try again', async () => {
  const user = userEvent.setup()
  // The other 500 on this route — internal_error — is an attempt that did not
  // finish, and the way out is this form once the fault clears. The
  // distinction above must not sweep it up.
  const fetchMock = vi.fn(async (input: string) => {
    if (input.startsWith('/api/v1/auth/challenge/')) {
      return new Response(challengeBody, { status: 200, headers: { 'Content-Type': 'application/json' } })
    }
    return new Response(JSON.stringify({ error: 'internal_error', message: '로그인을 처리하지 못했습니다.', trace_id: 'trace-7' }), {
      status: 500, headers: { 'Content-Type': 'application/json' },
    })
  })
  vi.stubGlobal('fetch', fetchMock)

  renderLogin('/login?request=live-token')
  await screen.findByText(/사내 포털에서 마스터 계정 인증을 요청했습니다/)
  await user.type(screen.getByRole('textbox', { name: '아이디' }), 'admin')
  await user.type(screen.getByLabelText(/비밀번호/, { selector: 'input' }), 'correct horse battery staple')
  await user.click(screen.getByRole('button', { name: /로그인/ }))

  await screen.findByText('로그인을 처리하지 못했습니다.')
  expect(screen.queryByText(/연결한 서비스로 돌아가 다시 시작하세요/)).not.toBeInTheDocument()
  expect(screen.getByRole('button', { name: /로그인/ })).toBeEnabled()
  vi.unstubAllGlobals()
})

test.each([
  {
    label: '500 internal_error',
    entry: '/login?request=live-token',
    answer: () => new Response(JSON.stringify({ error: 'internal_error', message: '로그인을 처리하지 못했습니다.', trace_id: 'trace-7' }), {
      status: 500, headers: { 'Content-Type': 'application/json' },
    }),
    message: '로그인을 처리하지 못했습니다.',
    trace: 'trace-7',
  },
  {
    label: 'status 0',
    entry: '/login?request=live-token',
    answer: () => { throw new TypeError('Failed to fetch') },
    message: '서버에 연결하지 못했습니다. 네트워크와 ReSSO 서비스 상태를 확인한 뒤 다시 시도하세요.',
    trace: undefined,
  },
  {
    label: '500 internal_error on the console login',
    entry: '/login',
    answer: () => new Response(JSON.stringify({ error: 'internal_error', message: '로그인을 처리하지 못했습니다.', trace_id: 'trace-8' }), {
      status: 500, headers: { 'Content-Type': 'application/json' },
    }),
    message: '로그인을 처리하지 못했습니다.',
    trace: 'trace-8',
  },
])('a fault this service did not finish ($label) says to try here again and shows its trace', async ({ entry, answer, message, trace }) => {
  const user = userEvent.setup()
  // These answers shared the red line with a wrong password, which read as
  // "that did not work" and said nothing about when or where to try again —
  // and the 500 carried a Trace ID the page dropped, so the guide's "tell an
  // administrator" had nothing to pass on. The request was not consumed and
  // nothing was recorded, so the form stays the way through.
  const fetchMock = vi.fn(async (input: string) => {
    if (input.startsWith('/api/v1/auth/challenge/')) {
      return new Response(challengeBody, { status: 200, headers: { 'Content-Type': 'application/json' } })
    }
    return answer()
  })
  vi.stubGlobal('fetch', fetchMock)

  renderLogin(entry)
  if (entry.includes('request=')) await screen.findByText(/사내 포털에서 마스터 계정 인증을 요청했습니다/)
  await user.type(screen.getByRole('textbox', { name: '아이디' }), 'admin')
  await user.type(screen.getByLabelText(/비밀번호/, { selector: 'input' }), 'correct horse battery staple')
  await user.click(screen.getByRole('button', { name: /로그인/ }))

  const notice = await screen.findByText(/잠시 후 이 화면에서 다시 시도하세요/)
  expect(notice.textContent).toContain('계정에는 아무것도 기록되지 않았')
  // Only a request that came from a relying party has somewhere else the
  // person might wrongly go; the console login has no such place to warn about.
  if (entry.includes('request=')) {
    expect(notice.textContent).toContain('연결한 서비스에서 다시 시작하지 말고')
  } else {
    expect(notice.textContent).not.toContain('연결한 서비스')
  }
  // The service's own message is shown once, as the notice's title, not again
  // as a red line.
  expect(screen.getAllByText(message)).toHaveLength(1)
  if (trace) {
    expect(screen.getByText(`trace: ${trace}`)).toBeInTheDocument()
  } else {
    expect(screen.queryByText(/^trace:/)).not.toBeInTheDocument()
  }
  expect(screen.queryByText(/연결한 서비스로 돌아가 다시 시작하세요/)).not.toBeInTheDocument()
  expect(screen.queryByText(/반복 실패하면 계정이 일정 시간 잠기며/)).not.toBeInTheDocument()
  expect(screen.getByRole('button', { name: /로그인/ })).toBeEnabled()
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
