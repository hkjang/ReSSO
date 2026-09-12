import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, expect, test, vi } from 'vitest'
import { ReauthenticationGate } from './ReauthenticationGate'
import { APIError, api } from '../lib/api'
import { confirmIdentity } from '../lib/reauthentication'

afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks() })

function answer(status: number, body: unknown) {
  return Promise.resolve(new Response(JSON.stringify(body), {
    status, headers: { 'Content-Type': 'application/json' },
  }))
}

// 보호된 작업이 거절되면 그것은 보고할 실패가 아니라 물어볼 질문이다. 화면마다
// 이 대화 상자를 따로 붙이면 아홉 곳에 같은 코드가 생기고 열 번째가 빠진다.
test('거절당한 요청은 비밀번호를 확인한 뒤 그대로 이어진다', async () => {
  const user = userEvent.setup()
  const fetchMock = vi.fn((input: RequestInfo | URL) => {
    const path = String(input)
    if (path.includes('reauthenticate')) return answer(200, { reauthenticated: true })
    return fetchMock.mock.calls.filter(([p]) => String(p).includes('keys/rotate')).length === 1
      ? answer(403, { error: 'reauthentication_required', message: '보호된 작업입니다.' })
      : answer(200, { rotated: true })
  })
  vi.stubGlobal('fetch', fetchMock)
  render(<ReauthenticationGate><div>화면</div></ReauthenticationGate>)

  const result = api<{ rotated: boolean }>('/api/admin/v1/realms/r1/keys/rotate', { method: 'POST' })
  await user.type(await screen.findByLabelText('비밀번호'), 'bootstrap-password-123')
  await user.click(screen.getByRole('button', { name: '확인하고 계속' }))

  expect(await result).toEqual({ rotated: true })
  expect(fetchMock.mock.calls.filter(([p]) => String(p).includes('keys/rotate'))).toHaveLength(2)
})

// 취소했는데 아무 일도 일어나지 않으면, 작업을 요청한 화면은 영원히 기다린다.
test('취소하면 원래 요청이 서버가 준 메시지로 실패한다', async () => {
  const user = userEvent.setup()
  vi.stubGlobal('fetch', vi.fn(() => answer(403, { error: 'reauthentication_required', message: '보호된 작업입니다.' })))
  render(<ReauthenticationGate><div>화면</div></ReauthenticationGate>)

  const result = api('/api/admin/v1/realms/r1/keys/rotate', { method: 'POST' })
  await user.click(await screen.findByRole('button', { name: '취소' }))
  await expect(result).rejects.toMatchObject({ code: 'reauthentication_required', message: '보호된 작업입니다.' })
})

// 비밀번호를 잘못 쳤다고 진행하던 작업이 실패하면, 운영자는 처음부터 다시 한다.
test('비밀번호가 틀리면 대화 상자를 열어 둔 채 이유를 보여준다', async () => {
  const user = userEvent.setup()
  let attempts = 0
  vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL) => {
    const path = String(input)
    if (path.includes('reauthenticate')) {
      attempts += 1
      return attempts === 1
        ? answer(401, { error: 'invalid_credentials', message: '비밀번호가 올바르지 않습니다.' })
        : answer(200, { reauthenticated: true })
    }
    return attempts >= 2 ? answer(200, { rotated: true })
      : answer(403, { error: 'reauthentication_required', message: '보호된 작업입니다.' })
  }))
  render(<ReauthenticationGate><div>화면</div></ReauthenticationGate>)

  const result = api<{ rotated: boolean }>('/api/admin/v1/realms/r1/keys/rotate', { method: 'POST' })
  await user.type(await screen.findByLabelText('비밀번호'), 'wrong')
  await user.click(screen.getByRole('button', { name: '확인하고 계속' }))
  expect(await screen.findByText('비밀번호가 올바르지 않습니다.')).toBeInTheDocument()
  expect(screen.getByLabelText('비밀번호')).toHaveValue('')

  await user.type(screen.getByLabelText('비밀번호'), 'right')
  await user.click(screen.getByRole('button', { name: '확인하고 계속' }))
  expect(await result).toEqual({ rotated: true })
})

// 열네 개를 한 번에 처리하는 작업은 열네 번 동시에 거절당한다. 대화 상자 열네 개는
// 보안 장치가 아니라 콘솔을 그만 쓸 이유다.
test('동시에 여러 요청이 거절당해도 한 번만 묻는다', async () => {
  const user = userEvent.setup()
  let confirmed = false
  vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL) => {
    const path = String(input)
    if (path.includes('reauthenticate')) { confirmed = true; return answer(200, { reauthenticated: true }) }
    return confirmed ? answer(200, { done: true })
      : answer(403, { error: 'reauthentication_required', message: '보호된 작업입니다.' })
  }))
  render(<ReauthenticationGate><div>화면</div></ReauthenticationGate>)

  const all = Promise.all([1, 2, 3].map((n) => api(`/api/admin/v1/realms/r${n}/keys/rotate`, { method: 'POST' })))
  await user.type(await screen.findByLabelText('비밀번호'), 'right')
  expect(screen.getAllByRole('dialog')).toHaveLength(1)
  await user.click(screen.getByRole('button', { name: '확인하고 계속' }))
  expect(await all).toEqual([{ done: true }, { done: true }, { done: true }])
})

// 다른 이유로 거절된 요청까지 비밀번호를 묻기 시작하면, 묻는 일 자체가 의미를 잃는다.
test('다른 거절에는 묻지 않는다', async () => {
  vi.stubGlobal('fetch', vi.fn(() => answer(403, { error: 'insufficient_permission', message: '권한이 없습니다.' })))
  render(<ReauthenticationGate><div>화면</div></ReauthenticationGate>)
  await expect(api('/api/admin/v1/realms/r1/keys/rotate', { method: 'POST' }))
    .rejects.toBeInstanceOf(APIError)
  await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
})

// 물어볼 창이 없는데 기다리게 하면, 요청한 쪽은 영원히 끝나지 않는다.
test('대화 상자가 없으면 즉시 아니라고 답한다', async () => {
  expect(await confirmIdentity()).toBe(false)
})
