import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, expect, test, vi } from 'vitest'
import { MailPage } from './MailPage'

const mocks = vi.hoisted(() => ({ api: vi.fn() }))
vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  api: (...args: unknown[]) => mocks.api(...args),
  jsonBody: (value: unknown) => ({ body: JSON.stringify(value) }),
}))
import { APIError } from '../lib/api'
vi.mock('../components/toast-context', () => ({ useToast: () => ({ notify: vi.fn() }) }))

const events = [
  { event: 'approval.requested', key: 'mail.notify_approval_request', label: '승인 요청이 도착함', description: '검토자에게.' },
  { event: 'approval.decided', key: 'mail.notify_approval_decision', label: '승인 요청이 결정됨', description: '요청한 사람에게.' },
]
const off = {
  'mail.enabled': false, 'mail.smtp_host': '', 'mail.smtp_port': 25, 'mail.security': 'auto', 'mail.skip_tls_verify': false,
  'mail.username': '', 'mail.from_address': '', 'mail.from_name': 'ReSSO', 'mail.base_url': '', 'mail.timeout_seconds': 10,
  'mail.notify_approval_request': true, 'mail.notify_approval_decision': true,
}

let saved: unknown[]
beforeEach(() => {
  saved = []
  let current = { settings: off, password_set: false, events }
  mocks.api.mockReset()
  mocks.api.mockImplementation((path: string, init?: RequestInit) => {
    if (path === '/api/admin/v1/mail' && init?.method === 'PUT') {
      const body = JSON.parse(String(init.body))
      saved.push(body)
      current = { settings: body.settings, password_set: Boolean(body.password) || current.password_set, events }
      return Promise.resolve(current)
    }
    if (path === '/api/admin/v1/mail/test') {
      return Promise.reject(new APIError(502, 'mail_send_failed', 'RCPT TO 실패: 550 relay says no'))
    }
    if (path.startsWith('/api/admin/v1/mail/deliveries')) {
      return Promise.resolve({ items: [
        { id: 'd1', event: 'test', recipient: 'admin@example.com', subject: '[ReSSO] SMTP 발송 테스트', status: 'failed', attempts: 1, error_message: 'SMTP 연결 실패: connection refused', created_at: '2026-09-14T01:00:00Z', updated_at: '2026-09-14T01:00:00Z' },
        { id: 'd2', event: 'approval.requested', recipient: 'lead@example.com', subject: "[ReSSO] 홍길동 님의 'ops' Role 승인 요청", status: 'sent', attempts: 1, created_at: '2026-09-14T00:59:00Z', updated_at: '2026-09-14T00:59:00Z' },
      ], total: 2, by_status: { failed: 1, sent: 1 } })
    }
    return Promise.resolve(current)
  })
})

function renderPage() {
  return render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })}>
    <MailPage />
  </QueryClientProvider>)
}

// A fresh install: off, port 25, no password, and the test button waits for
// the switch. The record shows both the failure and the success.
test('a fresh install shows mail off with the internal-relay defaults', async () => {
  renderPage()
  expect(await screen.findByLabelText('메일 알림 사용')).not.toBeChecked()
  expect(screen.getByLabelText(/포트/)).toHaveValue(25)
  expect(screen.getByPlaceholderText('설정되지 않음')).toBeInTheDocument()
  expect(screen.getByRole('button', { name: '시험 발송' })).toBeDisabled()
  expect(await screen.findByText('SMTP 연결 실패: connection refused')).toBeInTheDocument()
  expect(screen.getByText('lead@example.com')).toBeInTheDocument()
})

// Saving sends the standard keys and the password apart from them; the
// password field is emptied afterwards and shows "set" instead of the value.
test('saving carries the password separately and never shows it again', async () => {
  const user = userEvent.setup()
  renderPage()
  await user.click(await screen.findByLabelText('메일 알림 사용'))
  await user.type(screen.getByLabelText(/SMTP 릴레이 주소/), 'relay.corp.example')
  await user.type(screen.getByLabelText(/보내는 주소/), 'resso@corp.example')
  await user.type(screen.getByLabelText(/^비밀번호/), 'hunter2')
  await user.click(screen.getByLabelText('승인 요청이 결정됨', { exact: false }))
  await user.click(screen.getByRole('button', { name: '저장' }))
  await waitFor(() => expect(saved).toHaveLength(1))
  const body = saved[0] as { settings: Record<string, unknown>; password: string; clear_password: boolean }
  expect(body.password).toBe('hunter2')
  expect(body.clear_password).toBe(false)
  expect(body.settings['mail.enabled']).toBe(true)
  expect(body.settings['mail.smtp_host']).toBe('relay.corp.example')
  expect(body.settings['mail.notify_approval_decision']).toBe(false)
  expect(body.settings['mail.notify_approval_request']).toBe(true)
  expect(body.settings['mail.password']).toBeUndefined()
  expect(await screen.findByPlaceholderText('설정됨 — 바꿀 때만 입력')).toHaveValue('')
  expect(screen.getByLabelText('저장된 비밀번호 지우기')).toBeInTheDocument()
})

// The relay's answer to a test send is shown where the button is.
test('a failed test send shows what the relay said', async () => {
  const user = userEvent.setup()
  mocks.api.mockImplementationOnce(() => Promise.resolve({ settings: { ...off, 'mail.enabled': true, 'mail.smtp_host': 'relay' }, password_set: false, events }))
  renderPage()
  const button = await screen.findByRole('button', { name: '시험 발송' })
  expect(button).toBeEnabled()
  await user.type(screen.getByLabelText(/받는 사람/), 'me@corp.example')
  await user.click(button)
  expect(await screen.findByText(/550 relay says no/)).toBeInTheDocument()
})
