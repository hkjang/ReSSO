import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { expect, test, vi } from 'vitest'
import { RealmPicker } from './RealmPicker'
import type { Realm } from '../types'

function realm(name: string, displayName: string): Realm {
  return {
    id: `id-${name}`, name, display_name: displayName, issuer_url: `https://sso/realms/${name}`,
    enabled: true, approval_enabled: false, access_token_ttl_seconds: 300, refresh_token_ttl_seconds: 3600,
    session_ttl_seconds: 3600, idle_timeout_seconds: 1800, password_min_length: 8, max_login_attempts: 5,
    lockout_seconds: 300, created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z',
  }
}

const realms = [realm('acme-prod', '에이스 운영'), realm('acme-stage', '에이스 스테이징'), realm('globex', '글로벡스')]

function renderPicker() {
  const onChange = vi.fn()
  render(<RealmPicker realms={realms} value="id-acme-prod" onChange={onChange} />)
  return { onChange, field: screen.getByRole('combobox', { name: 'Realm' }) }
}

// Realm이 쉰 개인 서비스에서 드롭다운을 끝까지 굴려 찾는 것이 원래 동작이었다.
test('표시 이름의 일부로 좁힐 수 있다', async () => {
  const user = userEvent.setup()
  const { onChange, field } = renderPicker()
  await user.clear(field)
  await user.type(field, '글로벡')
  await user.click(screen.getByRole('option', { name: /글로벡스/ }))
  expect(onChange).toHaveBeenCalledWith('id-globex')
})

// 운영자가 기억하는 이름은 둘 중 어느 쪽일지 모른다. issuer URL과 감사 기록에
// 나오는 것은 기술 이름 쪽이다.
test('기술 이름의 일부로도 좁힐 수 있다', async () => {
  const user = userEvent.setup()
  const { onChange, field } = renderPicker()
  await user.clear(field)
  await user.type(field, 'stage')
  await user.click(screen.getByRole('option', { name: /acme-stage/ }))
  expect(onChange).toHaveBeenCalledWith('id-acme-stage')
})

test('좁히면 맞지 않는 Realm은 보이지 않는다', async () => {
  const user = userEvent.setup()
  const { field } = renderPicker()
  await user.clear(field)
  await user.type(field, 'globex')
  expect(screen.getAllByRole('option')).toHaveLength(1)
})

// 두 이름이 모두 보여야 목록에서 고를 수 있다 — 표시 이름만으로는 운영과
// 스테이징을 가르지 못하는 경우가 흔하다.
test('목록이 표시 이름과 기술 이름을 함께 보여준다', async () => {
  const user = userEvent.setup()
  const { field } = renderPicker()
  await user.click(field)
  const option = screen.getByRole('option', { name: /에이스 스테이징/ })
  expect(option).toHaveTextContent('에이스 스테이징')
  expect(option).toHaveTextContent('acme-stage')
})

// 지워 버리면 그 뒤의 모든 화면이 보여줄 Realm을 잃는다.
test('선택을 비울 수 없다', async () => {
  const user = userEvent.setup()
  const { onChange, field } = renderPicker()
  await user.clear(field)
  await user.tab()
  expect(onChange).not.toHaveBeenCalled()
  expect(field).toHaveValue('에이스 운영')
})
