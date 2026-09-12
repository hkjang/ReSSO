import { expect, test, vi } from 'vitest'
import { describeBulkOutcome, runBulk } from './bulk'

test('모두 성공하면 성공한 수를 센다', async () => {
  const outcome = await runBulk([1, 2, 3], () => Promise.resolve())
  expect(outcome).toEqual({ succeeded: 3, failed: 0 })
})

// 중간에 하나가 실패했다고 멈추면 남은 행은 손도 대지 않은 채 끝난다. 운영자가
// 정확히 처리하려던 행들이다.
test('하나가 실패해도 나머지를 끝까지 처리한다', async () => {
  const action = vi.fn((n: number) => (n === 2 ? Promise.reject(new Error('nope')) : Promise.resolve()))
  const outcome = await runBulk([1, 2, 3, 4], action)
  expect(action).toHaveBeenCalledTimes(4)
  expect(outcome.succeeded).toBe(3)
  expect(outcome.failed).toBe(1)
})

test('첫 실패를 들고 있어 무엇이 잘못됐는지 말할 수 있다', async () => {
  const first = new Error('첫 번째')
  const outcome = await runBulk([1, 2], (n) => Promise.reject(n === 1 ? first : new Error('두 번째')))
  expect(outcome.error).toBe(first)
})

// 한 번에 전부 열면 느린 서버에서 동시 타임아웃 이백 개가 된다.
test('한 번에 네 개까지만 진행한다', async () => {
  let inFlight = 0
  let peak = 0
  await runBulk(Array.from({ length: 12 }, (_, i) => i), async () => {
    inFlight += 1
    peak = Math.max(peak, inFlight)
    await Promise.resolve()
    inFlight -= 1
  })
  expect(peak).toBeLessThanOrEqual(4)
})

test('아무것도 없으면 아무것도 하지 않는다', async () => {
  const action = vi.fn()
  expect(await runBulk([], action)).toEqual({ succeeded: 0, failed: 0 })
  expect(action).not.toHaveBeenCalled()
})

// 열넷 중 셋이 남아 있는데 "완료"라고 말하는 것이 이 코드가 막으려는 결과다.
test('일부만 실패하면 남은 수를 먼저 말하고 경고로 알린다', () => {
  const described = describeBulkOutcome({ succeeded: 11, failed: 3 }, '세션 종료')
  expect(described.severity).toBe('warning')
  expect(described.message).toContain('14건 중 3건이 실패')
  expect(described.message).toContain('11건은 처리')
})

test('전부 실패하면 오류로 알린다', () => {
  expect(describeBulkOutcome({ succeeded: 0, failed: 4 }, '세션 종료')).toEqual({
    message: '세션 종료 4건을 모두 처리하지 못했습니다.', severity: 'error',
  })
})

test('전부 성공하면 성공으로 알린다', () => {
  expect(describeBulkOutcome({ succeeded: 4, failed: 0 }, '세션 종료').severity).toBe('success')
})
