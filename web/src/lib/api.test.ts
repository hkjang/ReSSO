import { afterEach, expect, test, vi } from 'vitest'
import { api, APIError } from './api'

afterEach(() => vi.unstubAllGlobals())

test('an unreachable service becomes a readable error rather than "Failed to fetch"', async () => {
  vi.stubGlobal('fetch', vi.fn(async () => { throw new TypeError('Failed to fetch') }))
  const error = await api('/api/admin/v1/realms').catch((caught) => caught)
  expect(error).toBeInstanceOf(APIError)
  expect((error as APIError).status).toBe(0)
  expect((error as APIError).code).toBe('network_unreachable')
  expect((error as APIError).message).not.toContain('Failed to fetch')
})

test('Retry-After reaches the caller', async () => {
  vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ error: 'rate_limited', message: 'too many' }), {
    status: 429, headers: { 'Content-Type': 'application/json', 'Retry-After': '42' },
  })))
  const error = await api('/api/v1/auth/login', { method: 'POST' }).catch((caught) => caught)
  expect((error as APIError).retryAfterSeconds).toBe(42)
})
