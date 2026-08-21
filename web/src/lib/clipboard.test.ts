import { afterEach, expect, test, vi } from 'vitest'
import { copyText } from './clipboard'

afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks() })

test('uses the async clipboard when the page is a secure context', async () => {
  const writeText = vi.fn(async () => undefined)
  vi.stubGlobal('navigator', { clipboard: { writeText } })
  expect(await copyText('rk_secret')).toBe(true)
  expect(writeText).toHaveBeenCalledWith('rk_secret')
})

test('falls back when navigator.clipboard is unavailable on a plain HTTP origin', async () => {
  // ReSSO is normally reached over plain HTTP inside an offline network, where
  // navigator.clipboard does not exist at all.
  vi.stubGlobal('navigator', {})
  const execCommand = vi.fn(() => true)
  Object.defineProperty(document, 'execCommand', { value: execCommand, configurable: true })
  expect(await copyText('rk_secret')).toBe(true)
  expect(execCommand).toHaveBeenCalledWith('copy')
  // The temporary element must not be left behind.
  expect(document.querySelectorAll('textarea')).toHaveLength(0)
})

test('falls back when the async clipboard rejects', async () => {
  const writeText = vi.fn(async () => { throw new Error('permission denied') })
  vi.stubGlobal('navigator', { clipboard: { writeText } })
  const execCommand = vi.fn(() => true)
  Object.defineProperty(document, 'execCommand', { value: execCommand, configurable: true })
  expect(await copyText('rk_secret')).toBe(true)
  expect(execCommand).toHaveBeenCalled()
})

test('reports failure so the caller can tell the user to copy manually', async () => {
  vi.stubGlobal('navigator', {})
  Object.defineProperty(document, 'execCommand', { value: () => false, configurable: true })
  expect(await copyText('rk_secret')).toBe(false)
  expect(await copyText('')).toBe(false)
})
