import { describe, expect, test } from 'vitest'
import { EMAIL_MAX_LENGTH, normalizeEmail } from './email'

describe('email helpers', () => {
  test('normalizes email for semantic comparisons', () => {
    expect(normalizeEmail('  Alice@Example.COM ')).toBe('alice@example.com')
    expect(normalizeEmail()).toBe('')
  })

  test('exports the server-aligned maximum length', () => {
    expect(EMAIL_MAX_LENGTH).toBe(320)
  })
})
