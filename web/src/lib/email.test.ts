// @vitest-environment node
//
// The suite builds a jsdom for every file by default, which costs more than
// half a minute each on a slow filesystem — enough that this file used to lose
// the race for worker startup and get dropped from the run. Tests that only
// exercise pure functions opt out; anything touching document, window or
// Testing Library must not — including indirectly, through the module under
// test: api.ts reads document.cookie for the CSRF header, so its tests stay on
// jsdom even though the test file itself never names document.
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
