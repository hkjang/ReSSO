// @vitest-environment node
import { expect, test } from 'vitest'
import { describeDevice } from './device'

test('names the browser and platform a person would recognise', () => {
  const cases: Array<[string, string]> = [
    ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36', 'Chrome · Windows'],
    ['Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15', 'Safari · macOS'],
    ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0', 'Edge · Windows'],
    ['Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0', 'Firefox · Linux'],
    ['Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1', 'Safari · iPhone'],
    ['curl/8.5.0', 'curl'],
  ]
  for (const [agent, expected] of cases) {
    expect(describeDevice(agent), agent).toBe(expected)
  }
})

test('handles a missing or unrecognised user agent without showing a wall of text', () => {
  expect(describeDevice(undefined)).toBe('알 수 없는 클라이언트')
  expect(describeDevice('   ')).toBe('알 수 없는 클라이언트')
  const noise = 'x'.repeat(200)
  expect(describeDevice(noise).length).toBeLessThanOrEqual(50)
})
